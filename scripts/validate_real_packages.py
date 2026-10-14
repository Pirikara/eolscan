"""Run the real CLI on reviewed public packages and expose detection misses.

Uses only the Python standard library. This measures actual detection against
independently reviewed package examples; known misses intentionally exit 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "testdata" / "real-packages"


def read_json(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def package_key(purl):
    value = unquote(purl)
    if value.startswith(("pkg:nuget/", "pkg:pypi/")):
        value = value.lower()
    return value


def assess(report, profile, cases, input_path):
    selected = {c["id"]: c for c in cases if profile in c["goals"]}
    rows = {r["source_ref"]: r for r in report["results"]}
    if len(rows) != len(report["results"]) or rows.keys() != selected.keys():
        raise ValueError(f"{profile}: report must contain each selected case once")
    if report["input_sha256"] != digest(input_path):
        raise ValueError(f"{profile}: report does not match the supplied SBOM")
    results = []
    for case_id, case in selected.items():
        row = rows[case_id]
        if package_key(row["purl"]) != package_key(case["purl"]):
            raise ValueError(f"{case_id}: report identifies a different package")
        goal = case["goals"][profile]
        actual = row["lifecycle"]
        met = None if goal is None else (
            actual == "EOL" if goal == "EOL" else actual in ("NO_EOL_DETECTED", "SUPPORTED")
        )
        results.append({
            "case_id": case_id,
            "purl": row["purl"],
            "group": case["group"],
            "reference_kind": case["reference_kind"],
            "goal": goal,
            "goal_met": met,
            "lifecycle": actual,
            "confidence": row["confidence"],
            "eol_basis": row["eol_basis"],
            "version_verification": row["version_verification"]["status"],
            "signals": {s["type"]: s["status"] for s in row["signal_evaluations"]},
            "unknown_reasons": row["unknown_reasons"],
            "incomplete": row["incomplete"],
            "source_urls": case["source_urls"],
        })
    retired = [r for r in results if r["group"] == "retired"]
    by_reference = {}
    for kind in sorted({r["reference_kind"] for r in results}):
        selected_kind = [r for r in results if r["reference_kind"] == kind]
        by_reference[kind] = {
            "total": len(selected_kind),
            "eol": sum(r["lifecycle"] == "EOL" for r in selected_kind),
            "unknown": sum(r["lifecycle"] == "UNKNOWN" for r in selected_kind),
        }
    return {
        "as_of": report["as_of"],
        "generated_at": report["generated_at"],
        "tool_version": report["tool_version"],
        "policy_hash": report["policy_hash"],
        "input_sha256": report["input_sha256"],
        "cli_summary": report["summary"],
        "ci_gate": report["ci_gate"],
        "reviewed_retirement_targets": len(retired),
        "retirement_targets_detected": sum(r["lifecycle"] == "EOL" for r in retired),
        "by_reference_kind": by_reference,
        "goal_misses": [r["case_id"] for r in results if r["goal_met"] is False],
        "results": results,
    }


def run_cli(binary, profile, spec, output):
    report_path = output / f"{profile}.report.json"
    report_path.unlink(missing_ok=True)
    command = [str(binary), "scan", "--input", str(DATA / spec["input"])]
    if spec["config"]:
        command += ["--config", str(DATA / spec["config"])]
    command += ["--format", "json", "--output", str(report_path)]
    print(f"Running {profile} against public APIs...", flush=True)
    process = subprocess.run(command, capture_output=True, text=True)
    (output / f"{profile}.stderr.txt").write_text(process.stderr)
    if process.returncode not in (0, 1, 3) or not report_path.is_file():
        raise ValueError(f"CLI failed ({process.returncode}): {process.stderr.strip()}")
    return report_path, {
        "profile": profile,
        "command": command,
        "cli_exit_code": process.returncode,
        "stderr": process.stderr,
        "report_sha256": digest(report_path),
        "input_sha256": digest(DATA / spec["input"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "bin" / "eolscan")
    parser.add_argument("--profile", choices=("default", "inactivity", "both"), default="both")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts" / "real-packages")
    parser.add_argument("--reports-dir", type=Path, help="Analyze recorded reports without making requests")
    args = parser.parse_args()
    manifest = read_json(DATA / "manifest.json")
    cases = manifest["cases"]
    if len({c["id"] for c in cases}) != len(cases):
        raise ValueError("case IDs must be unique")
    if any(goal not in (None, "EOL", "NOT_EOL") for c in cases for goal in c["goals"].values()):
        raise ValueError("case goals must be EOL, NOT_EOL, or null")
    profiles = list(manifest["profiles"]) if args.profile == "both" else [args.profile]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    receipts = {}
    if args.reports_dir:
        receipt_path = args.reports_dir / "executions.json"
        if receipt_path.is_file():
            receipts = {r["profile"]: r for r in read_json(receipt_path)["executions"]}
    elif not args.binary.is_file():
        raise ValueError("build bin/eolscan first, or pass --binary")
    analyses = {}
    live_receipts = []
    for profile in profiles:
        spec = manifest["profiles"][profile]
        if args.reports_dir:
            report_path = args.reports_dir / f"{profile}.report.json"
            receipt = receipts.get(profile)
            if receipt and receipt["report_sha256"] != digest(report_path):
                raise ValueError(f"{profile}: recorded report hash differs from execution receipt")
        else:
            report_path, receipt = run_cli(args.binary.resolve(), profile, spec, output)
            live_receipts.append(receipt)
        analysis = assess(read_json(report_path), profile, cases, DATA / spec["input"])
        analysis["cli_exit_code"] = receipt["cli_exit_code"] if receipt else None
        analyses[profile] = analysis
        print(f"{profile}: {analysis['retirement_targets_detected']}/"
              f"{analysis['reviewed_retirement_targets']} retirement targets detected; "
              f"{len(analysis['goal_misses'])} unmet goals; CLI exit {analysis['cli_exit_code']}")
        for row in analysis["results"]:
            if row["goal_met"] is False:
                print(f"  MISS {row['purl']}: {row['lifecycle']}")
    combined = {}
    for analysis in analyses.values():
        for row in analysis["results"]:
            if row["group"] == "retired":
                combined[row["case_id"]] = combined.get(row["case_id"], False) or row["lifecycle"] == "EOL"
    summary = {
        "mode": "recorded" if args.reports_dir else "live",
        "sample_scope": manifest["review_scope"],
        "profiles": analyses,
        "combined_retirement_targets": len(combined),
        "combined_retirement_targets_detected": sum(combined.values()),
    }
    (output / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    if live_receipts:
        (output / "executions.json").write_text(json.dumps({
            "binary_sha256": digest(args.binary), "executions": live_receipts,
        }, indent=2) + "\n")
    print(f"Results: {output / 'results.json'}")
    return 1 if any(a["goal_misses"] for a in analyses.values()) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f"Validation error: {error}", file=sys.stderr)
        sys.exit(2)
