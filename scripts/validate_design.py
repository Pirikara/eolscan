"""Validate the versioned contracts and fictional fixtures without network access."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
TESTDATA = ROOT / "testdata"
NAMESPACE = "urn:eolscan:schema:2:"


class ContractError(ValueError):
    pass


def ensure(condition, message):
    if not condition:
        raise ContractError(message)


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        ensure(key not in result, f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def load_yaml(path):
    return yaml.load(path.read_text(), Loader=UniqueKeyLoader)


SCHEMAS = {
    json.loads(path.read_text())["$id"]: json.loads(path.read_text())
    for path in sorted((ROOT / "schemas").glob("*.json"))
}
REGISTRY = Registry().with_resources(
    (uri, Resource.from_contents(schema)) for uri, schema in SCHEMAS.items()
)
for schema in SCHEMAS.values():
    Draft202012Validator.check_schema(schema)


def validate_schema(value, name):
    Draft202012Validator(
        SCHEMAS[NAMESPACE + name], registry=REGISTRY, format_checker=FormatChecker()
    ).validate(value)


def merge(defaults, partial):
    result = copy.deepcopy(defaults)
    for key, value in partial.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def day(value):
    return date.fromisoformat(value)


def canonical_hash(value):
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def policy_hash(policy, catalog, exceptions):
    return canonical_hash(
        {"policy": policy, "catalog": catalog, "exceptions": exceptions}
    )


def validate_policy(policy):
    validate_schema(policy, "policy")
    for provider in ("endoflife_date", "deps_dev", "npm", "pypi", "rubygems"):
        url = urlsplit(policy["sources"][provider]["base_url"])
        ensure(
            url.scheme == "https"
            and url.hostname
            and (
                not policy["sources"][provider]["enabled"]
                or url.hostname in policy["network"]["allowed_hosts"]
            )
            and not url.username
            and not url.password
            and not url.query
            and not url.fragment,
            f"{provider}: base URL must use an explicitly allowed HTTPS host",
        )
    ensure(
        set(policy["network"]["host_limits"]).issubset(policy["network"]["allowed_hosts"]),
        "host_limits must use explicitly allowed hosts",
    )
    ensure(
        "STALE_RELEASE" not in policy["ci"]["fail_on_signals"]
        or policy["signals"]["stale_release_days"] is not None,
        "required STALE_RELEASE needs a threshold",
    )


def unique(values, label):
    ensure(len(values) == len(set(values)), f"{label} must be unique")


def validate_catalog(catalog):
    validate_schema(catalog, "support-catalog")
    entries = {entry["id"]: entry for entry in catalog["entries"]}
    unique([entry["id"] for entry in catalog["entries"]], "catalogue entry IDs")
    unique(
        [assertion["package_purl"] for assertion in catalog["verified_versions"]],
        "version assertions",
    )
    unique(
        [review["id"] for review in catalog["general_eol_reviews"]], "review IDs"
    )
    unique(
        [
            (
                review["product_slug"],
                review["package_purl"],
                review["matched_cycle"],
                review["support_scope"],
            )
            for review in catalog["general_eol_reviews"]
        ],
        "review targets",
    )
    for item in (
        catalog["entries"]
        + catalog["verified_versions"]
        + catalog["general_eol_reviews"]
    ):
        ensure(
            day(item["reviewed_at"]) <= day(item["valid_until"]),
            "review date must precede or equal expiry",
        )
    for assertion in catalog["verified_versions"]:
        ensure(
            instant(assertion["published_at"]).date() <= day(assertion["reviewed_at"]),
            "a local version cannot be reviewed before its publication",
        )
    for entry in entries.values():
        if entry["claim"] == "UPSTREAM_SECURITY_WINDOW":
            ensure(
                day(entry["support_start_date"]) < day(entry["eol_effective_date"]),
                "support window must have positive duration",
            )
        replacement = entry["superseded_by"]
        if replacement:
            ensure(replacement in entries, "superseding entry ID does not exist")
            target = entries[replacement]
            ensure(
                all(
                    entry[key] == target[key]
                    for key in ("package_purl", "matched_cycle", "support_scope")
                ),
                "supersession must concern the same target and support scope",
            )
            seen = {entry["id"]}
            while replacement:
                ensure(replacement not in seen, "supersession must not contain a cycle")
                seen.add(replacement)
                replacement = entries[replacement]["superseded_by"]


DEFAULT = load_yaml(EXAMPLES / "eol-policy.example.yaml")
validate_policy(DEFAULT)


def load_context(policy_path):
    partial = load_yaml(policy_path)
    validate_schema(partial, "policy-input")
    policy = merge(DEFAULT, partial)
    validate_policy(policy)
    catalog = None
    catalog_source = policy["sources"]["official_catalog"]
    if catalog_source["enabled"]:
        catalog = load_yaml(policy_path.parent / catalog_source["path"])
        validate_catalog(catalog)
    exceptions = None
    if policy["exceptions"]["path"]:
        exceptions = load_yaml(policy_path.parent / policy["exceptions"]["path"])
        validate_schema(exceptions, "exceptions")
    return policy, catalog, exceptions


def current_review(review, run_date):
    return day(review["reviewed_at"]) <= run_date <= day(review["valid_until"])


def package_key(purl):
    # Only compare already normalized fixture identities; this is not a PURL parser.
    return purl.split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0]


def applicable(evidence, component, catalog):
    if not component["purl"] or evidence["package_purl"] != package_key(
        component["purl"]
    ):
        return False
    cycle = evidence["matched_cycle"]
    version = component["version"]
    if version == cycle or (version and version.startswith(cycle + ".")):
        return True
    return any(
        entry["package_purl"] == evidence["package_purl"]
        and entry["matched_cycle"] == cycle
        and entry["match"] == "exact_versions"
        and version in entry["versions"]
        for entry in (catalog or {}).get("entries", [])
    )


def eligible_evidence(component, policy, catalog, run_at):
    result = []
    run_date = run_at.date()
    for evidence in component["evidence"]:
        if not applicable(evidence, component, catalog):
            continue
        if evidence["claim"] == "GENERAL_EOL_END":
            review = evidence["general_eol_review"]
            if not review or not current_review(review, run_date):
                continue
            if not all(
                review[key] == evidence[key]
                for key in ("product_slug", "package_purl", "matched_cycle")
            ):
                continue
            if review not in (catalog or {}).get("general_eol_reviews", []):
                continue
            age = (run_at - instant(evidence["observed_at"])).total_seconds() / 86400
            if age > policy["decision"]["max_evidence_age_days"]:
                continue
        elif not (
            day(evidence["reviewed_at"]) <= run_date <= day(evidence["valid_until"])
        ):
            continue
        result.append(evidence)
    active = {evidence["id"]: evidence for evidence in result}
    retained = []
    for evidence in result:
        target = active.get(evidence["superseded_by"])
        if target and evidence["supersession_source_url"]:
            ensure(
                all(
                    evidence[key] == target[key]
                    for key in ("package_purl", "matched_cycle", "support_scope")
                ),
                "supersession target has a different identity or scope",
            )
            continue
        retained.append(evidence)
    return retained


def expected_lifecycle(component, policy, catalog, run_at, as_of):
    eligible = eligible_evidence(component, policy, catalog, run_at)
    tier = max(
        (2 if evidence["source_class"] == "OFFICIAL" else 1 for evidence in eligible),
        default=0,
    )
    top = [
        evidence
        for evidence in eligible
        if (2 if evidence["source_class"] == "OFFICIAL" else 1) == tier
    ]
    conflict = len({e["eol_effective_date"] for e in top}) > 1 or len(
        {
            e["support_start_date"]
            for e in top
            if e["claim"] == "UPSTREAM_SECURITY_WINDOW"
        }
    ) > 1
    if component["version_verification"]["status"] != "VERIFIED" or not top or conflict:
        return "UNKNOWN", top, conflict
    end = day(top[0]["eol_effective_date"])
    if as_of >= end:
        return "EOL", top, conflict
    if any(
        e["claim"] == "UPSTREAM_SECURITY_WINDOW"
        and day(e["support_start_date"]) <= as_of
        for e in top
    ):
        return "SUPPORTED", top, conflict
    return "UNKNOWN", top, conflict


def validate_report(report, policy, catalog, exceptions, input_path):
    validate_schema(report, "report")
    run_at = instant(report["generated_at"])
    as_of = day(report["as_of"])
    ensure(report["projection"] == (as_of > run_at.date()), "projection is inconsistent")
    ensure(
        report["input_sha256"] == hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "input SHA-256 is inconsistent",
    )
    ensure(
        report["policy_hash"] == policy_hash(policy, catalog, exceptions),
        "policy hash is inconsistent",
    )
    requested = set(policy["ci"]["fail_on_signals"])
    if policy["signals"]["deprecated"]:
        requested.add("DEPRECATED")
    for flag in ("yanked", "archived", "quarantined"):
        if policy["signals"][flag]:
            requested.add(flag.upper())
    if policy["signals"]["stale_release_days"] is not None:
        requested.add("STALE_RELEASE")
    counts = {"EOL": 0, "SUPPORTED": 0, "UNKNOWN": 0}
    failures = 0
    rows = report["results"]
    ensure(
        rows == sorted(rows, key=lambda row: (row["purl"] is None, row["purl"] or "", row["source_ref"])),
        "results must be stably sorted",
    )
    for row in rows:
        verification = row["version_verification"]
        if verification["status"] == "VERIFIED":
            publication = instant(verification["published_at"])
            ensure(publication.date() <= as_of, "version was not released as of evaluation")
            ensure(publication <= run_at, "future publication cannot prove existence")
            if verification["provider_id"] == "official_catalog":
                assertions = [
                    item
                    for item in (catalog or {}).get("verified_versions", [])
                    if item["package_purl"] == row["purl"]
                ]
                ensure(len(assertions) == 1, "local version assertion must exist")
                assertion = assertions[0]
                ensure(current_review(assertion, run_at.date()), "local assertion has expired")
                ensure(
                    assertion["published_at"] == verification["published_at"]
                    and assertion["source_url"] == verification["source_url"],
                    "verification must preserve its local publication evidence",
                )
        if verification["status"] == "NOT_RELEASED_AS_OF":
            ensure(
                instant(verification["published_at"]).date() > as_of,
                "NOT_RELEASED_AS_OF must be justified by publication date",
            )
        unique([e["id"] for e in row["evidence"]], "report evidence IDs")
        expected, top, conflict = expected_lifecycle(row, policy, catalog, run_at, as_of)
        ensure(row["lifecycle"] == expected, "Lifecycle contradicts eligible highest-tier evidence")
        if conflict and verification["status"] == "VERIFIED":
            ensure("CONFLICT" in row["unknown_reasons"], "conflict reason is required")
        selected = [
            e for e in row["evidence"] if e["id"] in row["selected_evidence_ids"]
        ]
        ensure(
            len(selected) == len(row["selected_evidence_ids"]),
            "selected evidence ID does not exist",
        )
        if expected != "UNKNOWN":
            ensure(all(e in top for e in selected), "selected evidence must belong to top tier")
            ensure(
                all(e["eol_effective_date"] == row["eol_effective_date"] for e in selected),
                "selected EOL date does not match the result",
            )
            ensure(
                all(e["matched_cycle"] == row["matched_cycle"] for e in selected),
                "selected cycle does not match the result",
            )
            ensure(
                all(e["confidence"] == row["confidence"] for e in selected),
                "result confidence must follow selected evidence",
            )
            if expected == "SUPPORTED":
                ensure(
                    all(e["claim"] == "UPSTREAM_SECURITY_WINDOW" for e in selected),
                    "SUPPORTED requires an official security window",
                )
        for notice in row["notices"]:
            ensure(
                notice["evidence_id"] in row["selected_evidence_ids"],
                "notice must refer to selected evidence",
            )
            remaining = (day(row["eol_effective_date"]) - as_of).days
            ensure(
                notice["days_remaining"] == remaining
                and 0 < remaining <= policy["notices"]["eol_soon_days"],
                "notice date or threshold is inconsistent",
            )
        evaluations = row["signal_evaluations"]
        unique([item["type"] for item in evaluations], "signal evaluation types")
        ensure({item["type"] for item in evaluations} == requested, "requested signal evaluation is missing")
        for evaluation in evaluations:
            present = any(e["type"] == evaluation["type"] for e in row["signals"])
            if evaluation["status"] == "PRESENT":
                ensure(present, "PRESENT requires a corresponding signal")
            elif evaluation["status"] == "ABSENT":
                ensure(not present, "ABSENT cannot discard a detected signal")
            if (
                evaluation["type"] in policy["ci"]["fail_on_signals"]
                and evaluation["status"] == "UNKNOWN"
            ):
                ensure(row["incomplete"], "required UNKNOWN signal must mark incomplete")
        eligible_exceptions = [
            item
            for item in (exceptions or {}).get("exceptions", [])
            if item["package_purl"] == row["purl"]
            and run_at.date() <= day(item["expires_on"])
        ]
        if row["exception_applied"]:
            ensure(eligible_exceptions, "an active matching exception is required")
        status_failure = row["lifecycle"] in policy["ci"]["fail_on_statuses"] and (
            row["lifecycle"] == "UNKNOWN"
            or policy["ci"]["min_confidence"] == "MEDIUM"
            or row["confidence"] == "HIGH"
        )
        signal_failure = any(
            item["status"] == "PRESENT"
            and item["type"] in policy["ci"]["fail_on_signals"]
            for item in evaluations
        )
        expected_failure = (status_failure or signal_failure) and not row["exception_applied"]
        ensure(row["ci_failure"] == expected_failure, "component CI failure is inconsistent")
        counts[row["lifecycle"]] += 1
        failures += row["ci_failure"]
    summary = report["summary"]
    ensure(summary["in_scope"] == len(rows), "in_scope must count result components")
    for status, key in (("EOL", "eol"), ("SUPPORTED", "supported"), ("UNKNOWN", "unknown")):
        ensure(summary[key] == counts[status], f"{key} count is inconsistent")
    coverage = (counts["EOL"] + counts["SUPPORTED"]) / len(rows) if rows else 0
    ensure(math.isclose(summary["assessment_coverage"], coverage), "coverage is inconsistent")
    ensure(summary["ci_failure_count"] == failures, "CI failure count is inconsistent")
    incomplete = any(row["incomplete"] for row in rows)
    ensure(report["ci_gate"]["incomplete"] == incomplete, "aggregate incomplete is inconsistent")
    codes = []
    if failures:
        codes.append("COMPONENT_POLICY_VIOLATION")
    ratio = counts["UNKNOWN"] / len(rows) if rows else 0
    threshold = policy["ci"]["max_unknown_ratio"]
    if threshold is not None and ratio > threshold:
        codes.append("MAX_UNKNOWN_RATIO_EXCEEDED")
    if incomplete and policy["ci"]["fail_on_incomplete_scan"]:
        codes.append("INCOMPLETE_SCAN")
    ensure(set(report["ci_gate"]["violation_codes"]) == set(codes), "gate violations are inconsistent")
    ensure(report["ci_gate"]["passed"] == (not codes), "gate result is inconsistent")
    if failures or "MAX_UNKNOWN_RATIO_EXCEEDED" in codes:
        return 1
    return 3 if "INCOMPLETE_SCAN" in codes else 0


def run():
    valid_files = 0
    for path in sorted([*EXAMPLES.rglob("*.yaml"), *TESTDATA.rglob("*.yaml")]):
        if path.name.startswith("eol-policy") or path.name.startswith("policy."):
            load_context(path)
        elif path.name.startswith("support-catalog") or path.name.startswith("catalog."):
            validate_catalog(load_yaml(path))
        elif path.name.startswith("eol-exceptions"):
            validate_schema(load_yaml(path), "exceptions")
        else:
            raise ContractError(f"unclassified example: {path}")
        valid_files += 1
    fixtures = {}
    manifest = json.loads((TESTDATA / "fixtures/manifest.json").read_text())
    for case in manifest:
        report = json.loads((ROOT / case["report"]).read_text())
        context = load_context(ROOT / case["policy"])
        input_path = ROOT / case["input"]
        actual = validate_report(report, *context, input_path)
        ensure(actual == case["expected_exit"], f"{case['name']}: unexpected exit")
        fixtures[case["name"]] = (report, context, input_path)
    tests = []

    def rejected(label, callback):
        try:
            callback()
        except (ContractError, ValidationError):
            tests.append(label)
            return
        raise ContractError(f"invalid example was accepted: {label}")

    def change_report(name, edit):
        report, context, input_path = fixtures[name]
        value = copy.deepcopy(report)
        edit(value)
        validate_report(value, *context, input_path)

    def force_eol(report):
        row = report["results"][0]
        chosen = next(e for e in row["evidence"] if e["eol_effective_date"] <= report["as_of"])
        row.update(
            lifecycle="EOL",
            confidence=chosen["confidence"],
            eol_effective_date=chosen["eol_effective_date"],
            matched_cycle=chosen["matched_cycle"],
            selected_evidence_ids=[chosen["id"]],
            unknown_reasons=[],
        )

    for name in ("future-date-conflict", "upper-tier-future-end", "unreviewed-general-eol"):
        rejected(name + " cannot become EOL", lambda name=name: change_report(name, force_eol))

    rejected(
        "missing version publication",
        lambda: change_report("supported", lambda r: r["results"][0]["version_verification"].update(published_at=None)),
    )
    rejected(
        "missing evidence field",
        lambda: change_report("supported", lambda r: r["results"][0]["evidence"][0].pop("claim")),
    )
    rejected(
        "required signal cannot hide incomplete",
        lambda: change_report("required-signal-unknown", lambda r: r["results"][0].update(incomplete=False)),
    )
    rejected(
        "requested signal cannot be omitted",
        lambda: change_report("required-signal-unknown", lambda r: r["results"][0]["signal_evaluations"].pop()),
    )
    rejected(
        "UNKNOWN signal requires a reason",
        lambda: change_report("required-signal-unknown", lambda r: r["results"][0]["signal_evaluations"][1].update(reason_code=None)),
    )
    rejected(
        "PRESENT requires evidence",
        lambda: change_report("supported", lambda r: r["results"][0]["signal_evaluations"][0].update(
            status="PRESENT", provider_id="deps_dev", source_url="https://api.deps.dev/example",
            checked_at=r["generated_at"], reason_code=None
        )),
    )
    rejected(
        "EOL cannot carry EOL_SOON",
        lambda: change_report("reviewed-general-eol", lambda r: r["results"][0]["notices"].append(
            {"type": "EOL_SOON", "days_remaining": 1, "evidence_id": r["results"][0]["selected_evidence_ids"][0], "rule_id": "R-009"}
        )),
    )
    rejected(
        "invalid evidence reference",
        lambda: change_report("supported", lambda r: r["results"][0]["selected_evidence_ids"].append("missing")),
    )
    rejected(
        "incorrect summary",
        lambda: change_report("supported", lambda r: r["summary"].update(eol=1)),
    )
    rejected(
        "invalid notice date",
        lambda: change_report("supported", lambda r: r["results"][0]["notices"][0].update(days_remaining=90)),
    )
    for key in ("unknown_on_same_tier_conflict", "excluded_general_eol_products"):
        partial = {"schema_version": 2, "decision": {key: True if key.startswith("unknown") else []}}
        rejected("old setting " + key, lambda partial=partial: validate_schema(partial, "policy-input"))
    rejected(
        "version verification cannot be optional",
        lambda: validate_schema({"schema_version": 2, "version_verification": {"mode": "optional"}}, "policy-input"),
    )
    missing_publication = copy.deepcopy(load_yaml(EXAMPLES / "support-catalog.example.yaml"))
    missing_publication["verified_versions"][0].pop("published_at")
    rejected("catalogue publication is required", lambda: validate_catalog(missing_publication))
    rejected(
        "credentials in evidence URLs",
        lambda: change_report("supported", lambda r: r["results"][0]["evidence"][0].update(source_url="https://token@example.org/support")),
    )

    for label, modify in (
        ("review scope must match", lambda review: review.update(matched_cycle="2.0")),
        ("review expiry uses execution date", lambda review: review.update(valid_until="2026-10-10")),
    ):
        report, context, input_path = copy.deepcopy(fixtures["reviewed-general-eol"])
        policy, catalog, exceptions = context
        review = catalog["general_eol_reviews"][1]
        modify(review)
        report["results"][0]["evidence"][0]["general_eol_review"] = copy.deepcopy(review)
        report["policy_hash"] = policy_hash(policy, catalog, exceptions)
        rejected(label, lambda r=report, c=context, p=input_path: validate_report(r, *c, p))

    report, context, input_path = copy.deepcopy(fixtures["not-released-as-of"])
    policy, catalog, exceptions = context
    catalog["verified_versions"][0]["valid_until"] = "2026-10-10"
    verification = report["results"][0]["version_verification"]
    verification.update(status="VERIFIED", reason_code=None)
    report["policy_hash"] = policy_hash(policy, catalog, exceptions)
    rejected(
        "past as_of cannot revive expired proof",
        lambda: validate_report(report, *context, input_path),
    )
    # Make publication temporally valid in isolation: this then exercises expiry directly.
    report["as_of"] = "2024-05-01"
    rejected("expired local proof", lambda: validate_report(report, *context, input_path))

    partial = load_yaml(EXAMPLES / "eol-policy.partial.example.yaml")
    ensure(merge(DEFAULT, partial) == load_yaml(EXAMPLES / "eol-policy.ci-strict.yaml"), "partial merge must equal strict policy")

    # A required UNKNOWN signal stays visible in report-first, while its gate may pass.
    report, context, input_path = copy.deepcopy(fixtures["required-signal-unknown"])
    policy, catalog, exceptions = context
    policy["ci"]["fail_on_incomplete_scan"] = False
    report["policy_hash"] = policy_hash(policy, catalog, exceptions)
    report["ci_gate"].update(passed=True, violation_codes=[])
    ensure(validate_report(report, *context, input_path) == 0, "report-first incomplete must be visible with exit 0")

    # Same-day publication is compared as a UTC day, not against midnight as_of.
    report, context, input_path = copy.deepcopy(fixtures["supported"])
    report["as_of"] = "2024-04-12"
    report["results"][0]["notices"] = []
    report["results"][0]["rule_ids"] = ["R-002"]
    ensure(validate_report(report, *context, input_path) == 0, "same-day publication is applicable")

    print(
        f"Validated {len(SCHEMAS)} schemas, {valid_files} YAML examples, "
        f"{len(manifest)} report fixtures, {len(tests)} rejection cases, "
        "and 3 additional merge/date/gate checks."
    )


if __name__ == "__main__":
    run()
