# eolscan

eolscan is a Go CLI that reads an SBOM and checks whether upstream security support has ended for its dependencies. It implements the [v0.3 design specification](docs/EOL_Checker_Design_v0.3.md).

No database is required. Repeated API queries share an in-memory result during each run, and disk caching is disabled by default. Build with Go 1.24 or later; the CLI runs as a single binary.

## Build and run

```sh
go build -o bin/eolscan .

./bin/eolscan scan -i sbom.cdx.json
./bin/eolscan scan -i sbom.spdx.json -f json -o report.json
cat sbom.cdx.json | ./bin/eolscan scan -i - -f json
./bin/eolscan policy validate -c examples/eol-policy.ci-strict.yaml
./bin/eolscan providers list
```

Supported inputs are CycloneDX JSON 1.4–1.7 and SPDX 2.3 JSON. Packages are identified by PURL, with support for the gem, npm, pypi, maven, golang, cargo, and nuget ecosystems. Components without a version remain in the report as `UNKNOWN`. CycloneDX `metadata.component` is excluded by default.

Configuration uses schema version `2`, and JSON reports use version `2.0`. The CLI and output are incompatible with the initial prototype. Native Syft JSON, CPE matching, OS name matching, and direct registry queries are outside this MVP. When using Syft, provide CycloneDX or SPDX JSON.

## Understanding results

| Lifecycle | Meaning |
| --- | --- |
| `EOL` | The end of upstream security support has been confirmed. |
| `SUPPORTED` | An explicit official security support window includes the evaluation date. |
| `UNKNOWN` | Package version existence, publication time, or applicable support evidence could not be sufficiently verified. |

Lifecycle results and maintenance signals are evaluated separately. Deprecation or release inactivity alone cannot establish EOL. Signals use three states: `PRESENT / ABSENT / UNKNOWN`. `EOL_SOON` is a notice derived from the scheduled end of a `SUPPORTED` window.

**The default support catalog and general EOL reviews are empty.** A generic EOL date from endoflife.date alone cannot establish `EOL` or `SUPPORTED`. Many results will be `UNKNOWN` in an online scan without a reviewed catalog.

| Data source | Role |
| --- | --- |
| Local support catalog | Reviewed official support windows and end dates, exact version publication times, and reviews of what generic EOL dates mean. |
| [endoflife.date API v1](https://endoflife.date/docs/api/v1/) | Fetches the PURL index once, then fetches generic EOL dates for matched products. |
| [deps.dev API v3](https://docs.deps.dev/api/v3/) | Verifies exact package versions and publication times, and supplies available deprecation information and version lists. |

A version absent from the deps.dev index is `UNKNOWN` unless a valid local version assertion verifies it. A missing publication time also produces `UNKNOWN` and an incomplete scan unless a valid local assertion provides it. Registry-derived information, including RubyGems data, is accessed through deps.dev; direct registry queries are not implemented.

`DEPRECATED` uses an explicit `true` as positive evidence. A confirmed negative result requires an explicit `false` for npm. For other ecosystems, `false` or a missing field produces `UNKNOWN`. PyPI project status, Go retract, and GitHub archived status are planned capabilities. Requiring them in CI currently produces `UNKNOWN` and an incomplete scan.

`STALE_RELEASE` uses a version list with complete publication dates to find the latest release on or before the evaluation date. Missing dates or a future evaluation date produce `UNKNOWN`. Because deps.dev documents collection limits for Go and PyPI, eolscan cannot treat their version lists as complete and leaves this signal `UNKNOWN`.

## Using a support catalog

Policy files are recursively merged into the built-in defaults. Relative paths are resolved from the policy file's directory.

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: true
    path: ./support-catalog.yaml
```

The catalog contains three arrays. See the [example](examples/support-catalog.example.yaml) and [schema](schemas/support-catalog.schema.json) for the full definitions.

- `entries`: Official security support windows or end dates. Each entry requires an applicable release series, source URL, review date, and expiry date.
- `verified_versions`: Exact versioned PURLs and publication times. These enable offline version verification and provide a fallback for versions absent from deps.dev.
- `general_eol_reviews`: Reviews of generic EOL dates, matched exactly by product slug, unversioned PURL, release series, and support scope.

Official evidence has `HIGH` confidence; reviewed generic EOL evidence has `MEDIUM` confidence. Unreviewed or expired generic EOL evidence remains in the report but is excluded from lifecycle decisions. A future generic EOL date cannot establish `SUPPORTED`. Conflicting end dates within the highest applicable tier produce `UNKNOWN / CONFLICT`, including conflicts involving future dates. Evidence is excluded from conflict detection only when a formal replacement or withdrawal has been verified.

The bundled products, reviews, and version assertions are **fictional test data**. Try the offline example:

```sh
./bin/eolscan scan \
  -i examples/fixtures/supported.cdx.json \
  -c examples/eol-policy.catalog.example.yaml \
  --offline --as-of 2026-10-11
```

This returns `SUPPORTED / HIGH`. The example reviews and version assertions are valid through 2026-12-01. Expiry is checked against the execution date in UTC, so a historical `--as-of` date cannot restore expired evidence. Populate production catalogs with evidence you have actually verified.

## Using eolscan in CI

The default policy is report-first: only `EOL / HIGH` fails CI. `UNKNOWN` results, `EOL / MEDIUM` results, and incomplete scans caused by API failures remain visible in the report.

```sh
./bin/eolscan scan \
  -i sbom.cdx.json \
  -c examples/eol-policy.ci-strict.yaml \
  -f json -o report.json
```

The strict policy fails for EOL with at least `MEDIUM` confidence, incomplete scans, or an `UNKNOWN` ratio above 0.25. It still requires you to supply reviewed generic EOL mappings or official support evidence in a catalog.

Signals included in CI failure conditions require a successful evaluation.

```yaml
schema_version: 2
ci:
  fail_on_signals: [STALE_RELEASE]
  fail_on_incomplete_scan: true
```

With this policy, a confirmed stale release exits with code `1`, a confirmed absence exits with code `0`, and an unavailable evaluation makes the scan incomplete and exits with code `3`. If another explicit policy violation is present, code `1` takes precedence.

| Exit code | Meaning |
| --- | --- |
| 0 | The configured CI conditions passed. Check the report for unknown results or incomplete checks. |
| 1 | A component violates the CI policy, or the unknown ratio exceeds its limit. |
| 2 | Input, configuration, or output error. |
| 3 | A required check is incomplete, with no other explicit CI violation. |
| 4 | Internal error. |

Run the compiled binary in CI. `go run` does not preserve the program's exit code and cannot reliably distinguish codes `1` and `3`.

Configure [expiring exceptions](examples/eol-exceptions.example.yaml) using `exceptions.path`. An exception suppresses component-level CI failures for an exact PURL; lifecycle results, the unknown ratio, and incomplete status remain visible.

## Offline mode, caching, and output

- `--offline` uses the local catalog and usable disk cache entries without making HTTP requests.
- `cache.enabled: true` stores `200` and `404` responses under `eolscan/v2` in the OS cache directory. No database is needed.
- `--no-cache` disables persistent caching. Combining it with `--offline` is a configuration error.
- Online scans refresh entries whose TTL has expired. Offline scans can use expired entries within the maximum evidence age, marked `CACHE_STALE`. Older entries are rejected.
- `--as-of YYYY-MM-DD` evaluates a UTC calendar date. Future evaluations are marked `projection: true`. Versions published after the evaluation date are `UNKNOWN`.
- JSON output retains all components, evidence, diagnostics, and CI results. File output is replaced atomically. `output.include_unknown` and `output.include_evidence` affect table display only.

Online scans send package names and versions to the configured public APIs. Requests are restricted to HTTPS on explicitly allowed hosts. Arbitrary URLs from the SBOM or evidence are not fetched, and configuration URLs containing credentials or query strings are rejected.

## Development and validation

```sh
go test -race ./...
go vet ./...
go build -o bin/eolscan .
```

Go tests cover design acceptance cases UT-01 through UT-45. Ten report fixtures run through the actual CLI and verify decisions, exit codes, input hashes, and policy hashes. External APIs are replaced with fixed responses and local HTTPS servers, so tests require no public API access.

JSON schemas are embedded in the binary to validate configuration and reports. Additional documentation and example validation uses Python, which is not a CLI runtime dependency.

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

See the [design, schemas, and fixture index](docs/README.md) for implementation details. Fully reproducing historical support policies requires fixed snapshots of external evidence.
