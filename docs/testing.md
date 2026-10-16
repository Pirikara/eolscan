# Testing EOL decisions

Tests exercise package facts through normalization, version verification, EOL classification, reports, and the CI gate. Fixed timestamps and local API responses make regression cases reproducible without public registry or GitHub requests.

## Covered scenarios

| Area | Checks |
| --- | --- |
| Configured criteria | All 18 two-input AND/OR combinations of PRESENT, ABSENT, and UNKNOWN; multiple rules with reordered declarations; support-date precedence; unresolved maintenance conditions alongside an official support window. |
| Policy loading | Rule replacement rather than appending defaults; normalized package identities; ecosystem and package scopes together; malformed rules and missing inactivity thresholds. |
| Mixed SBOMs | Seven ecosystems, multiple versions, duplicate components, missing identities, and unavailable source mappings through CycloneDX and SPDX, with JSON and table output. Verify original references, EOL/nonmatch/unknown totals, warnings, exit codes, and shared requests. |
| RubyGems | Publisher source URLs in version details and metadata; active and archived repositories; mismatched or unavailable details; a missing package-wide listing with independently valid exact-version details. Existing tests also cover platform boundaries and yank limitations. |
| PyPI | Exact-version project URL discovery; source-label normalization; homepage and issue links excluded; wrong names/versions and malformed metadata; registry archival combined with source-repository archival. |
| GitHub | Provenance ranking, ambiguous mappings, malformed/duplicate fields, incorrect identities, absent archival flags, 404/403/429/503, timeouts, safe redirects, token scope, primary and secondary quota resets. |
| Release inactivity | Native npm/PyPI/RubyGems results just below, exactly at, and above the threshold; a recent project release must prevent an inactivity match even when the SBOM version is old. Existing cases cover incomplete histories and later artifacts for older releases. |
| Broader EOL acquisition | General/OSS series end while an official security window continues; Maven stable qualifiers and excluded prerelease/service-pack qualifiers; undated flags and historical/future dates; publisher classifiers and configurable text patterns; missing metadata and wrong identities; HTML/Markdown retirement notices versus examples, comments, predecessor/dependency notices; repository push thresholds and ignored metadata updates; standalone CI checks are not skipped. |
| CI and exceptions | HIGH versus MEDIUM thresholds; same-day and expired exceptions; exact-version matching; unresolved checks remain incomplete; exceptions suppress CI failures without changing EOL or warnings. |
| Reports | Support notices and evidence; hiding UNKNOWN rows preserves totals; reject invented dates, unsupported confidence, missing signal proof, historical live-status claims, inconsistent counts, coverage, component failures, and aggregate gates. |
| Executable | Linux CI builds the actual CLI and runs it as a child process against local HTTPS providers, verifying a dependency nested under an excluded metadata subject and real exit codes 0, 1, and 3. |

The subprocess HTTPS test supplies a local certificate through `SSL_CERT_FILE` only in its child process. Go's macOS native certificate verifier ignores that setting, so that test is skipped on macOS and runs on the Linux CI runner. Portable HTTPS integration tests inject a trusted client and run on both platforms. No test disables the application's TLS verification or changes a system trust store.

## Run the checks

```sh
go test -race ./...
go vet ./...
go build -o bin/eolscan ./cmd/eolscan
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

Measure statement coverage across internal packages, including calls made by integration tests:

```sh
go test -race -coverpkg=./internal/... \
  -coverprofile=/tmp/eolscan.cover -json ./... > /tmp/eolscan-tests.jsonl
go tool cover -func=/tmp/eolscan.cover
```

Inspect both uncovered code and expected outcomes. Statement coverage is not branch coverage and does not certify correctness. Test function totals omit unnamed table iterations; when counting named cases from JSON, exclude parent tests to avoid counting the same work twice.

Fixed responses verify behavior under known API shapes and failure modes. They do not verify current public API availability, every package's metadata, or the completeness of upstream support information.

## Detection on actual packages

[Real package validation](real-package-validation.md) covers 47 actual versions across all seven supported ecosystems: 36 retirement/deprecation targets, one inactivity candidate, and ten controls. The default criteria detect 34/36 targets, with 36/36 under an opt-in 730-day release inactivity rule. An isolated publisher-declarations profile detects 7/7 targets across RubyGems, PyPI, and Cargo without support-date or archival criteria. These observed outcomes and two default misses are retained alongside independently reviewed upstream sources.

```sh
make validate-real-packages
```

This makes public API requests and exits nonzero for unmet detection goals. It is intentionally separate from deterministic CI. CI checks the recorded reports' contracts, hashes, and CLI gate outcomes without contacting public services; it does not assert that all real-world targets were detected.

## Regressions found while expanding coverage

- Exact RubyGems version details could verify a version but their source URL was discarded when the package-wide version list lacked it. Repository discovery now uses validated exact-version details independently of that list.
- Report validation previously checked only that lifecycle totals summed to the component count. It now compares classification and CI totals with the actual rows and verifies coverage, component CI decisions, aggregate incompleteness, and gate violations against the effective policy.

- Live declaration checks exposed missed HTML headings and bold quoted warnings. Regression cases and re-scans confirm the corrected acquisition without treating code examples, comments, or predecessor retirement as self-declarations.
