# eolscan

eolscan is a Go CLI that reads an SBOM and classifies dependencies as EOL using **configurable criteria**. Support dates, version deprecation, project archival, and selected maintenance conditions can drive the result. Release 0.6.0 implements the [v0.8 design specification](docs/design.md).

No database is required. Repeated API queries share an in-memory result during each run, and disk caching is disabled by default. Build with Go 1.24 or later; the CLI runs as a single binary.

## Build and run

```sh
go build -o bin/eolscan ./cmd/eolscan

./bin/eolscan scan -i sbom.cdx.json
./bin/eolscan scan -i sbom.spdx.json -f json -o report.json
./bin/eolscan scan -i sbom.cdx.json -c examples/eol-policy.auto-eol.yaml
./bin/eolscan scan -i sbom.cdx.json -c examples/eol-policy.rules.example.yaml
cat sbom.cdx.json | ./bin/eolscan scan -i - -f json
./bin/eolscan policy validate -c examples/eol-policy.ci-strict.yaml
./bin/eolscan providers list
```

Supported inputs are CycloneDX JSON 1.4–1.7 and SPDX 2.3 JSON. Packages are identified by PURL, with support for the gem, npm, pypi, maven, golang, cargo, and nuget ecosystems. Components without a version remain in the report as `UNKNOWN`. CycloneDX `metadata.component` is excluded by default; its nested components are still inspected individually. A scan with no components in scope exits `3` with `NO_COMPONENTS`.

Configuration uses schema version `2`, and JSON reports use version `2.5`. Native Syft JSON, CPE matching, and OS name matching are outside the current scope. When using Syft, provide CycloneDX or SPDX JSON. Registry ecosystem support does not imply lifecycle coverage for every package; generic runtimes and OS package PURLs are currently unsupported.

When upgrading from 0.1.0, allow the three native registry hosts if your policy overrides `network.allowed_hosts`, or disable those sources explicitly. Partial version 2 policies inherit the new defaults.

When upgrading from 0.3.0, report consumers must accept the current schema `2.5`, including the `source_label` evidence field and `CURATED_SECURITY_END` claim introduced in 0.4. Fixed bundled support dates and `--catalog builtin` have been removed. Disable the old `official_catalog` selection or provide a local path. Partial policies inherit automatic security-scope detection. Empty scans still exit `3`; interrupted scans exit `130`. Local catalog contents participate in `policy_hash`; remote responses are identified by evidence hashes.

When upgrading from 0.4.0, accept report schema `2.5`, `NO_EOL_DETECTED`, `support_assessment`, `eol_basis`, and `eol_rule_evaluations`. Partial policies inherit the default deprecated/archive EOL rules. Use `decision.eol_rules: []` for dates-only behavior. Allow `api.github.com` when GitHub is enabled, or disable that source and adjust rules that depend on it.

When upgrading from 0.5.0, accept report schema `2.5` and the `RELEASE_SERIES_EOL` and `DECLARED_UNMAINTAINED` signal types. Partial policies inherit both new default rules; an explicit `decision.eol_rules` list still replaces all defaults. Declaration patterns and repository inactivity are configurable. The report schema also accepts recorded 2.4 reports.

## Configure what counts as EOL

```yaml
schema_version: 2
signals:
  stale_release_days: 365
decision:
  use_support_dates: true
  eol_rules:
    - id: deprecated-version
      any_of: [DEPRECATED]
      ecosystems: [npm, pypi, nuget]
    - id: archived-and-inactive
      all_of: [ARCHIVED, STALE_RELEASE]
ci:
  min_confidence: MEDIUM
  fail_on_incomplete_scan: true
```

Rules are ORed together; `all_of` combines conditions with AND. This policy warns and fails CI for a deprecated npm/PyPI/NuGet version, an archived project with more than 365 days of release inactivity, or an eligible support end date that has passed. `eol_rules` replaces the default list. Rules can be scoped by ecosystem or exact package PURL. See [criteria, acquisition, unknown conditions, and CI](docs/eol-rules.md).

The defaults warn on an elapsed applicable release-series EOL date, publisher-declared retirement, deprecation for npm/PyPI/NuGet, project/source-repository archival, and eligible support dates. General support end is sufficient for the default EOL warning; a confirmed security-support cutoff is not required. Release and repository inactivity become EOL only when selected in a rule. An EOL rule automatically requests the facts it needs. Missing methods and API failures remain unresolved, never a confirmed negative.

## Understanding results

| Lifecycle | Meaning |
| --- | --- |
| `EOL` | A configured EOL criterion matched: an eligible elapsed support date or a maintenance rule. |
| `SUPPORTED` | An explicit official security support window includes the evaluation date. |
| `NO_EOL_DETECTED` | Required policy checks resolved without a match; this does not certify upstream support. |
| `UNKNOWN` | Required identity, version, condition, or support information could not be resolved. |

Maintenance facts use three states: `PRESENT / ABSENT / UNKNOWN`. The policy decides which facts count as EOL. Every EOL result emits a warning, identifies its basis and matched rules, and participates in CI policy. `support_assessment` preserves the formal security-support conclusion; maintenance-rule EOL has no invented end date. `EOL_SOON` remains a notice derived from a `SUPPORTED` window.

**Online scans automatically retrieve lifecycle data from endoflife.date.** They fetch the exact PURL index once, then details for the products present in the SBOM. An elapsed applicable `eolFrom` establishes `RELEASE_SERIES_EOL`, including general/OSS support phases, at `MEDIUM` confidence. An undated explicit `isEol: true` can establish the same current-status condition. The original phase, source, and date remain in the report. No product or release-series date table is embedded in the binary. New matching products and series can be used without rebuilding eolscan. See [automatic data retrieval, coverage, and optional catalogs](docs/catalog.md).

In dates-only mode, a future security end date alone remains `UNKNOWN / SECURITY_END_ONLY`. `SUPPORTED / HIGH` still requires a reviewed official support window. Missing identities, dates, or verified publication times also remain `UNKNOWN`.

The optional formal security assessment retains its scope checks; the overall default EOL warning also accepts general support end through `RELEASE_SERIES_EOL`. General support end does not establish that security patches have stopped, and a future cutoff does not establish `SUPPORTED`.

| Data source | Role |
| --- | --- |
| Local support catalog | Reviewed official support windows and end dates, exact version publication times, and reviews of what generic EOL dates mean. |
| [endoflife.date API v1](https://endoflife.date/docs/api/v1/) | Automatically fetches exact PURL mappings and matched release-series EOL; retains the stated phase without requiring a security-scope review for the general EOL rule. |
| [npm registry](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) | Versions, publication times, per-version deprecation, and exact-version publisher descriptions. |
| [PyPI Index API](https://docs.pypi.org/api/index-api/) | Publication times, yank/project status, exact-version descriptions, and the publisher's Inactive classifier. |
| [RubyGems API](https://guides.rubygems.org/rubygems-org-api/) | Available versions, publication times, exact-version descriptions/source links, and explicit yank status where supplied. |
| [GitHub repository API](https://docs.github.com/en/rest/repos/repos#get-a-repository) | Repository archival, current README retirement declarations, and optional last-push inactivity after validating the source mapping. |
| [deps.dev API v3](https://docs.deps.dev/api/v3/) | Fallback version/publication verification and available maintenance metadata; primary remote provider for the other four ecosystems. |

Version verification prefers a valid local assertion, then the native registry for npm/PyPI/RubyGems, then deps.dev. Native package metadata is fetched and parsed once per package, shared across its SBOM versions. Successful native verification avoids a deps.dev request for that check; additional requested facts or missing repository mappings can still require deps.dev. Failed lookups remain diagnostics even when a fallback completes the check.

A version absent from every available source remains `UNKNOWN`; a 404 cannot prove global nonexistence. Missing publication time also produces `UNKNOWN` and an incomplete scan unless another source supplies valid proof. A version published after `--as-of` cannot receive a definitive lifecycle result.

`DEPRECATED` comes from npm version metadata or PyPI's explicit project status. A valid full npm version record without a deprecation message is a confirmed negative; missing or malformed metadata is not. deps.dev can provide a positive result in any supported ecosystem, but an explicit negative is trusted for npm and NuGet.

`YANKED`, `ARCHIVED`, and `QUARANTINED` are requested through optional signals, EOL rules, or `ci.fail_on_signals`. The default archived EOL rule makes ARCHIVED mandatory for policy evaluation. PyPI supplies all three. `YANKED` means all available artifacts for the target version are explicitly yanked; one explicit non-yanked artifact makes it `ABSENT`. RubyGems can supply explicit yank status for available releases, but its public APIs do not prove the status of a removed release.

`STALE_RELEASE/PRESENT` requires a complete available release list with publication dates. `ABSENT` can be established by a sufficiently recent verified release even if older versions have missing dates. For artifact-based native data, that release needs complete first-upload evidence; uploading another wheel for an old version does not reset its age. Native PyPI recognizes retained legacy eggs. deps.dev's limited Go/PyPI collections can confirm a recent release, but cannot prove prolonged inactivity. A future evaluation date remains `UNKNOWN`. Current registry data cannot reconstruct deleted releases or historical status changes. Rules using live status flags remain unresolved for historical or future evaluation dates.

See [registry sources and request behavior](docs/registries.md) for endpoints and limitations. GitHub source mapping is available across all seven registry ecosystems, using native metadata or deps.dev. GitLab/Bitbucket archival, native Go retraction, and native NuGet deprecation remain unimplemented. A rule that depends on unavailable data remains unresolved and makes the scan incomplete.

## Using a support catalog

Policy files are recursively merged into the built-in defaults. Relative paths are resolved from the policy file's directory. The optional official catalog is disabled by default; normal online scans use automatically fetched lifecycle evidence.

A local catalog adds reviewed official support information, version assertions, and generic EOL reviews alongside remote evidence. You can override its path with `--catalog ./support-catalog.yaml`; CLI paths are relative to the current directory. Official evidence takes precedence over curated evidence, and disagreements remain diagnostics.

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: true
    path: ./support-catalog.yaml
```

The catalog contains three arrays. See the [example](examples/support-catalog.example.yaml) and [schema](schemas/support-catalog.schema.json) for the full definitions.

- `entries`: Official security support windows or end dates. Each entry requires an applicable release series, source URL, review date, and expiry date.
- `verified_versions`: Exact versioned PURLs and publication times. These are preferred for version verification and enable offline checks or proof of versions absent from remote indexes.
- `general_eol_reviews`: Reviews of generic EOL dates, matched exactly by product slug, unversioned PURL, release series, and support scope.

Official evidence has `HIGH` confidence; automatically scoped security end dates and reviewed generic EOL evidence have `MEDIUM` confidence. Unreviewed or expired generic EOL evidence remains in the report but is excluded from the formal security assessment. The default general EOL rule can independently use a fresh applicable date. A future generic EOL date cannot establish `SUPPORTED`. Conflicting end dates within the highest applicable tier produce a formal support assessment of `UNKNOWN / CONFLICT`, including conflicts involving future dates. Evidence is excluded from conflict detection only when a formal replacement or withdrawal has been verified.

The products, reviews, and version assertions in `examples/support-catalog.example.yaml` are **fictional test data**. Try the offline example:

```sh
./bin/eolscan scan \
  -i examples/sbom.cdx.json \
  -c examples/eol-policy.catalog.example.yaml \
  --offline --as-of 2026-10-11
```

This returns `SUPPORTED / HIGH`. The example reviews and version assertions are valid through 2026-12-01. Expiry is checked against the execution date in UTC, so a historical `--as-of` date cannot restore expired evidence. Populate production catalogs with evidence you have actually verified.

## Using eolscan in CI

The default CI policy is report-first: only `EOL / HIGH` fails CI. Warnings are emitted for every EOL result, including matched maintenance rules. `UNKNOWN` results, `EOL / MEDIUM` results, and incomplete scans caused by API failures remain visible in the report. A scan with no components in scope always fails, and SIGINT/SIGTERM interruption always exits nonzero.

```sh
./bin/eolscan scan \
  -i sbom.cdx.json \
  -c examples/eol-policy.ci-strict.yaml \
  -f json -o report.json
```

The strict policy fails for EOL with at least `MEDIUM` confidence, incomplete scans, or an `UNKNOWN` ratio above 0.25. It retrieves support data and EOL-rule inputs automatically. Adjust the unknown-ratio threshold to the coverage of your actual SBOM.

To fail CI on support dates and matching maintenance rules while leaving unknown components visible, use `examples/eol-policy.auto-eol.yaml`. It sets `ci.min_confidence: MEDIUM` and keeps the default report-first treatment of unknown and incomplete checks. The default `HIGH` threshold reports automatically retrieved EOL/MEDIUM without failing CI.

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
| 3 | No components were in scope (`NO_COMPONENTS`), or a required check is incomplete with no other explicit CI violation. |
| 4 | Internal error. |
| 130 | Interrupted by SIGINT or SIGTERM. |

Cancellation while reading input or querying providers does not publish a report.

Run the compiled binary in CI. `go run` does not preserve the program's exit code and cannot reliably distinguish codes `1` and `3`.

Configure [expiring exceptions](examples/eol-exceptions.example.yaml) using `exceptions.path`. An exception suppresses component-level CI failures for an exact PURL; lifecycle results, the unknown ratio, and incomplete status remain visible.

## Offline mode, caching, and output

- `--offline` uses the local catalog and usable disk cache entries without making HTTP requests.
- `cache.enabled: true` stores `200` and `404` responses under `eolscan/v2` in the OS cache directory. No database is needed.
- `--no-cache` disables persistent caching. Combining it with `--offline` is a configuration error.
- Online scans refresh entries whose TTL has expired. Offline scans can use expired entries within the maximum evidence age, marked `CACHE_STALE`. Older entries are rejected.
- `--as-of YYYY-MM-DD` evaluates a UTC calendar date. Future evaluations are marked `projection: true`. Versions published after the evaluation date are `UNKNOWN`.
- JSON output retains all components, evidence, diagnostics, and CI results. File output is replaced atomically. `output.include_unknown` and `output.include_evidence` affect table display only.

Requests are paced per host at **2 requests/second, burst 1** by default, including retries and redirects. HTTP 429 and 503 establish a shared host cooldown. Retries use exponential backoff with jitter and honor `Retry-After`. A wait longer than `max_wait_seconds` (default 30, per wait) returns an unavailable lookup; CI completeness follows the configured required checks.

```yaml
schema_version: 2
network:
  requests_per_second: 2
  burst: 1
  max_wait_seconds: 30
  host_limits:
    rubygems.org:
      requests_per_second: 1
      burst: 1
cache:
  enabled: true
```

These limits apply to one process. Parallel CI jobs do not share budgets; keep concurrency and persistent cache settings appropriate for your runner.

Online scans send package names and versions to the configured public APIs. Requests are restricted to HTTPS on explicitly allowed hosts. Arbitrary URLs from the SBOM or evidence are not fetched, and configuration URLs containing credentials or query strings are rejected.

## Project layout

```text
cmd/eolscan/        CLI entry point and process lifecycle
internal/
  cli/             Command parsing and execution
  scanner/         Scan orchestration and CI gates
  sbom/            CycloneDX and SPDX parsing
  identity/        PURL normalization and release series matching
  lifecycle/       Support decisions and signal aggregation and configurable EOL rules
  provider/        Catalog, registry, deps.dev, and endoflife.date adapters
  transport/       HTTPS, host rate limits, retries, memoization, and disk cache
  config/          Policy, catalog, and exception loading
  contract/        Schema validation and canonical serialization
  model/           Shared input, policy, evidence, and report types
  report/          Table output, report invariants, and exit codes
  fileio/          Bounded reads and atomic writes
  version/         Application version
  testutil/        Deterministic test helpers
schemas/           Canonical JSON schemas, embedded in the binary
examples/          User-facing policies, catalogs, and sample SBOM
testdata/fixtures/  Fixed acceptance inputs, reports, and manifest
testdata/real-packages/  Reviewed public packages, live-scan inputs, and observations
tests/             Acceptance and HTTP integration tests
docs/              Design specification and architecture
.github/workflows/ CI checks
```

The command entry point delegates to the internal packages. Package tests live beside their implementations; tests spanning the scan pipeline live in `tests/`. See [architecture](docs/architecture.md) for dependencies and extension points.

## Development and validation

```sh
go test -race ./...
go vet ./...
go build -o bin/eolscan ./cmd/eolscan
```

Go tests cover design acceptance cases UT-01 through UT-45, native registry selection, fallback, signal completeness, offline caching, and host rate control. Regression tests cover nested metadata components, empty scans, cancellation, recent-release proof with incomplete older history, automatic security-scope detection, configurable AND/OR rules, package scopes, unknown conditions, source-repository discovery, date refresh, and offline cache expiry. Fifteen report fixtures run through the actual CLI and verify decisions, exit codes, input hashes, and policy hashes. External APIs are replaced with fixed responses and local HTTPS servers, so tests require no public API access.

The expanded suite covers the full two-input three-valued truth tables, mixed seven-ecosystem CycloneDX/SPDX scans, RubyGems listing/detail disagreements, PyPI source discovery, GitHub malformed responses and quota/redirect behavior, inactivity boundaries, and report/CI consistency. Linux CI also runs the built executable against local HTTPS fixtures. See [test scope, platform behavior, and coverage measurement](docs/testing.md).

[Actual package detection validation](docs/real-package-validation.md) uses 47 public versions across all seven ecosystems. On 2026-10-17 JST, the default criteria detected **34/36** reviewed retirement/deprecation targets; all ten controls remained without EOL. Adding a 730-day release inactivity rule detected **36/36**. A separate declarations-only profile detected **7/7** explicit retirement examples, including RubyGems. PyCrypto and Commons HttpClient remain default misses. This selected sample does not estimate general recall. Run `make validate-real-packages`; the validator exits nonzero while reviewed goals remain unmet.

JSON schemas are embedded in the binary to validate configuration and reports. Additional documentation and example validation uses Python, which is not a CLI runtime dependency.

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

See the [design, schemas, and fixture index](docs/README.md) for implementation details. Fully reproducing historical support policies requires fixed snapshots of external evidence.
