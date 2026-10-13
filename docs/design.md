# eolscan — Implementation Design v0.6

**Document status:** Release 0.4.0 implemented; automatic lifecycle retrieval with explicit security scope

**Revised:** 2026-10-13

**Audience:** CLI implementers, security reviewers, and CI administrators

**Authoritative specification:** This Markdown document. JSON schemas and example policies conform to it.

**Corresponding implementation release:** 0.4.0, independent of the document version

> **Core principle:** Return `SUPPORTED` only with **explicit evidence** that upstream security support covers the evaluation date. If the target version's existence and publication time cannot be verified, its lifecycle remains `UNKNOWN`.

## 0. Revision history and accepted decisions

### Decisions adopted in v0.6

| ID | Decision | Affected sections |
| --- | --- | --- |
| D-18 | Automatically scope endoflife.date dates when the API labels the ending phase as Security Support or Maintenance & Security Support. Record CURATED_SECURITY_END at MEDIUM confidence; future dates alone do not establish SUPPORTED. | §2, §6, §7 |
| D-19 | Remove fixed bundled product dates. Retrieve mappings and dates during scans, with optional TTL-based disk caching. Keep local official catalogs optional and disabled by default. Supersedes D-15. | §6, §8, §11 |
| D-20 | Emit report 2.3 with source_label and security-specific UNKNOWN reasons. Preserve report-first confidence defaults and provide a MEDIUM-threshold CI example. | §8, §10 |

### Decisions adopted in v0.5

| ID | Decision | Affected sections |
| --- | --- | --- |
| D-13 | Excluding the CycloneDX metadata subject must preserve its nested components. A scan with no components in scope always fails with NO_COMPONENTS and exit 3. | §5, §8, §10 |
| D-14 | Dispatch, workers, input, and output boundaries observe cancellation. Scans cancelled during input or provider work return no result and exit 130; a deadline exits 3. Bound process shutdown for blocked I/O. | §9 |
| D-15 | Enable a small reviewed official catalog embedded in the binary. Keep general EOL reviews and version assertions empty. Expiry still uses execution time. | §6, §8 |
| D-16 | Prove release inactivity only from complete available history. A verified recent release can prove ABSENT with incomplete older history. Do not let new artifacts reset an old version's release date. | §6 |
| D-17 | Emit report 2.2 with NO_COMPONENTS. Include bundled catalog contents in policy_hash and document limited lifecycle coverage separately from registry support. | §10 |

### Decisions adopted in v0.4

| ID | Decision | Affected sections |
| --- | --- | --- |
| D-10 | Prefer valid local publication assertions, then native npm/PyPI/RubyGems metadata, then deps.dev for unresolved capable checks. Share package responses across versions. | §5, §6 |
| D-11 | Pace all HTTP request starts per host, including retries and redirects; share 429/503 cooldowns, honor Retry-After, add jitter, and bound waits. | §8, §11 |
| D-12 | Add YANKED independently of DEPRECATED, expose explicit PyPI project markers, and retain UNKNOWN for unavailable required signals. Emit report 2.1. | §6, §7, §10 |

Configuration remains version 2, with native source and network defaults added. Current reports use version 2.3; consumers must accept YANKED, NO_COMPONENTS, source_label, and CURATED_SECURITY_END. Existing partial policies inherit automatic security-scope detection. Fixed bundled dates from CLI 0.3.0 are removed. A policy overriding `network.allowed_hosts` must allow enabled native hosts or disable those sources explicitly.

### Decisions adopted in v0.3

| ID | Decision | Affected sections |
| --- | --- | --- |
| D-06 | Retain future end dates, detect conflicts within the highest tier, then derive the state for the evaluation date. | §7 |
| D-07 | Use generic EOL evidence for EOL/MEDIUM only after reviewing its meaning for the product, PURL, release series, and support scope. The default allowlist is empty. | §2, §6, §7 |
| D-08 | Evaluate CI-required signals as PRESENT/ABSENT/UNKNOWN. If equivalent fallback information cannot resolve UNKNOWN, mark the scan incomplete. | §6, §7, §8 |
| D-09 | Require publication timestamps in VersionAssertion. Validate assertion and review expiry against the execution date. | §5, §6, §7 |

Document v0.3 was implemented by CLI 0.1.0 with configuration version 2 and report version 2.0.

### Decisions already adopted in v0.2

| ID | Issue | Decision in v0.2 | Affected sections |
| --- | --- | --- | --- |
| D-01 | Generic EOL dates could imply SUPPORTED. | Require an explicit `UPSTREAM_SECURITY_WINDOW` for SUPPORTED. endoflife.date's `eolFrom` alone is insufficient. | §2, §6, §7 |
| D-02 | Default exit 0 could differ from user expectations. | Default to **report-first**: `EOL/HIGH` exits 1; API-related incompleteness normally exits 0. Provide a separate strict policy. | §8, §9 |
| D-03 | Fabricated versions such as `7.2.9999` could receive lifecycle decisions. | **Verify version existence before lifecycle evaluation.** Unverified versions remain UNKNOWN. Use deps.dev GetVersion or an exact local version assertion. | §5, §7 |
| D-04 | `/products/full` and per-product GET requests duplicate work. | Fetch endoflife.date's `/identifiers/purl` index, then details for matched products. The MVP does not fetch the full dataset. Disk caching is **optional and off by default**. | §6, §11 |
| D-05 | EOL_SOON types, conflict settings, and output examples were inconsistent. | Separate `EOL_SOON` into `Notice`. Remove `unknown_on_same_tier_conflict`; same-tier conflicts always produce UNKNOWN. Define required and nullable fields in schemas. | §7, §8, §10 |

Configuration uses `schema_version: 2` and output uses `schema_version: "2.3"`. The earlier v0.1 design contract must not be silently reinterpreted. The HTTP cache format remains version 2.0, independently of the output report version.

## 1. System overview and scope

The CLI extracts packages from a single CycloneDX or SPDX JSON SBOM, identifies them by PURL, verifies exact versions, collects lifecycle evidence and maintenance signals, and produces decisions and reports.

### 1.1 MVP scope

| Area | MVP | Future extensions |
| --- | --- | --- |
| Input | CycloneDX JSON 1.4–1.7; SPDX 2.3 JSON | SPDX 3.x, XML, multiple SBOMs |
| Dependency identity | Complete versioned PURLs | CPE and explicit manual mappings |
| Ecosystems | gem, npm, pypi, maven, golang, cargo, nuget | OS distributions, oci, composer, and others |
| EOL evidence | Automatically retrieved endoflife.date security end dates; optional reviewed official catalog | Official vendor APIs, successor projects |
| Version verification | Exact catalog assertions; native npm/PyPI/RubyGems; deps.dev GetVersion | Additional native registries, signed snapshots |
| Signals | Native registry deprecation, PyPI project markers and yank metadata; available publication dates; deps.dev fallback | GitHub, native Go retract, NuGet deprecation, and others |
| Output | Tables; JSON report schema 2.3 | SARIF, HTML, CycloneDX annotations |
| Execution modes | Default report-first; strict CI policy; offline | Organization-wide policy distribution |

**Outside scope:** Vulnerability or CVSS detection, declaring EOL solely from release age, fuzzy name matching, automatically combining extended support with upstream support, and interpreting web pages with an LLM.

## 2. Concepts and EOL semantics

| Concept | Definition |
| --- | --- |
| `EOL` | Upstream security support has been confirmed to have ended. Generic EOL information can supply MEDIUM evidence only after reviewing its meaning for the product, release series, and support scope. |
| `SUPPORTED` | Explicit evidence confirms that upstream security support continues throughout a period containing the evaluation date. |
| `UNKNOWN` | Evidence is insufficient to establish EOL or SUPPORTED. It does not imply safety or ongoing support. |
| `CURATED_SECURITY_END` | An endoflife.date cutoff explicitly labelled as the end of a security phase. Eligible for EOL/MEDIUM without a per-product date review; future cutoffs alone remain UNKNOWN. |
| `GENERAL_EOL_END` | A generic EOL date published by a source such as endoflife.date. A future date does not imply SUPPORTED. |
| `UPSTREAM_SECURITY_WINDOW` | An officially stated upstream security support interval `[start, end)`. |
| `UPSTREAM_SECURITY_END` | An officially confirmed end date for upstream security support. It does not establish SUPPORTED before that date. |
| `MaintenanceSignal` | Deprecation, archival, prolonged inactivity, or similar information, evaluated independently of lifecycle. |
| `Notice` | A notification derived from a decision. The MVP includes only `EOL_SOON`. |
| `Confidence` | Confidence in the lifecycle evidence, rather than a measure of security risk. |

### 2.1 Date semantics and boundaries

- Evaluate lifecycle using UTC calendar dates (`YYYY-MM-DD`). Support has ended when `as_of >= eol_effective_date`.
- Capture `run_started_at` once when execution begins. Validate `valid_until` and `expires_on` for version assertions, catalog entries, generic EOL reviews, and CI exceptions against that execution date in UTC. A past `--as-of` date cannot restore expired material. An expiry date is inclusive; the material expires the next day.
- Convert `published_at` to a UTC calendar date before comparing it with `as_of`. A version published on the same calendar date can be evaluated for that date; this is not timestamp-level historical replay. A publication timestamp later than execution time cannot prove the existence of a future version.
- `eol_effective_date` means support is considered ended **from 00:00 UTC on that date**. If a source means support continues through the end of that day, normalize the effective date to the next day. Preserve the original date and conversion in evidence.
- `UPSTREAM_SECURITY_WINDOW` permits SUPPORTED when `support_start_date <= as_of < eol_effective_date`. `UPSTREAM_SECURITY_END` remains UNKNOWN before the end date.
- When `labels.eol` is exactly Security Support or Maintenance & Security Support and automatic scope detection is enabled, store endoflife.date's dated `eolFrom` as `CURATED_SECURITY_END` at MEDIUM confidence. On or after the cutoff it can establish EOL; beforehand return UNKNOWN/SECURITY_END_ONLY. Otherwise store it as `GENERAL_EOL_END`. It can yield `EOL/MEDIUM` only after the date has passed and a valid allowlist review matches the product, PURL, release series, and support scope. Retain unreviewed information as evidence and return `UNKNOWN/GENERAL_EOL_UNREVIEWED`. Before the end date, remain UNKNOWN unless a separate security window applies. Boolean fields cannot imply SUPPORTED.
- `isMaintained=true` may include extended support. Keep upstream and extended support distinct; `isMaintained` must not reverse an established upstream EOL. Record diagnostics for conflicting information.
- The default generic EOL review count is zero. Product-name-only permissions and blanket permissions for all products are prohibited. Expired reviews cannot supply EOL evidence.
- Future `--as-of` dates set `projection=true`. Do not infer future version existence or continued support.

### 2.2 Support authority

The MVP evaluates `upstream_security`. Distribution backports and paid extended support are separate authorities and cannot establish upstream support. The official catalog schema accepts only upstream security evidence.

Keep the original scope of generic EOL evidence as `general_eol`. Map its scope to `upstream_security` for comparison only when a valid review confirms that meaning. A review must not change `source_class` or raise confidence to HIGH.

## 3. Functional and quality requirements

| ID | Requirement |
| --- | --- |
| FR-01 | Extract SBOM packages and preserve their original reference IDs and versions. |
| FR-02 | Parse PURLs with a standard parser and prevent incorrect name or version matches. |
| FR-03 | **Complete version existence verification before lifecycle evaluation.** |
| FR-04 | Fetch only the required endoflife.date PURL index and product details, separately. |
| FR-05 | Store official security windows, official security end dates, and generic EOL dates as distinct evidence claims. |
| FR-06 | Store lifecycle, maintenance signals, derived notices, and diagnostics as separate types. |
| FR-07 | Provide JSON schemas for configuration and reports, and validate both. |
| FR-08 | Provide default report-first behavior, a strict CI example, and stable exit codes. |
| FR-09 | Report conflicts, missing information, and incomplete scans using auditable reason codes. |
| FR-10 | Support offline execution, retries, per-run memoization, and optional persistent caching. |
| FR-11 | Share parsed native metadata across package versions and use capable fallback only for unresolved checks. |
| FR-12 | Limit request starts per host, share server cooldowns, and retain unavailable lookups when wait budgets are exceeded. |

- **Reproducibility:** Preserve `as_of`, `tool_version`, `policy_hash`, `input_sha256`, and evidence `observed_at`. Historical API responses are not reconstructed; complete historical replay requires fixed fixtures.
- **Failure isolation:** A network failure for one package must not stop processing all packages.
- **Security:** Do not fetch arbitrary URLs from an SBOM. Enforce TLS, allowed hosts, secret redaction, and input size and depth limits.
- **Privacy:** State in help that package identities such as PURLs may be sent to public APIs, and provide `--offline`.

## 4. Architecture and module boundaries

The diagram describes the logical pipeline. See [architecture](architecture.md) for the concrete Go package layout.

```text
SBOM JSON
  -> FormatDetector / Parser
  -> Normalizer / PURL Resolver
  -> MetadataResolver (local assertions -> native registries -> deps.dev)
        |                             \
        |                              -> Maintenance Signals
        v
     LifecycleEvidenceProviders
       - Official Support Catalog
       - endoflife.date PURL Index -> Product Details
        |
        v
     EvidenceValidator (scope, version, freshness, dates)
        |
        v
     LifecycleEvaluator (EOL | SUPPORTED | UNKNOWN)
        |
        +-> NoticeEvaluator (EOL_SOON)
        +-> Diagnostics / IncompleteTracker
        |
        v
     Exception / CI Gate -> table | JSON | exit
```

| Module | Responsibility | Constraint |
| --- | --- | --- |
| `sbom` | Parse CycloneDX/SPDX and extract components. | Do not associate names with official products. |
| `identity` | Normalize PURLs, establish identity, and resolve release series. | Avoid incorrect matches from simple string prefixes. |
| `verification` | Verify that an exact version is registered. | An API 404 does not prove that the software does not exist. |
| `provider` | Collect evidence, signals, and diagnostics. | Do not make final lifecycle decisions. |
| `policy` | Evaluate scope, tier, conflicts, dates, and notices. | Do not automatically promote deprecation to EOL. |
| `transport` | Handle HTTP, per-host pacing, cooldowns, retries, concurrency, memoization, and optional disk caching. | Do not fetch arbitrary SBOM-supplied URLs. |
| `report` | Produce JSON/tables, aggregates, and exit codes. | Do not display unknown results as confirmed success. |

## 5. SBOM, PURL, and version verification

### 5.1 SBOM extraction

| Format | Extraction | PURL | Source reference |
| --- | --- | --- | --- |
| CycloneDX JSON 1.4–1.7 | `components[]` and nested `components[]` | `component.purl` | `bom-ref`, or a stable JSON path when absent |
| SPDX 2.3 JSON | `packages[]` | `externalRefs` with `referenceType=purl` | `SPDXID` |

Exclude only the CycloneDX `metadata.component` subject by default; inspect its nested components independently. Do not propagate exclusion of a parent to its children. Do not apply component type filtering to SPDX packages. Query duplicate PURLs once, but emit a result for each original component. Make `input.include_component_types` and `input.include_metadata_component` configurable. Zero components in scope produce a failed JSON/table report with NO_COMPONENTS and exit 3, irrespective of the report-first policy.

### 5.2 Package and version validity

1. Use a standard PURL parser rather than splitting `name/version`. Follow ecosystem rules for names, namespaces, case, qualifiers, and subpaths.
2. If both PURL and SBOM versions exist and differ, return UNKNOWN with `VERSION_CONFLICT`. Missing versions or version ranges produce UNKNOWN with `VERSION_UNRESOLVED`.
3. Do not confuse a private package with a public package of the same name. Suspected private dependencies produce UNKNOWN with `PRIVATE_SOURCE_UNSUPPORTED`.
4. Verify the **exact target version** in the PURL. `version_verification.mode=required` is the MVP's only mode.
5. Verification requires an exact trusted local `verified_versions` assertion, valid matching native registry metadata, or deps.dev GetVersion HTTP 200 with a matching normalized version. Every method requires publication time. Prefer local assertions, then native registries, then deps.dev; the configured methods select capabilities rather than change this precedence. A release series match alone cannot prove version existence.
6. An index 404 or missing exact version means `NOT_FOUND_IN_INDEX`, rather than proving global nonexistence. Try another capable configured source; if unresolved, keep lifecycle UNKNOWN and record `VERSION_NOT_FOUND_IN_INDEX`.
7. Timeouts, 429s, and 5xx responses leave a lookup unavailable. Record SOURCE_ERROR or RATE_LIMITED; exhausted token waits use RATE_LIMIT_WAIT_TIMEOUT. Without a valid fallback, version status is UNVERIFIED and the scan is incomplete.
8. If the UTC date of `published_at` is later than `as_of`, return UNKNOWN with `NOT_RELEASED_AS_OF`; do not replace conclusive native proof with fallback. Missing or invalid publication times produce `UNVERIFIED / VERSION_UNVERIFIED` even when evaluating the current date. HTTP 200 and a matching version alone are insufficient for VERIFIED. If no valid fallback supplies the timestamp, set `incomplete=true`. A timestamp later than execution time produces `UNVERIFIED / PUBLICATION_IN_FUTURE`.
9. Never assign `EOL` or `SUPPORTED` to a component whose verification is not `VERIFIED`. Still report maintenance signals and diagnostics already collected.
10. `version_verification.mode=required` is a fixed policy invariant. Any future relaxed mode requires a separate specification and version.

The verification status values are `VERIFIED | NOT_FOUND_IN_INDEX | UNVERIFIED | NOT_RELEASED_AS_OF | NOT_APPLICABLE`. `NOT_APPLICABLE` also leaves lifecycle UNKNOWN.

### 5.3 Release series matching

- Match product release series only after an exact PURL type and package identity match.
- MVP automatic matching supports only **numeric dotted series**, such as `7.2` matching `7.2.4`. Compare complete numeric segments so `7.2` does not match `7.20`.
- Choose the longest matching series. If equally ranked candidates differ in meaning, return `AMBIGUOUS_CYCLE`.
- Date-based series, codenames, LTS names, and prereleases remain UNKNOWN without an explicit catalog mapping.
- **A series match establishes the applicability of lifecycle evidence; it cannot replace exact version verification.**

## 6. Providers and data retrieval

### 6.1 Common provider contract

```text
Provider {
  id(): string
  supports(component): bool
  fetch(component, context): ProviderResult
}
ProviderResult {
  lifecycle_evidence: LifecycleEvidence[]
  version_assertions: VersionAssertion[]
  signals: SignalEvidence[]
  signal_evaluations: SignalEvaluation[]
  diagnostics: Diagnostic[]
}
```

Route communication through `transport`. Providers normalize identities, dates, and applicability but do not return final lifecycle statuses. Preserve original source links, field names, and observation times. Distinguish HTTP 404, HTTP 429, and timeouts.

### 6.2 Official support catalog, version assertions, and generic EOL reviews

The optional official catalog is disabled by default. Lifecycle mappings and dates are retrieved during online scans; see [automatic retrieval, freshness, and optional local catalogs](catalog.md). A local `support-catalog.yaml` supplies official evidence, version assertions, or generic EOL meaning reviews alongside remote evidence. The catalog is a trust boundary: scans rely on recorded review rather than automatically reviewing linked content. The fixed bundled catalog and its reserved selection were removed in release 0.4.0.

- `entries[]`: Official security windows and end dates. Require an official evidence URL, support authority, review date, and expiry date. Windows require both start and end dates. An end date alone cannot establish SUPPORTED beforehand.
- `verified_versions[]`: VersionAssertion objects defined below, with manually verified exact versioned PURLs and publication times. Do not generate versions from release series.
- `general_eol_reviews[]`: GeneralEolReview objects defined below, confirming the meaning for a product slug, unversioned PURL, release series, and `upstream_security` scope. Blanket product permissions and wildcards are prohibited.
- Validate expiry against the UTC date of `run_started_at`. Exclude expired material from decisions and record `STALE_EVIDENCE`.
- An official entry's `match` is `numeric_segment_prefix` or `exact_versions`. The former requires an empty `versions` array; the latter requires explicit version strings. Series mapping and version existence verification remain separate operations.
- Only a verified formal withdrawal or update may populate `superseded_by` and `supersession_source_url` with replacement evidence ID and proof URL. A newer observation time alone does not establish precedence.

```text
VersionAssertion {
  package_purl: string       # Exact versioned PURL
  published_at: timestamp   # Required; normalize to UTC
  source_url: https_url
  reviewed_at: date
  valid_until: date         # Validate against execution UTC date
}
GeneralEolReview {
  id: string
  product_slug: string
  package_purl: string       # Unversioned
  matched_cycle: string
  support_scope: upstream_security
  evidence_url: https_url
  reviewed_at: date
  valid_until: date
}
```

The catalog example uses a fictional product and must not be used as proof of support for a real product.

```yaml
schema_version: 2
entries:
  - id: example-security-2.4
    package_purl: pkg:gem/example
    matched_cycle: "2.4"
    match: numeric_segment_prefix
    versions: []
    claim: UPSTREAM_SECURITY_WINDOW
    support_scope: upstream_security
    support_start_date: "2024-04-12"
    eol_effective_date: "2026-12-01"
    evidence_url: https://example.org/support/2.4
    support_authority: example-upstream
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
    superseded_by: null
    supersession_source_url: null
verified_versions:
  - package_purl: pkg:gem/example@2.4.7
    published_at: "2024-04-12T09:00:00Z"
    source_url: https://example.org/releases/2.4.7
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
general_eol_reviews:
  - id: example-general-eol-2.4
    product_slug: example
    package_purl: pkg:gem/example
    matched_cycle: "2.4"
    support_scope: upstream_security
    evidence_url: https://example.org/support/2.4
    reviewed_at: "2026-10-01"
    valid_until: "2026-12-01"
```

The schema is `../schemas/support-catalog.schema.json`; a complete example is `../examples/support-catalog.example.yaml`. If a review's target does not match the actual product details, treat the information as unreviewed.

### 6.3 endoflife.date API v1: PURL index to product details

**The MVP uses the following retrieval strategy.** Do not use `/products/full`.

1. When needed, fetch `GET https://endoflife.date/api/v1/identifiers/purl/` once per run. Redirects, including trailing-slash normalization, must remain on the fixed host.
2. Build an index from `result[].identifier`, an unversioned PURL, and `result[].product.uri`. Validate product URIs against `https://endoflife.date/api/v1/products/{slug}/`; reject unknown hosts or unexpected paths.
3. Accept only **exact matches** to the component's unversioned PURL. Multiple matching products produce `AMBIGUOUS_IDENTITY`.
4. Fetch `GET /api/v1/products/{slug}/` only for matched products. Coalesce requests for the same product.
5. Confirm the identity again in the product's `identifiers[type=purl]`, then match the series against `releases[].name`.
6. Retain `labels.eol` in `source_label`. If automatic scope detection is enabled and the label is exactly Security Support or Maintenance & Security Support, store the dated `releases[].eolFrom` as `CURATED_SECURITY_END`, scope upstream_security, rule R-012, and confidence MEDIUM. Otherwise store GENERAL_EOL_END. `isEol` and `isMaintained` cannot establish SUPPORTED.
7. Match generic EOL reviews by product slug, PURL, series, and support scope. Store matching valid reviews in evidence `general_eol_review`. Unmatched or absent reviews are null. Preserve expired reviews but exclude them from decisions. Retain original evidence in every case.
8. CURATED_SECURITY_END participates in tier and conflict comparison after freshness and identity checks, without a per-product date review. On or after its cutoff return EOL/MEDIUM, otherwise UNKNOWN/SECURITY_END_ONLY. Unreviewed generic EOL produces `UNKNOWN/GENERAL_EOL_UNREVIEWED`. Reviewed evidence participates in tier and conflict comparison even when its end date is in the future. Without a conflict, return EOL/MEDIUM on or after the end date and UNKNOWN/GENERAL_EOL_ONLY beforehand. An official window follows official-tier rules.

In the OpenAPI contract, `/identifiers/{identifier_type}` returns `result[]` items containing `identifier` and a `product` URI reference. `/products/full` returns all product details and is not used to obtain the index.

### 6.4 deps.dev API v3: Version verification and signals

- `GET /v3/systems/{system}/packages/{name}/versions/{version}` is the version provider for ecosystems without native support and a fallback for unresolved native metadata. Systems are `GO/RUBYGEMS/NPM/CARGO/MAVEN/PYPI/NUGET`.
- Require both HTTP 200 and a normalized `versionKey.system/name/version` matching the target. A mismatch produces `VERSION_CONFLICT`.
- `isDeprecated=true` records `DEPRECATED/PRESENT` and preserves `deprecatedReason`; it does not change lifecycle. Treat false or an absent field as ABSENT only when the ecosystem and API contract provide reliable negative information. Missing collection capability, missing data, or API failures produce UNKNOWN.
- `publishedAt` is mandatory for version verification. A missing or invalid value produces UNVERIFIED unless a valid fallback assertion supplies it.
- STALE_RELEASE/PRESENT requires a complete GetPackage version list and publication dates. A verified recent publication can establish ABSENT even if other version dates are missing or the Go/PyPI collection is limited. A gap exceeding `stale_release_days` establishes PRESENT only when available history is complete. API failure, invalid future publication, absent recent proof with incomplete history, or a future `as_of` requiring prediction produce UNKNOWN.
- A 404 means `NOT_FOUND_IN_INDEX`, without proving that the version does not exist. Do not retry it; leave the result UNKNOWN.
- Convert Maven `group:artifact` names, npm scopes, Go paths, and URL encoding according to the official API contract.
- deps.dev does not itself guarantee upstream security support for any ecosystem.

### 6.5 Native npm, PyPI, and RubyGems

The authoritative endpoint and signal details are in [registry sources](registries.md). Native sources are enabled by default; all requests use the shared transport and allowed hosts. Share each immutable parsed package snapshot across its SBOM versions.

- npm full metadata supplies exact version records, `time[version]`, and deprecation messages. A valid full version record without a deprecation message confirms ABSENT; missing or malformed metadata remains UNKNOWN.
- PyPI uses the JSON Index API with its vendor media type, identifies versions from wheel/sdist and recognized legacy egg filenames, and reads `upload-time`, `yanked`, and explicit `project-status`. The deprecated project JSON `releases` field is not used. Exact version aliases or unrecognized artifacts may require fallback. Missing project markers remain UNKNOWN.
- RubyGems uses the v1 versions list with `created_at`, and v2 exact details with `version_created_at` where needed. Never use `built_at` as publication. An explicit platform qualifier requires a matching native platform; platform-independent fallback cannot certify another artifact. Public endpoints exclude removed/yanked releases; a miss does not prove yanking or recover publication time.
- YANKED is distinct from DEPRECATED. For PyPI, every available artifact of a target version must be explicitly yanked for PRESENT; any explicit non-yanked artifact gives ABSENT. Incomplete artifact identification or missing statuses cannot establish a positive result.
- STALE_RELEASE/PRESENT needs complete available release metadata. ABSENT can use one recent release whose first-upload evidence is complete, despite missing dates for other versions. Unassigned PyPI artifacts can hide an earlier upload and block that proof. A newer wheel/platform build for an old version does not reset release age. Deleted history and past marker changes cannot be reconstructed. Future `as_of` values remain UNKNOWN.
- Native failures remain diagnostics if fallback succeeds. A known native signal avoids an extra equivalent lookup; contradictory fallback data already needed for another check produces SIGNAL_CONFLICT. Registry facts cannot create lifecycle evidence.

### 6.6 Future providers and behavior

GitHub archived status, native Go retract, native NuGet deprecation, and other individual registry APIs remain future capabilities. Configuring `github.enabled=true` is a **configuration error (exit 2)**; reject unknown provider settings.

Future signal types may still be listed in `ci.fail_on_signals`. If no provider can evaluate a requested signal, its status is UNKNOWN and `incomplete=true`.

## 7. Internal types, evaluation, and conflict rules

### 7.1 Type contracts: Logical model

`LifecycleEvidence`: **Every field is required; `| null` means an explicit null value.**

```text
LifecycleEvidence {
  id: string
  provider_id: string
  source_class: OFFICIAL | CURATED_DATABASE
  claim: UPSTREAM_SECURITY_WINDOW | UPSTREAM_SECURITY_END | GENERAL_EOL_END | CURATED_SECURITY_END
  package_purl: string                    # Unversioned
  product_slug: string | null             # Required for curated evidence
  matched_cycle: string
  support_scope: upstream_security | general_eol
  support_start_date: date | null
  eol_effective_date: date
  source_url: https_url
  source_field: string
  source_label: string | null             # Original labels.eol for remote evidence
  observed_at: timestamp
  source_updated_at: timestamp | null
  reviewed_at: date | null                 # Required for OFFICIAL
  valid_until: date | null                 # Required for OFFICIAL; validate against execution date
  raw_payload_hash: string | null         # SHA-256 hex
  confidence: HIGH | MEDIUM
  rule_id: string                         # Interpretation rule for this evidence
  general_eol_review: GeneralEolReview | null
  superseded_by: string | null
  supersession_source_url: https_url | null
}
```

`VersionVerification`:

```text
VersionVerification {
  status: VERIFIED | NOT_FOUND_IN_INDEX | UNVERIFIED |
          NOT_RELEASED_AS_OF | NOT_APPLICABLE
  provider_id: string | null
  source_url: https_url | null
  checked_at: timestamp | null
  published_at: timestamp | null
  reason_code: string | null
}
```

`SignalEvidence`, with the MVP enum:

```text
SignalEvidence {
  type: DEPRECATED | YANKED | ARCHIVED | RETRACTED | QUARANTINED |
        STALE_RELEASE | STALE_REPOSITORY
  provider_id: string
  source_url: https_url | null
  observed_at: timestamp
  details: object
}
```

`SignalEvaluation`: One evaluation is required for each type in the union of enabled detection types and CI-required types.

```text
SignalEvaluation {
  type: SignalEvidence.type
  status: PRESENT | ABSENT | UNKNOWN
  provider_id: string | null
  source_url: https_url | null
  checked_at: timestamp | null
  reason_code: string | null
}
```

PRESENT requires corresponding evidence in `signals[]`. ABSENT requires a successful evaluation with sufficient negative information; HTTP success alone is insufficient. UNKNOWN requires a reason.

Aggregate equivalent successful information across providers. Conflicting evaluations produce UNKNOWN/SIGNAL_CONFLICT. Exceptions do not change evaluation status or incompleteness.

`Notice` is **derived information**, not a provider signal:

```text
Notice {
  type: EOL_SOON
  days_remaining: integer                 # 1..notice threshold
  evidence_id: string
  rule_id: "R-009"
}
```

`Diagnostic` requires `code`, `provider_id|null`, `http_status|null`, `retryable`, and `message`. A LifecycleEvidence `source_url` is the authoritative evidence URL. Do not output retrieval URLs containing authentication parameters.

### 7.2 Evidence tiers and comparison

1. Collect evidence matching the target PURL, exact version, and applicable release series. Retain original data and diagnostics.
2. Validate expiry, date syntax, support scope, automatic security labels, and generic EOL reviews. Exclude invalid, expired, or unreviewed information from the decision set, but retain it in `evidence[]`. Exclude older material from comparison only when a verified formal withdrawal or update supplies a proof URL and replacement evidence ID.
3. **Do not compare `as_of` with end dates to remove candidates at this stage. Retain future end dates.**
4. Select the highest eligible tier: `OFFICIAL/HIGH > CURATED_DATABASE/MEDIUM`. Reviewed generic EOL has comparison scope upstream_security, while its original source class, confidence, and scope remain unchanged.
5. If the highest tier contains different end dates for the same target version and support scope, return `UNKNOWN/CONFLICT`. Different start dates between windows also conflict. A window and an end-only claim with the same end date do not conflict; the explicit window can establish continued support. Record lower-tier differences in dates or states as `SOURCE_DISAGREEMENT` without overriding the higher tier.
6. After conflict detection, compare the evaluation date with the dates. A window yields SUPPORTED for `start <= as_of < end`, EOL for `as_of >= end`, and UNKNOWN before its start. A security end claim yields EOL on or after its end date, otherwise UNKNOWN. Reviewed GENERAL_EOL_END yields EOL/MEDIUM on or after its end date, otherwise UNKNOWN/GENERAL_EOL_ONLY. CURATED_SECURITY_END yields EOL/MEDIUM on or after its end date, otherwise UNKNOWN/SECURITY_END_ONLY.
7. If a higher-tier future security end claim yields UNKNOWN, do not fall back to lower-tier evidence to return EOL. Separate highest-tier selection from state derivation.
8. Without verified version existence and publication time, lifecycle remains UNKNOWN regardless of the evidence comparison. Retain collected diagnostics such as CONFLICT. For a definitive lifecycle decision, save selected evidence IDs in `selected_evidence_ids[]`.
9. Add an EOL_SOON notice only when the result is `SUPPORTED` and `0 < days_until_eol <= notices.eol_soon_days`.

Example: Official security end dates of 2026-10-01 and 2026-12-01 produce UNKNOWN/CONFLICT even for as_of=2026-10-11. Remove the older claim from comparison only after verifying a formal update that withdraws it.

**Deduplication:** Deduplicate claims with the same primary source, applicability, and dates. The number of independent sources must not increase confidence.

### 7.3 Stable rule IDs

| Rule ID | Condition |
| --- | --- |
| `R-001` | Official security window or end evidence establishes EOL / HIGH. |
| `R-002` | An official security window includes the evaluation date: SUPPORTED / HIGH. |
| `R-003` | CURATED GENERAL_EOL_END has a valid matching meaning review and has ended: EOL / MEDIUM. |
| `R-004` | **Retired and reserved.** The v0.1 CURATED-to-SUPPORTED rule must not be implemented. |
| `R-005` | Extract maintenance signals without changing lifecycle. |
| `R-006` | No eligible lifecycle candidate: UNKNOWN. |
| `R-007` | Same-tier evidence conflicts: UNKNOWN / CONFLICT. |
| `R-008` | Lower-tier disagreement: retain the higher tier and add a diagnostic. |
| `R-009` | SUPPORTED with a scheduled end within the threshold: EOL_SOON notice. |
| `R-010` | Apply exceptions and the CI gate without changing lifecycle. |
| `R-011` | Version unverified, absent from the index, or not yet published: UNKNOWN. |
| `R-012` | Automatically retrieved, explicitly scoped CURATED_SECURITY_END has elapsed: EOL / MEDIUM. |

### 7.4 Required algorithm: Pseudocode

```text
run_started_at = utc_now_once()
run_date = utc_date(run_started_at)
required_signal_types = ci.fail_on_signals
requested_signal_types = enabled_signal_types union required_signal_types

for component in normalized_sbom:
  initialize lifecycle=UNKNOWN, confidence=null, chosen=[], reasons=[]
  initialize evidence=[], signals=[], diagnostics=[], signal_evaluations=[]
  if invalid_identity_or_version:
    verification = NOT_APPLICABLE
    reasons = identity_reasons
    signal_evaluations = UNKNOWN for each requested_signal_type
  else:
    verification = verify_exact_version_and_publication(component, as_of, run_started_at)
    collected = fetch_lifecycle_and_signals(component, requested_signal_types)
    evidence = normalize_evidence_keep_all(collected)
    eligible = validate_identity_cycle_scope_dates_freshness(evidence, run_date)
    eligible = validate_explicit_security_labels_or_matching_general_eol_review(eligible, run_date)
    eligible = remove_explicitly_superseded_with_proof(eligible)
    top = evidence_at_highest_tier(eligible)  # Retain evidence with future end dates
    conflict = compare_end_dates_and_support_windows(top)
    diagnostics += lower_tier_disagreements(eligible, top)
    signal_evaluations, signals = aggregate_signal_evaluations(collected)

    if verification.status != VERIFIED:
      reasons = verification_reasons(verification)
      diagnostics += conflict_if_present(conflict)
    elif conflict:
      reasons = [CONFLICT]
    elif top is empty:
      reasons = explain_no_eligible_evidence(evidence)
    else:
      lifecycle, reasons = derive_state_after_conflict_check(top, as_of)
      if lifecycle != UNKNOWN:
        chosen = deterministic_applicable_evidence(top, lifecycle)
        confidence = HIGH if top.tier == OFFICIAL else MEDIUM

  selected_evidence_ids = ids(chosen)
  notices = derive_eol_soon_only_if_supported(chosen, as_of, soon_days)
  required_signal_unknown = any(e.status == UNKNOWN for e in signal_evaluations
                                if e.type in required_signal_types)
  incomplete = required_lookup_unavailable_without_equivalent_success(component)
               or required_signal_unknown
  ci_failure = evaluate_component_ci(lifecycle, confidence, signal_evaluations, exceptions)
  emit result with all evidence, verification, evaluations, diagnostics, incomplete

report.ci_gate = aggregate_component_failures_unknown_ratio_incomplete()
exit_code = apply_exit_precedence(report.ci_gate)
```

### 7.5 UNKNOWN reasons and scan incompleteness

Lifecycle reason codes: `MISSING_PURL`, `INVALID_PURL`, `VERSION_UNRESOLVED`, `VERSION_CONFLICT`, `VERSION_NOT_FOUND_IN_INDEX`, `VERSION_UNVERIFIED`, `NOT_RELEASED_AS_OF`, `PUBLICATION_IN_FUTURE`, `PRIVATE_SOURCE_UNSUPPORTED`, `UNSUPPORTED_ECOSYSTEM`, `AMBIGUOUS_IDENTITY`, `AMBIGUOUS_CYCLE`, `GENERAL_EOL_ONLY`, `GENERAL_EOL_UNREVIEWED`, `SECURITY_END_ONLY`, `SECURITY_SCOPE_UNCONFIRMED`, `NO_LIFECYCLE_EVIDENCE`, `STALE_EVIDENCE`, `CONFLICT`, `SOURCE_ERROR`.

- Set `incomplete=true` if required version verification, publication time, or highest-tier evidence retrieval fails because of an error or missing data, without an equivalent or better valid fallback.
- An index miss, index 404, unreviewed generic EOL, NOT_RELEASED_AS_OF, or ordinary lack of evidence does not alone make a scan incomplete.
- **A CI-required signal with UNKNOWN status always sets `incomplete=true`**, whether caused by an API failure, missing publication time, or unavailable retrieval capability. Never convert UNKNOWN to ABSENT.
- A successful equivalent fallback evaluation of a required signal can avoid incompleteness. Failures affecting only optional signals remain diagnostics and do not alone make a scan incomplete.
- `fail_on_incomplete_scan=true` makes incompleteness a gate violation. When false, retain incompleteness in `result.incomplete` and `ci_gate.incomplete`. Exceptions do not waive incompleteness.
- Invalid identities still require UNKNOWN evaluations for CI-required signals that cannot be queried, and `incomplete=true`. An early return must not omit required evaluations.

## 8. YAML configuration and defaults

### 8.1 Resolution and invariants

- Precedence is `CLI flags > YAML > built-in defaults`. Policy YAML requires `schema_version: 2`; all other fields may be supplied as **partial overrides**. Validate unknown keys and types against the input schema, recursively merge into defaults, then validate the effective policy. Resolve relative paths from the policy file's directory.
- Unknown configuration keys, type mismatches, enabling unimplemented capabilities, or contradictory values produce `exit 2` in both `policy validate` and `scan`.
- **Removed keys:** `decision.unknown_on_same_tier_conflict` and `decision.excluded_general_eol_products`. Same-tier conflicts always yield UNKNOWN; generic EOL requires valid reviews. Reject the old keys as unknown configuration.
- `version_verification.mode` is fixed to `required`. `decision.support_scope` is fixed to `upstream_security`. Configuration cannot change lifecycle semantics.
- Configurable areas are query providers, notice thresholds, caching, networking, the CI gate, local catalogs and reviews, and exceptions.
- This document and `policy.schema.json` define the policy contract. Compute `policy_hash` as SHA-256 of the normalized `{policy, catalog, exceptions}` object containing the effective policy and referenced catalog and exception content. Use UTF-8 JSON, sorted keys, and no extra whitespace. Unused catalogs or exceptions are null. Relative paths retain their literal configuration values in the hash; actual file resolution uses the policy directory. Exclude secret values.

### 8.2 Default: Report-first

```yaml
schema_version: 2
input:
  include_component_types:
    - "library"
    - "framework"
    - "application"
    - "operating-system"
  include_metadata_component: false
  max_input_bytes: 52428800
  max_components: 100000
  max_json_depth: 128
sources:
  npm:
    enabled: true
    base_url: "https://registry.npmjs.org"
  pypi:
    enabled: true
    base_url: "https://pypi.org"
  rubygems:
    enabled: true
    base_url: "https://rubygems.org"
  official_catalog:
    enabled: false
    path: null
  endoflife_date:
    enabled: true
    base_url: "https://endoflife.date/api/v1"
    match_purl_exactly: true
    use_security_support_label: true
  deps_dev:
    enabled: true
    base_url: "https://api.deps.dev/v3"
version_verification:
  mode: "required"
  sources:
    - "official_catalog"
    - "registries"
    - "deps_dev"
signals:
  deprecated: true
  yanked: false
  archived: false
  quarantined: false
  stale_release_days: 730
notices:
  eol_soon_days: 90
decision:
  support_scope: "upstream_security"
  max_evidence_age_days: 30
network:
  allowed_hosts:
    - "endoflife.date"
    - "api.deps.dev"
    - "registry.npmjs.org"
    - "pypi.org"
    - "rubygems.org"
  timeout_seconds: 8
  retries: 2
  max_concurrency: 6
  requests_per_second: 2
  burst: 1
  max_wait_seconds: 30
  host_limits: {}
cache:
  enabled: false
  positive_ttl_hours: 24
  negative_ttl_hours: 6
ci:
  fail_on_statuses:
    - "EOL"
  min_confidence: "HIGH"
  fail_on_signals: []
  fail_on_incomplete_scan: false
  max_unknown_ratio: null
exceptions:
  path: null
output:
  include_unknown: true
  include_evidence: true
```

**Required user-facing explanation:** Online scans retrieve current lifecycle mappings and dates. Only explicit security phase labels automatically establish scope, at MEDIUM confidence; linked official pages do not raise confidence. No fixed product dates ship in the binary. Generic EOL reviews and local version assertions remain optional. Version existence still requires independent verification. Future end-only claims, ambiguous labels, and identities outside source coverage remain UNKNOWN. The default HIGH CI threshold reports automatic EOL/MEDIUM; `eol-policy.auto-eol.yaml` lowers it to MEDIUM to fail on these results.

A catalog containing only generic EOL meaning reviews can yield EOL/MEDIUM. That result alone does not fail CI at the default HIGH threshold. API-related incompleteness also does not fail default CI. Report-first prioritizes reporting and inventory.

### 8.3 Strict CI profile

The bundled `eol-policy.ci-strict.yaml` is a **complete standalone policy file** based on the defaults with these changes:

```yaml
ci:
  fail_on_statuses: [EOL]
  min_confidence: MEDIUM
  fail_on_signals: []
  fail_on_incomplete_scan: true
  max_unknown_ratio: 0.25
```

The snippet shows the strict policy's **differences**; the bundled file contains the full configuration. `max_unknown_ratio: 0.25` is an example threshold to adjust for an organization's tolerance. Ecosystems with many UNKNOWN results may trigger frequent failures; observe coverage in report-first mode before enabling this gate.

- `ci.min_confidence` applies only to EOL. If `fail_on_statuses` includes UNKNOWN, that status fails regardless of confidence.
- `ci.fail_on_signals` accepts signal types and makes their evaluations mandatory, even if detection is otherwise disabled. PRESENT is a component violation, ABSENT is not a violation, and UNKNOWN makes the scan incomplete. Notices are excluded. Requiring STALE_RELEASE with a null threshold is contradictory and exits 2.
- `max_unknown_ratio` is violated when `unknown/in_scope > threshold`. For `in_scope=0`, the ratio is zero, but NO_COMPONENTS always fails the scan independently of this threshold.
- Exceptions suppress only component-level CI failures. They do not waive aggregate unknown ratio or scan incompleteness.

## 9. CLI and exit codes

```bash
eolscan scan -i sbom.cdx.json --format table
eolscan scan -i sbom.cdx.json -c eol-policy.ci-strict.yaml --format json -o report.json
eolscan scan --input sbom.spdx.json --offline --as-of 2026-10-11
eolscan scan --input sbom.cdx.json --catalog ./support-catalog.yaml
eolscan policy validate --config eol-policy.example.yaml
eolscan providers list
eolscan version
```

| Option | Meaning |
| --- | --- |
| `scan -i, --input` | Required: input file, or `-` for stdin. |
| `-c, --config` | Optional policy file. Defaults to report-first when omitted. |
| `--catalog` | Local YAML path, overriding the policy's catalog selection; CLI paths resolve from the current directory. |
| `-f, --format` | `table` by default, or `json`. |
| `-o, --output` | Defaults to stdout. File output uses atomic replacement from a temporary file. |
| `--as-of` | UTC date; defaults to the execution date in UTC. |
| `--offline` | Use only the local catalog and usable disk cache entries, without external HTTP. |
| `--no-cache` | Disable disk caching; cannot be combined with `--offline`. |
| `--verbose` | Write diagnostic logs to stderr with tokens and secrets masked. |

| Exit | Condition |
| --- | --- |
| `0` | Execution completed without CI violations. **The default may exit 0 with UNKNOWN, MEDIUM EOL, or incomplete results.** |
| `1` | A configured CI gate violation, such as EOL or excessive unknown ratio. |
| `2` | A user-correctable input or configuration error, including an unsupported schema version. |
| `3` | NO_COMPONENTS; or a required incomplete scan with no other explicit policy violation; or a context deadline. |
| `4` | An unexpected internal error. |
| `130` | A scan interrupted by SIGINT/SIGTERM. |

Cancellation takes precedence over scan outcomes. Otherwise precedence is `2/4` (processing failure) `> 1` (explicit violation) `> 3` (incomplete or empty) `> 0`. If `ci_gate.incomplete=true` and an EOL violation is also present, exit 1 and retain both in the report.

The parser and scanner check context cancellation; the dispatch loop stops submitting jobs and active workers finish cancellation. The CLI does not serialize an interrupted scan as a successful report and leaves an existing report file intact when cancellation occurs during input or provider work. The process entry point allows a bounded shutdown interval for blocked I/O. Exit 130 applies even when `ci.fail_on_incomplete_scan=false`.

## 10. JSON report 2.3 contract

Keep `../schemas/report.schema.json` consistent with this specification, and maintain `../examples/report.example.json` as a complete valid example. Schemas validate structure; additional semantic validation checks date comparisons, reference IDs, and aggregate values.

### 10.1 Result structure

```text
Report {
  schema_version: "2.3", tool_version, as_of, projection, generated_at,
  input_sha256, policy_hash,
  summary: {in_scope, excluded, eol, supported, unknown,
            assessment_coverage, provider_error_count, ci_failure_count},
  ci_gate: {passed, violation_codes, incomplete},
  results: ComponentResult[]
}
ComponentResult {
  source_ref, purl, name, version,
  version_verification: VersionVerification,  # Required
  lifecycle: EOL | SUPPORTED | UNKNOWN,
  confidence: HIGH | MEDIUM | null,
  eol_effective_date: date | null,
  matched_cycle: string | null,
  signals: SignalEvidence[],                  # Evidence for PRESENT evaluations only
  signal_evaluations: SignalEvaluation[],      # PRESENT/ABSENT/UNKNOWN
  selected_evidence_ids: string[],             # Empty for UNKNOWN
  notices: Notice[],                          # EOL_SOON belongs here
  unknown_reasons: string[],
  rule_ids: string[],
  evidence: LifecycleEvidence[],              # Retain every required field
  diagnostics: Diagnostic[],
  incomplete: bool,
  ci_failure: bool,
  exception_applied: bool
}
```

### 10.2 Invariants

1. `in_scope == eol + supported + unknown`.
2. `assessment_coverage == (eol + supported) / in_scope`, or zero when there are no components in scope.
3. `lifecycle=UNKNOWN` requires `confidence=null`, `eol_effective_date=null`, and at least one `unknown_reasons` entry.
4. `lifecycle!=UNKNOWN` requires `version_verification.status=VERIFIED`, `confidence in [HIGH,MEDIUM]`, an `eol_effective_date`, and at least one selected evidence item.
5. SUPPORTED requires selected official upstream_security window evidence containing the evaluation date. EOL derived from generic EOL requires a review matching product, PURL, series, and scope, valid on the execution date. VERIFIED requires a publication timestamp.
6. `notices[].type=EOL_SOON` exists only for SUPPORTED. `Notice.evidence_id` references an existing LifecycleEvidence `id`.
7. Output every field of each `evidence[]` item. Required nullable properties must be present with a null value rather than omitted.
8. `ci_gate.passed=false` requires nonempty `violation_codes`. Report-first permits `ci_gate.incomplete=true` with `passed=true` for component/provider incompleteness. Zero components always require `passed=false`, `incomplete=true`, and NO_COMPONENTS. Cancellation returns no completed report.
9. `ci_failure_count` counts component failures after exceptions are applied. Report aggregate condition failures in `violation_codes`.
10. JSON always retains evidence and unknown results. `output.include_unknown/include_evidence` affect table display only.
11. Stable-sort `results[]` by PURL, with null last, then `source_ref`. Deduplicate elements within arrays by stable keys. Retain separate results for different source SBOM components, even when their PURLs are identical.
12. `selected_evidence_ids` and `Notice.evidence_id` must exist in output evidence. Selected IDs must pass expiry, tier, and conflict checks. UNKNOWN requires an empty selected ID array.
13. UNKNOWN for a CI-required signal requires `result.incomplete=true`. PRESENT requires corresponding evidence of the same type in `signals[]`.
14. Report `generated_at` equals `run_started_at`. Use that time for expiry checks and publication validation against execution time. Write completion time to logs if needed.
15. `policy_hash` includes the selected catalog contents, including embedded data. A local catalog replaces the embedded snapshot rather than merging it silently.

### 10.3 Required evidence JSON fields

**LifecycleEvidence:** `id`, `provider_id`, `source_class`, `claim`, `package_purl`, `product_slug`, `matched_cycle`, `support_scope`, `support_start_date`, `eol_effective_date`, `source_url`, `source_field`, `source_label`, `observed_at`, `source_updated_at`, `reviewed_at`, `valid_until`, `raw_payload_hash`, `confidence`, `rule_id`, `general_eol_review`, `superseded_by`, `supersession_source_url`.

**SignalEvidence:** `type`, `provider_id`, `source_url`, `observed_at`, `details`.

**SignalEvaluation:** `type`, `status`, `provider_id`, `source_url`, `checked_at`, `reason_code`.

**Notice:** `type`, `days_remaining`, `evidence_id`, `rule_id`.

**VersionVerification:** `status`, `provider_id`, `source_url`, `checked_at`, `published_at`, `reason_code`.

**VersionAssertion:** `package_purl`, `published_at`, `source_url`, `reviewed_at`, `valid_until`.

**GeneralEolReview:** `id`, `product_slug`, `package_purl`, `matched_cycle`, `support_scope`, `evidence_url`, `reviewed_at`, `valid_until`.

**Diagnostic:** `code`, `provider_id`, `http_status`, `retryable`, `message`.

`report.example.json` is a valid example based on fictional fixtures. It must not omit evidence properties.

## 11. HTTP, memoization, and persistent caching

### 11.1 HTTP

- Default allowed hosts are `endoflife.date`, `api.deps.dev`, `registry.npmjs.org`, `pypi.org`, and `rubygems.org`. Changing a configured `base_url` still requires TLS and explicit registration in `network.allowed_hosts`; do not silently fall back to HTTP.
- Use an 8-second request timeout and at most two retries for 429s, 5xx responses, and transient network failures. Honor `Retry-After` seconds and HTTP dates and use exponential backoff with jitter. Scheduling uses a live clock separately from the fixed evidence timestamp. Do not retry 404s.
- Pace request starts at 2 requests/second per hostname with burst 1 by default. Acquire a token after an HTTP concurrency slot; retries and allowed redirects also consume tokens. `host_limits` overrides require both rate and burst for an allowed host.
- Share 429/503 cooldowns across URLs on the same host. If a token wait or cooldown exceeds the per-wait `max_wait_seconds` budget (default 30), return an unavailable lookup rather than sending an early retry. Retain RATE_LIMITED or RATE_LIMIT_WAIT_TIMEOUT diagnostics. Another host has an independent budget; already in-flight requests can finish. Budgets are process-local.
- Enforce maximum concurrency 6 across all providers. Deduplicate in-flight requests by URL and JSON media type, and parsed native snapshots by package identity.
- An endoflife.date HTTP 304 may be combined with existing content only when disk caching is enabled. Without cached content, diagnose the 304 as an error.
- A response schema mismatch produces `PROVIDER_SCHEMA_MISMATCH`, not a successful result.

### 11.2 Caching

| Cache type | MVP default | Contract |
| --- | --- | --- |
| In-memory request memoization | **Required; always enabled** | Do not repeat the same PURL or product slug query within a scan. Discard on process exit. |
| File-based persistent cache | **Optional; disabled by default** | Use only when `cache.enabled=true`. No database is required. |

Hash persistent cache keys from the allowed host, API path, JSON representation, and cache format version. Store entries in the OS cache directory with safe permissions. Successful 200 responses have a 24-hour TTL; index 404 responses have a 6-hour TTL. Do not persist 429s, timeouts, or 5xx responses. PyPI vendor JSON and ordinary JSON must not share a cached representation.

`--offline` prohibits all network access. Verify versions and evaluate EOL using only catalogs and usable disk cache entries. **With default caching disabled and no local version assertions, many offline results may be UNKNOWN.**

Refresh expired disk entries online. Offline, entries beyond their TTL but within the maximum evidence age may be used with a CACHE_STALE diagnostic. Entries older than the maximum age are unusable and produce STALE_EVIDENCE. Calculate age from observation time to `run_started_at`, never from `as_of`. Catalog entries follow their individual `valid_until` dates; dynamic external API evidence also follows `decision.max_evidence_age_days`.

## 12. Security, audit, and observability

- Default SBOM limits are 50 MiB, 100,000 components, and a configured maximum JSON depth. Exceeding a limit exits 2.
- Allow GET requests only to URLs built by providers on fixed allowed hosts. Catalog `evidence_url` values are for output and are not fetched automatically.
- State in README and `--help` that requests may send package identities such as PURLs to external APIs. `--offline` must perform zero HTTP requests.
- Exclude API keys and Authorization values from output, stderr logs, and evidence URLs. `input_sha256` is SHA-256 of the original input bytes.
- Metrics: `in_scope, eol, supported, unknown, assessment_coverage, provider_error_count, incomplete_component_count, version_unverified_count, version_not_found_count, cache_hit_count, ci_failure_count`.
- Public application releases record the policy version, schemas, fixed fixtures, and dependency/tool versions.

## 13. Test design: Required acceptance cases

| Test | Fixture | Expected result |
| --- | --- | --- |
| UT-01 | Verified version and official security window, before the end date. | SUPPORTED/HIGH |
| UT-02 | Verified version and official security window, on the end date. | EOL/HIGH |
| UT-03 | Verified version and official security end claim, before the end date. | UNKNOWN; SUPPORTED prohibited |
| UT-04 | Verified version and generic endoflife.date EOL date, before the end date. | UNKNOWN/GENERAL_EOL_ONLY; SUPPORTED prohibited |
| UT-05 | Verified version, valid meaning review, and generic EOL date, on the end date. | EOL/MEDIUM |
| UT-06 | Only `isMaintained=true`. | UNKNOWN; SUPPORTED prohibited |
| UT-07 | `isMaintained=true` after a generic EOL date. | Do not use the boolean to change upstream EOL evaluation |
| UT-08 | Nonexistent `7.2.9999` matches series 7.2. | UNKNOWN/VERSION_NOT_FOUND_IN_INDEX |
| UT-09 | deps.dev version lookup times out. | UNKNOWN/VERSION_UNVERIFIED; incomplete=true |
| UT-10 | Exact match in catalog `verified_versions`. | VERIFIED; no online access required |
| UT-11 | Version publication date is later than a historical as_of. | UNKNOWN/NOT_RELEASED_AS_OF |
| UT-12 | Series boundary between `7.2` and `7.20`. | No incorrect match |
| UT-13 | PURL index followed by details for only two matched products. | Zero `/products/full` requests; only necessary product detail requests |
| UT-14 | PURL absent from the index. | UNKNOWN; no fuzzy name search |
| UT-15 | One index PURL maps to multiple products. | UNKNOWN/AMBIGUOUS_IDENTITY |
| UT-16 | Same-tier EOL dates differ. | UNKNOWN/CONFLICT; configuration cannot change this |
| UT-17 | OFFICIAL and CURATED states differ. | OFFICIAL takes precedence; SOURCE_DISAGREEMENT |
| UT-18 | Official security window with 90 days until EOL. | SUPPORTED and `notices:EOL_SOON`; no EOL_SOON signal |
| UT-19 | Generic EOL is 90 days away, without a security window. | UNKNOWN; no EOL_SOON |
| UT-20 | EOL/MEDIUM under report-first. | Exit 0; EOL remains in the report |
| UT-21 | EOL/MEDIUM under strict policy. | Exit 1 |
| UT-22 | Required API failure under report-first, with no other violation. | incomplete=true; exit 0 |
| UT-23 | Required API failure under strict policy; one of four results is UNKNOWN, without an unknown ratio violation. | incomplete=true; exit 3 |
| UT-24 | API failure and another EOL component under strict policy. | Exit 1; incomplete=true |
| UT-25 | Old `unknown_on_same_tier_conflict` configuration key. | Exit 2 for unknown key |
| UT-26 | Missing required notice or evidence field. | JSON schema validation error |
| UT-27 | Disk cache disabled. | No disk writes; memoization still works |
| UT-28 | Offline, cache disabled, and no catalog version assertion. | Zero HTTP requests; UNKNOWN |
| UT-29 | EOL/HIGH with a valid expiring exception. | Retain EOL; suppress only CI failure |
| UT-30 | Same PURL appears three times in the SBOM. | One provider query; three results |
| UT-31 | EOL projection for future `as_of`. | projection=true; no inference of future version existence |
| UT-32 | Bundled default/strict policies, catalog, and report. | All validate against their schemas |
| UT-33 | Same-tier official end dates of October 1 and December 1, with as_of October 11. | UNKNOWN/CONFLICT; retain future evidence |
| UT-34 | Higher-tier official end date is future; lower-tier reviewed generic EOL date is past. | UNKNOWN; no fallback to lower-tier EOL |
| UT-35 | Generic EOL has passed, with zero reviews. | UNKNOWN/GENERAL_EOL_UNREVIEWED; retain original evidence |
| UT-36 | Review series or scope mismatch, or expired review. | Do not select generic EOL evidence |
| UT-37 | Older evidence with verified formal withdrawal. | Retain original evidence; exclude only from comparison |
| UT-38 | CI-required STALE_RELEASE has an API failure, missing dates, or no retrieval capability. | UNKNOWN evaluation; incomplete=true |
| UT-39 | Equivalent fallback data confirms absence of a CI-required signal. | ABSENT; incomplete=false for that lookup |
| UT-40 | Optional signal fails; lifecycle is definitive and CI does not require the signal. | Retain diagnostics; incomplete=false for that lookup |
| UT-41 | Local VersionAssertion lacks a publication timestamp. | Catalog schema error; exit 2 |
| UT-42 | deps.dev lacks publication time, without fallback, for the current as_of date. | UNVERIFIED; UNKNOWN; incomplete=true |
| UT-43 | Historical as_of, but local version assertion expired by execution time. | Not VERIFIED; a past date cannot restore the assertion |
| UT-44 | Same UTC publication day, with a timezone-bearing timestamp. | Compare UTC calendar dates; same-day publication is eligible |
| UT-45 | CI-required signal is UNKNOWN with fail_on_incomplete_scan=false. | Report incompleteness; exit 0 without other violations |

Use fixed response fixtures for tests involving external APIs. Live API access must not be required on every CI run. Check OpenAPI compatibility in a separate integration job.

Release 0.2.0 additionally verifies package sharing across versions, native selection and equivalent fallback, PyPI artifact/project markers, RubyGems platform scope, signal conflicts, offline native cache reuse, host rate/burst/cooldown behavior, Retry-After overflow/date handling, cancellation, and the three native adapters through the actual CLI and a local HTTPS server.

## 14. Implementation phases and definition of done

**Phase 1 — Types and evaluator:** Input parser, PURLs, VersionVerification, separate lifecycle evidence/signals/notices, evaluator, schemas, and UT-01–12. Use fixtures throughout.

**Phase 2 — Providers:** Catalog, deps.dev GetVersion, endoflife.date PURL index and product details, key-based memoization, API failures, and UT-13–19.

**Phase 3 — CI and quality:** Default/strict policies, exit codes, exceptions, offline execution, optional disk cache, JSON output, schema validation, and UT-20–45.

**Release 0.2.0 — Native metadata and request budgets:** npm, PyPI, RubyGems, publication/signal fallback, per-host pacing and cooldowns, YANKED/report 2.1, and the additional tests above.

**Release 0.3.0 — Scan correctness and bundled evidence:** nested metadata components, mandatory NO_COMPONENTS failure, cancellation and bounded shutdown, recent-release negative proof with incomplete older history, legacy PyPI eggs, informative unavailable-signal reasons, five real reviewed support windows, catalog override, and report 2.2.

**Release 0.4.0 — Automatic lifecycle data:** remove fixed product dates, enable explicit security-phase scope from current API metadata, emit CURATED_SECURITY_END/MEDIUM and source_label in report 2.3, retain unknown future end-only claims, test response changes and cache expiry, and provide the automatic-EOL CI policy.

Definition of done:

- All 45 acceptance cases pass.
- Every SUPPORTED result has security window evidence.
- Every definitive lifecycle decision has a VERIFIED version.
- Reports conform to the bundled schemas.
- Incomplete scans carry diagnostics.
- Network restrictions, SSRF prevention, and secret redaction have been checked.
- README explicitly explains default report-first behavior.

## 15. Exceptions and deferred work

### 15.1 Exception files

Follow `eol-exceptions.example.yaml`. Require an exact `package_purl`, `reason`, `owner`, and `expires_on`. Ignore expired exceptions and record `EXPIRED_EXCEPTION`. Exceptions do not change lifecycle or the unknown ratio.

### 15.2 Deliberately deferred work

- Maintaining meaning reviews for products whose API labels do not explicitly establish security scope. Automatic security labels need no per-product date catalog; ambiguous labels remain UNKNOWN without a review.
- Binary distribution and organization-specific rate tuning. Process-local request budgets are implemented; cross-job coordination is deferred. The implementation uses Go 1.24 or later.
- Adapter changes when actual endoflife.date responses differ from OpenAPI descriptions. Schema mismatches remain failures.
- Private registries and distribution backports.

Deferred work does not relax lifecycle invariants.

## 16. References: Checked 2026-10-12

1. endoflife.date v1 OpenAPI: <https://github.com/endoflife-date/endoflife.date/blob/master/api_v1/openapi.yml>
2. endoflife.date API v1: <https://endoflife.date/docs/api/v1/>
3. deps.dev GetVersion: <https://docs.deps.dev/api/v3/>
4. PURL specification: <https://github.com/package-url/purl-spec>
5. CycloneDX JSON: <https://cyclonedx.org/docs/1.7/json/>
6. SPDX 2.3: <https://spdx.github.io/spdx-spec/v2.3.1-dev/>
7. Native registry API and rate references: [Registry sources](registries.md#primary-references).

## 17. Bundled artifacts and contract validation

- Configuration: `../schemas/policy-input.schema.json` for partial input; `../schemas/policy.schema.json` for the effective policy.
- Catalog: `../schemas/support-catalog.schema.json`, including version assertions and generic EOL reviews.
- Exceptions: `../schemas/exceptions.schema.json`.
- Common types and reports: `../schemas/common.schema.json` and `../schemas/report.schema.json`.
- Policy, catalog, exception, and report examples: `../examples/`.
- `../scripts/validate_design.py` validates schemas and examples at a fixed execution time. Go acceptance and CLI fixture tests separately verify runtime compliance.

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

**Implementation constraints:** Deriving EOL from unreviewed generic EOL, discarding future end dates before conflict detection, marking a version VERIFIED without publication time, or converting UNKNOWN CI-required signals to ABSENT violates this specification. EOL_SOON is a notice; only an official security window can establish SUPPORTED.
