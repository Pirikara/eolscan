# Configurable EOL criteria

eolscan applies your EOL criteria to every dependency in the SBOM. A matching maintenance rule produces `EOL`, a warning, and a result that the CI gate can reject. These rules do not require a product support-date catalog.

## Defaults

The default criteria are an applicable release-series EOL date that has passed, explicit publisher retirement, version deprecation for npm/PyPI/NuGet, project/source-repository archival, and eligible formal support dates. General support end is sufficient for the default warning; security-support termination is not a prerequisite. Maintenance-rule matches have `MEDIUM` confidence; official support dates retain `HIGH`, and curated dates retain `MEDIUM`.

Release inactivity is collected by default and becomes an EOL criterion only when a rule includes it. Repository inactivity is opt-in and uses a separate threshold. Warnings are always emitted for EOL results. The default CI threshold remains `HIGH`; set `ci.min_confidence: MEDIUM` to reject maintenance-rule EOL too.

## Define your criteria

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

This classifies a version as EOL when it is deprecated in npm/PyPI/NuGet, when its project is archived **and** its releases have been inactive for more than 365 days, or when an eligible support end date has passed. The deprecation rule is scoped to ecosystems where both positive and negative deprecation checks are available; the archival/inactivity rule applies across ecosystems. Broaden the scopes when you have the necessary acquisition capability.

```sh
./bin/eolscan policy validate -c examples/eol-policy.rules.example.yaml
./bin/eolscan scan -i sbom.cdx.json -c examples/eol-policy.rules.example.yaml
```

Rules are combined with **OR**. Within each rule, choose exactly one nonempty `any_of` (**OR**) or `all_of` (**AND**) list. Signal names and rule IDs must be unique within their respective lists. Supplying `eol_rules` replaces the entire default rule list.

Use `eol_rules: []` for support dates only; see the [dates-only policy](../examples/eol-policy.dates-only.yaml). Set `use_support_dates: false` to classify EOL exclusively through maintenance rules. Disable `sources.endoflife_date` separately if support information is not needed in the report.

`signals.stale_release_days` is the shared inactivity threshold and must be non-null when a rule uses `STALE_RELEASE`. A gap equal to the threshold does not match. Native sources require complete available release history to prove inactivity and do not let a new artifact reset an old version's release date.

## Scope a rule

```yaml
schema_version: 2
decision:
  eol_rules:
    - id: archived-gems
      any_of: [ARCHIVED]
      ecosystems: [gem]
    - id: selected-retired-versions
      any_of: [DEPRECATED, YANKED]
      packages:
        - pkg:npm/transitive-leaf
        - pkg:pypi/example@1.2.3
```

`ecosystems` restricts PURL types. `packages` accepts exact public package PURLs: unversioned entries match all versions, and versioned entries match only that exact identity. Both restrictions must match when both are present. Fuzzy names and string prefixes are not used. Inputs for an inapplicable rule are not queried solely for that rule.

## Conditions and data sources

| Condition | Acquisition |
| --- | --- |
| `DEPRECATED` | npm version metadata, PyPI project markers, and positive deps.dev deprecation. Explicit deps.dev negatives are usable for npm/NuGet. |
| `ARCHIVED` | PyPI project markers or GitHub's explicit `archived` boolean for a mapped source repository. |
| `YANKED` | Native PyPI artifacts and explicit RubyGems metadata, subject to version/artifact limitations. |
| `QUARANTINED` | PyPI project markers. |
| `STALE_RELEASE` | Native npm/PyPI/RubyGems release histories and capable deps.dev fallback. |
| `RELEASE_SERIES_EOL` | Exact endoflife.date PURL mapping and matching release series; elapsed `eolFrom` regardless of general/security phase, or explicit current undated `isEol`. |
| `DECLARED_UNMAINTAINED` | Exact npm/PyPI/RubyGems publisher descriptions; PyPI's `Development Status :: 7 - Inactive`; a mapped GitHub repository's current README. |
| `STALE_REPOSITORY` | GitHub repository `pushed_at`, compared with `signals.stale_repository_days`. `updated_at` is not code activity. |
| `RETRACTED` | Recognized without an acquisition adapter. A rule requiring it remains UNKNOWN and makes the scan incomplete. |

An EOL rule automatically requests its inputs, even when optional signal collection is disabled. Unavailable methods and failed lookups never mean that the condition is absent.

GitHub discovery uses the exact version's npm `repository`, RubyGems `source_code_uri`, or explicitly labelled source URLs in PyPI version metadata. deps.dev `SOURCE_REPO` relationships provide mappings for all seven supported registry ecosystems. Issue trackers and homepages are not guessed to be source repositories. Verified origin/attestation mappings take precedence; conflicting mappings at the same trust level remain unresolved. Positive archival evidence retains mapping provenance and its original metadata URL.

Metadata URLs are parsed into identities and queried through the configured GitHub API. Arbitrary SBOM or metadata URLs are not fetched. Same-host renames and transfers are supported, including stable numeric repository-ID redirects. The response identity and explicit archival flag must be verified. A 404 does not mean unarchived. GitLab, Bitbucket, missing links, and ambiguous mappings cannot currently resolve a GitHub archival check.

## Publisher retirement declarations

Default English patterns recognize explicit statements about this project/package/library or the exact package name, strong retirement headings, and explicit distribution-replacement notices. The PyPI Inactive classifier is an independent structured declaration. Ordinary API/dependency deprecations, unsupported platforms, negated statements, code examples, and a different predecessor's retirement are excluded by the default patterns. This is bounded pattern matching, not a general natural-language interpreter.

Only the mapped source repository's README is read; issue comments, arbitrary websites, and `download_url` links are not fetched. The README is current repository content, not necessarily the file shipped with the exact package version. Descriptions and READMEs are limited to 256 KiB. Unavailable/malformed content remains UNKNOWN; successfully examined content without a configured match is ABSENT for this detector, not proof of ongoing maintenance.

Override the entire pattern list with Go RE2 expressions. `{package}` is replaced with the escaped exact normalized package name. The expressions run after bounded Markdown/RST prose normalization (including line reflow and common notice prefixes):

```yaml
schema_version: 2
signals:
  unmaintained_patterns:
    - '(?im)^{package} maintenance ended[.!]?$'
```

An explicit empty list disables text matching but preserves the structured PyPI Inactive classifier. To disable the whole criterion, remove `DECLARED_UNMAINTAINED` from the EOL rules and standalone CI signals. Source field, expression/index or classifier, a short matching excerpt, observation time, and response hash remain in evidence.

## Repository inactivity

```yaml
schema_version: 2
signals:
  stale_repository_days: 730
decision:
  eol_rules:
    - id: explicitly-retired-and-inactive
      all_of: [DECLARED_UNMAINTAINED, STALE_REPOSITORY]
ci:
  min_confidence: MEDIUM
```

This replaces the default rule list. A push gap equal to the threshold is ABSENT; a greater gap is PRESENT. Missing/invalid/future `pushed_at` is UNKNOWN. Shared repository activity is project-wide and cannot establish that an old release branch is still supported. Repository and release inactivity can be combined or scoped independently.

## Unknown conditions

| Expression | Result |
| --- | --- |
| OR: one PRESENT, another UNKNOWN | PRESENT |
| OR: no PRESENT, at least one UNKNOWN | UNKNOWN |
| AND: one ABSENT, another UNKNOWN | ABSENT |
| AND: no ABSENT, at least one UNKNOWN | UNKNOWN |
| AND: every condition PRESENT | PRESENT |

A matching rule or an enabled confirmed support end date establishes EOL even if another rule is unresolved. Otherwise an unresolved applicable rule marks the component incomplete. CI-required standalone signals retain their own completeness requirement. `fail_on_incomplete_scan` changes the CI gate, never the truth value of a condition.

Every EOL result requires verified existence and publication time for the exact SBOM version. Current deprecation, yanking, quarantine, and archival flags cannot establish their status on another historical or future `--as-of` date; those rule inputs become UNKNOWN. Dated release comparisons and release-series end dates use their own as-of comparisons. An undated series status cannot establish a historical/future state. Historical flag replay requires snapshots beyond the current adapter contract.

## Interpret results

- `EOL`: an enabled support-date criterion or configured maintenance rule matched.
- `NO_EOL_DETECTED`: required EOL policy checks resolved without a matching criterion. This does not certify upstream support or safety.
- `SUPPORTED`: an official security window includes the evaluation date and no applicable maintenance rule matched or remains unresolved.
- `UNKNOWN`: a required identity, version, condition, or support-date evaluation could not be resolved. Dates-only mode also retains UNKNOWN when support evidence is insufficient.

`support_assessment` retains the formal security-support conclusion separately. A maintenance-rule EOL can coexist with an unknown or supported formal assessment without inventing an official end date.

`eol_basis` identifies `SUPPORT_DATE` or `POLICY_RULE`. `eol_rule_evaluations` records each applicable rule, its status, matched signals, unknown inputs, and an unresolved reason. Policy-rule EOL has a null `eol_effective_date` and `matched_cycle`; the matched rule and signal evidence supply its proof.

`assessment_coverage` counts EOL, SUPPORTED, and NO_EOL_DETECTED results. It measures evaluation of the selected policy, not worldwide support-data coverage.

## GitHub quotas and CI

For larger scans, supply an explicit token using `EOLSCAN_GITHUB_TOKEN`, or select another CI secret variable through `sources.github.token_env`.

```yaml
# Inside a GitHub Actions step:
env:
  EOLSCAN_GITHUB_TOKEN: ${{ github.token }}
```

The token is sent only to the configured public GitHub API's repository requests and same-host redirects. It is excluded from policies, reports, hashes, and cache records, and is not sent to custom API mirrors.

GitHub documents 60 requests/hour for unauthenticated requests and generally 5,000/hour for authenticated requests, with other token/installation limits. See [GitHub rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).

Repository metadata requests share transport memoization and optional TTL caching. Declaration detection can add one README request per mapped repository; native descriptions are shared with exact-version discovery. When a verified current version already matches another independent EOL rule, declaration collection can be skipped as UNKNOWN/NOT_NEEDED_FOR_EOL. A CI-required standalone declaration is always evaluated, and a confirmed native declaration avoids an unnecessary README request. Restore the cache in CI when appropriate. GitHub rate-limit 403s, 429s, reset times, and shared cooldowns are handled without early retries. An unavailable required condition remains UNKNOWN and incomplete.
