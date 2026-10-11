# Registry sources and request behavior

eolscan 0.2.0 queries npm, PyPI, and RubyGems directly. Remote version verification for Maven, Go, Cargo, and NuGet still uses deps.dev. None of these registry facts alone establishes an upstream security support window or an EOL date.

## Selection and fallback

1. Prefer an active exact local `verified_versions` assertion, including its publication time.
2. Use the native registry when enabled and selected in `version_verification.sources` as `registries`.
3. Use deps.dev when enabled and selected as `deps_dev`, if the version/publication proof remains unresolved.

The sources array selects available verification methods; the precedence above is fixed. Signals are selected independently through `signals` and `ci.fail_on_signals`. A valid local version assertion can therefore avoid all metadata requests when no signals are requested, but it does not certify maintenance status.

Native metadata is requested only if the target ecosystem supports it and a version or requested signal needs it. Each package response is fetched and parsed once per run and shared across its SBOM versions. A complete native result avoids the corresponding deps.dev query. Unresolved deprecation or release inactivity can use equivalent deps.dev data where that provider has a capability. Yanking and PyPI project markers have no deps.dev fallback.

Native failures remain diagnostics if a fallback succeeds. Successful equivalent fallback can complete the check; an unresolved CI-required signal makes the component and scan incomplete. API failures never mean `ABSENT`. If fallback data already needed for another check contradicts native signal evidence, that signal becomes `UNKNOWN / SIGNAL_CONFLICT` and both pieces of evidence remain visible.

A publication later than `--as-of` is `NOT_RELEASED_AS_OF`; fallback cannot replace that conclusive native result. Publication later than execution time is invalid proof. A 404 or missing exact version means absence from that index, without proving global nonexistence. Missing publication time cannot establish `VERIFIED`.

## Native capabilities

| Source | Endpoints | Version/publication | Maintenance signals |
| --- | --- | --- | --- |
| npm | `GET /{encoded-package-name}` with full JSON metadata | `versions` and per-version `time` | `DEPRECATED`, `STALE_RELEASE` |
| PyPI | `GET /simple/{normalized-name}/`, accepting `application/vnd.pypi.simple.v1+json` | Wheel/sdist identifiers and `upload-time` | `DEPRECATED`, `ARCHIVED`, `QUARANTINED`, `YANKED`, `STALE_RELEASE` |
| RubyGems | `GET /api/v1/versions/{name}.json`; version details from `/api/v2/rubygems/{name}/versions/{version}.json` when needed | `number` plus `created_at`; details use `version_created_at` | `STALE_RELEASE`; `YANKED` where explicit status is available |

All requests use configured HTTPS base URLs on allowed hosts. Download URLs from registry metadata are never fetched. Native Go retract and NuGet deprecation adapters are deferred.

### npm

Full packument metadata provides exact version records and publication timestamps. Names and versions must match the requested package. Scoped names are URL encoded. A nonempty version-level deprecation message is positive evidence. Under the full metadata contract, a valid version record with an omitted, null, or empty deprecation message is negative evidence. A missing version record or invalid response stays unknown.

The `time` map can retain removed version identifiers. If a timestamp refers to a version missing from `versions`, release-list completeness is unknown and native `STALE_RELEASE` cannot be resolved from that snapshot.

### PyPI

The adapter uses the JSON Index API. The older project JSON API's `releases` key is deprecated and is not used. Package names are normalized for case and runs of `-`, `_`, and `.`. The response must identify the requested package, use API major version 1, and supply a file list.

Explicit project status maps as follows:

| Status | DEPRECATED | ARCHIVED | QUARANTINED |
| --- | --- | --- | --- |
| `active` | ABSENT | ABSENT | ABSENT |
| `deprecated` | PRESENT | ABSENT | ABSENT |
| `archived` | ABSENT | PRESENT | ABSENT |
| `quarantined` | ABSENT | ABSENT | PRESENT |
| Missing or unrecognized | UNKNOWN | UNKNOWN | UNKNOWN |

Although the project-status specification defines a default for omitted status, eolscan conservatively requires an explicit known marker for negative evidence. An `active` marker does not certify security support. Quarantine may hide artifacts; the marker can be reported even when publication proof needs fallback.

Yank status is a boolean or a string reason, including an empty string meaning yanked. `YANKED/PRESENT` requires every available artifact for the target version to be explicitly yanked. Any explicit non-yanked artifact makes it `ABSENT`. Missing status or unidentified artifacts that prevent this conclusion leave it `UNKNOWN`. This version-level rule does not describe which artifact a particular installer selected.

The adapter recognizes modern wheels, `.tar.gz`, and `.zip` sdists. Unrecognized filenames make the release list incomplete. The optional `versions` list can retain an identifier, but it cannot supply a missing publication time. Version strings are matched exactly; legacy filenames and PEP 440 aliases may need deps.dev or a local assertion rather than native proof.

### RubyGems

Publication is based on upload/creation time, never `built_at`. Multiple platform artifacts are grouped by version; the earliest publication establishes a version's release date. A PURL with `platform` requires a matching platform in the native list. The unspecified default platform of the v2 endpoint, and deps.dev's platform-independent version response, cannot prove another platform artifact. An exact local assertion can still supply that proof.

Version details are requested when the list cannot verify an unqualified target version, or a requested `YANKED` evaluation lacks explicit status. A missing yank field remains unknown. One platform's positive status cannot certify other platform/ABI artifacts; a known non-yanked artifact is sufficient for ABSENT. Public RubyGems version endpoints currently exclude unindexed/yanked releases, so a 404 cannot recover their publication time or confirm yanking. These cases need independent proof such as a reviewed local assertion; deps.dev may retain version metadata but does not supply a reliable yank signal.

## Release inactivity and historical limits

`STALE_RELEASE` evaluates the currently available release list. Every considered version needs a valid publication timestamp; incomplete lists remain unknown. For a version with multiple artifacts, its earliest artifact upload is its publication. The latest such version publication on or before `--as-of` is compared with `stale_release_days`; a gap strictly greater than the threshold is `PRESENT`.

Uploading another wheel or platform build for an old version does not reset its release date. A future evaluation date remains unknown because subsequent releases cannot be predicted. Deleted releases, removed artifacts, and past deprecation/project-status changes cannot be fully reconstructed from live metadata. `--as-of` compares known dates, without recreating a historical registry snapshot. Strict historical replay needs saved evidence.

deps.dev's documented Go and PyPI collection limits prevent its lists from resolving package-wide inactivity. Native PyPI can resolve it when the available artifact list and timestamps are complete. Other native failures may use a complete deps.dev list.

## Host budgets, retries, and cache

Defaults are 2 requests per second per host, burst 1, concurrency 6, request timeout 8 seconds, and at most two retries. These are eolscan's conservative defaults, not promises about the services' quotas. All attempted request starts, including redirects and retries, consume host tokens.

HTTP 429 and 503 establish a cooldown shared by requests to the same hostname. `Retry-After` seconds and HTTP dates are respected, with exponential backoff and jitter. A long cooldown or token wait exceeding `network.max_wait_seconds` returns an unavailable lookup instead of an early retry. This is a per-wait budget, not an overall scan deadline. Other hosts keep independent budgets; already in-flight requests can finish.

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
signals:
  yanked: true
  archived: true
  quarantined: true
```

Overrides must name an allowed host and supply both rate and burst. Native sources can be individually disabled with `sources.npm.enabled`, `sources.pypi.enabled`, or `sources.rubygems.enabled`; `registries` can also be removed from the verification methods while keeping native signal collection enabled.

In-memory memoization is always enabled. Optional persistent caching stores successful JSON and 404 responses, with media types in cache keys. Failed 429/5xx lookups are not persisted. Offline mode performs zero HTTP requests and can reuse native metadata within evidence-age limits. Default storage is `$HOME/Library/Caches/eolscan/v2` on macOS, or `${XDG_CACHE_HOME:-$HOME/.cache}/eolscan/v2` on Linux; CI runners can restore that directory between jobs.

Budgets and cooldowns are process-local. Concurrent CI jobs sharing an egress IP need their own coordination or lower rates. RubyGems documents service quotas, while deps.dev has no formally specified numerical limit; both can return 429. Set `ci.fail_on_incomplete_scan: true` when required unavailable checks should fail the job. Enable optional signals only where desired, or list them in `ci.fail_on_signals` to make evaluation mandatory.

## Primary references

- [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) and [package metadata](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md).
- [PyPI Index API](https://docs.pypi.org/api/index-api/), [project JSON API](https://docs.pypi.org/api/json/), and [project status markers](https://packaging.python.org/en/latest/specifications/project-status-markers/).
- [RubyGems API guide](https://guides.rubygems.org/rubygems-org-api/), [rate limits](https://guides.rubygems.org/rubygems-org-rate-limits/), and [public version selection in source](https://github.com/rubygems/rubygems.org/blob/master/app/models/rubygem.rb).
- [deps.dev API v3](https://docs.deps.dev/api/v3/) and [maintainer explanation of rate limiting](https://github.com/google/deps.dev/issues/33#issuecomment-1744108819).
