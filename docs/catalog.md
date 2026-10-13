# Automatic lifecycle data and optional catalogs

eolscan 0.4.0 retrieves lifecycle dates during normal online scans. It does not embed product support dates. No database, separately maintained date file, or binary rebuild is needed to use new API products and release series that match the supported identities.

## Retrieval and identity matching

1. Read exact package identities and versions from the SBOM.
2. Fetch the [endoflife.date PURL index](https://endoflife.date/api/v1/identifiers/purl/) once per run.
3. Fetch product details only for exact, unambiguous PURL matches. Reconstruct request URLs from the configured base and validated product slug.
4. Re-check the product identity and PURL in its response. Match the most specific numeric release series for stable versions.
5. Verify the exact package version and its publication time independently through a registry, deps.dev, or a reviewed local assertion.
6. Use eligible support evidence to derive lifecycle and the configured CI result.

Coverage follows the API's PURL index, available release dates and scope metadata, and the seven registry ecosystems that eolscan can verify. Unmapped packages and unsupported runtimes/OS PURLs remain UNKNOWN. Additional framework modules are included only when the API provides their exact PURLs; namespaces and similar names do not create mappings.

## Security scope and confidence

The [API v1 contract](https://endoflife.date/docs/api/v1/) defines `labels.eol` as the phase preceding the end of life. The [Django response](https://endoflife.date/api/v1/products/django/) illustrates `labels.eol`, `releases[].eolFrom`, and separate active-support fields.

The automatic scope rule accepts exactly `Security Support` and `Maintenance & Security Support`. The corresponding dated `eolFrom` is recorded as `CURATED_SECURITY_END`, with `source_class=CURATED_DATABASE`, `confidence=MEDIUM`, and the original label in `source_label`. Linked official pages are references; merely linking one does not make an API claim official/HIGH.

| Evidence | Lifecycle result |
| --- | --- |
| Explicit security phase and an elapsed dated cutoff | EOL / MEDIUM, after version verification |
| Explicit security phase and a future cutoff | UNKNOWN / SECURITY_END_ONLY; retain the scheduled cutoff as evidence |
| Unknown/generic label and no applicable meaning review | UNKNOWN / GENERAL_EOL_UNREVIEWED |
| Missing date or unmatched release series | UNKNOWN |
| Reviewed official support window | SUPPORTED / HIGH or EOL / HIGH, according to its dates |

Commercial/extended-support dates and `isMaintained` do not replace upstream security end dates. Registry deprecation, yanking, and inactivity remain separate signals. An API error is a diagnostic and can make the scan incomplete; it is never evidence that a package is supported.

To require the earlier manual meaning-review path for all endoflife.date dates, disable the automatic label rule:

```yaml
schema_version: 2
sources:
  endoflife_date:
    use_security_support_label: false
```

## Freshness and updating

Disk caching is disabled by default, so a new online scan retrieves current API responses. Per-run memoization shares repeated requests. API changes to product mappings or dates take effect on the next scan without modifying eolscan.

With `cache.enabled: true`, responses are reused for the configured TTL (positive responses default to 24 hours). Online scans refresh expired entries and use ETags where available. `--no-cache` bypasses persistent storage. Rate limits, retries, and shared cooldowns apply to refresh requests as well as initial retrieval.

Offline scans make no HTTP requests. They can use cached responses within the configured evidence-age limit, marking expired TTL entries as stale. Responses older than that limit cannot establish EOL. Local reviewed assertions and support windows can also supply offline evidence. A historical `--as-of` does not restore expired local reviews or cache evidence.

A scheduled CI scan can refresh data periodically; eolscan itself does not run a background daemon. Remote response hashes and observation timestamps identify the evidence used for each result. Strict historical reproduction requires saved response snapshots.

## CI policy

The default remains report-first, failing for EOL/HIGH. To include automatically retrieved EOL/MEDIUM:

```sh
eolscan scan -i sbom.cdx.json -c examples/eol-policy.auto-eol.yaml
```

The policy sets `ci.min_confidence: MEDIUM` without an unknown-ratio gate. Add `ci.fail_on_incomplete_scan: true` to require successful source lookups. The stricter example also applies an unknown-ratio threshold, which should be chosen from observed coverage.

## Optional local catalogs

Use a local catalog for reviewed official windows, private support policies, exact version assertions, or interpretation of otherwise ambiguous generic EOL dates:

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: true
    path: ./support-catalog.yaml
```

Or select it with `eolscan scan -i sbom.cdx.json --catalog ./support-catalog.yaml`. Policy paths resolve relative to the policy file; CLI paths resolve relative to the current directory.

Local official evidence takes precedence over automatically retrieved curated evidence. Conflicts within the highest applicable tier produce UNKNOWN; lower-tier disagreements are reported. Local catalog review and expiry dates are checked at execution time. Examples under `examples/` and `testdata/` use fictional data.

## Migration from 0.3.0

The five fixed Angular/Rails windows and the reserved `builtin:upstream-security` selection have been removed. Disable that old official-catalog selection or set a local path. `--catalog builtin` now returns an explanatory configuration error. Automatic security dates have MEDIUM confidence and do not create official SUPPORTED windows.

Report schema 2.3 adds `source_label`, `CURATED_SECURITY_END`, and the security-specific UNKNOWN reasons. Configuration remains version 2; partial policies inherit `sources.endoflife_date.use_security_support_label: true`.
