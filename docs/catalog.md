# Bundled upstream security catalog

eolscan 0.3.0 embeds a small reviewed catalog and enables it by default. It contains official support evidence for five release series across two products. It does not provide lifecycle coverage for every package in the seven supported registry ecosystems.

The [catalog data](../internal/catalog/upstream-security.yaml) was reviewed on **2026-10-12** and is valid through **2026-11-11**, inclusive, using the execution date in UTC. After expiry, its claims remain visible as evidence but cannot establish `EOL` or `SUPPORTED`. Re-running with a historical `--as-of` does not restore an expired review. Pinning a binary pins the evidence snapshot, not the execution date.

## Scope and primary sources

| Exact package identity | Reviewed series | Support window starts | Security cutoff | Primary evidence |
| --- | --- | --- | --- | --- |
| `pkg:npm/%40angular/core` | 18 | 2024-05-22 | 2025-11-19 | [Angular v19 release schedule](https://v19.angular.dev/reference/releases) |
| `pkg:npm/%40angular/core` | 19 | 2024-11-19 | 2026-05-19 | [Angular v19 release schedule](https://v19.angular.dev/reference/releases) |
| `pkg:npm/%40angular/core` | 20 | 2025-05-28 | 2026-11-28 | [Current Angular release schedule](https://angular.dev/reference/releases) |
| `pkg:gem/rails` | 7.2 | 2024-10-15 | 2026-08-09 | [Rails maintenance announcement](https://rubyonrails.org/2024/10/15/new-maintenance-policy-and-eol-annouments) |
| `pkg:gem/rails` | 8.0 | 2025-10-29 | 2026-11-07 | [Rails support announcement](https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement) |

Angular's published LTS policy includes security patches. The archived schedule supplies the explicit dates for 18 and 19; the current schedule confirms that these series are no longer supported and supplies the date for 20. Other Angular packages are not automatically included by namespace.

Rails entries use the date of the cited support announcement as the start of the confirmed window. They do not assert support before that statement. The 2025 announcement confirms the 7.2 cutoff and the 8.0 security deadline; the [current maintenance page](https://rubyonrails.org/maintenance) lists 8.0 under security support. Individual Rails component gems are not automatically mapped to the `rails` metapackage.

These are UTC calendar-date checks, using the published cutoff date: `as_of < eol_effective_date` is inside an otherwise applicable window; `as_of >= eol_effective_date` is EOL. The catalog does not claim a particular intraday cutoff time or timezone. `SUPPORTED` describes the upstream release-series policy, not an assurance that every patch version is free of vulnerabilities or eligible for every backport.

## What is deliberately absent

- Angular 21 and 22 have month-only future end dates in the current table. No day is invented for them.
- Rails 6.1 has a transition involving additional security releases. Rails 7.0 and 7.1 have differing earlier schedules and later end-of-support announcements. They require reconciliation before a precise historical cutoff is added.
- OS packages, generic Node.js/Ruby runtimes, OCI images, third-party Angular libraries, other Rails component gems, prereleases, and commercial support are outside this catalog's scope.
- `verified_versions` and `general_eol_reviews` are empty. Exact version existence and publication time must still be verified independently. General endoflife.date information is not automatically promoted to security support evidence.

## Configure, replace, or disable

No extra file is needed for the default catalog. A full policy that disabled the official catalog can enable it explicitly:

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: true
    path: "builtin:upstream-security"
```

The reserved path above selects the embedded data. A normal path selects a local catalog and **replaces** the bundled catalog; it does not silently merge claims or suppress conflicts. Policy paths are resolved relative to the policy file. The CLI override is resolved relative to the current directory:

```sh
eolscan scan -i sbom.cdx.json --catalog builtin
eolscan scan -i sbom.cdx.json --catalog ./support-catalog.yaml
```

To disable the bundled evidence:

```yaml
schema_version: 2
sources:
  official_catalog:
    enabled: false
```

## Maintaining the data

Before extending a review, re-check the official policy and release announcements for the exact product, series, and upstream security scope. Verify precise dates and changes to the schedule. Preserve conflicting applicable claims unless an official replacement or withdrawal is confirmed. Add exact package mappings only when their applicability is established.

Record the review date, expiry, source URL, and support authority, then run policy/schema validation and the catalog integration tests. Updating embedded data requires rebuilding the binary; a reviewed local catalog can be updated independently. Expired data is not automatically refreshed or granted a new review date by a scan.

The catalog is part of `policy_hash`, so changing the reviewed data changes the report's policy hash. The files under `examples/` and `testdata/` that use fictional packages remain test fixtures.
