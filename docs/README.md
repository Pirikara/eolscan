# eolscan implementation contract

The [v0.5 design specification](design.md) incorporates the accepted lifecycle decisions, native registries, request pacing, and the scan-correctness revisions. Go CLI 0.3.0 implements this specification.

The configuration contract is version `2`, and the report contract is version `2.2`. These versions are independent of the document version. Report 2.2 adds `NO_COMPONENTS`; empty scans always fail. Partial version 2 policies inherit the enabled built-in official catalog.

- [Architecture](architecture.md): Package responsibilities, dependency direction, embedded assets, and testing.
- [Registry sources](registries.md): Native APIs, metadata priority, signal semantics, host pacing, and CI cache behavior.
- [Bundled catalog](catalog.md): Reviewed products and release series, official sources, expiry, boundary semantics, and maintenance.
- [Schemas](../schemas/): Partial policy input, effective policy, support catalog, exceptions, common types, and reports.
- [Examples](../examples/): Complete policies, local version assertions, generic EOL reviews, and complete reports.
- [Fixture manifest](../testdata/fixtures/manifest.json): Conflicts, unreviewed evidence, unknown CI-required signals, evaluations before publication, and other fixed cases.

The embedded official catalog contains reviewed real Angular and Rails support data. General EOL reviews and version assertions remain empty. Catalogs and reports under `examples/` and `testdata/` use fictional packages for acceptance tests; those fixtures are separate from the real embedded catalog.

The design validator uses Python with jsonschema and PyYAML. These are development dependencies; they are not required to run the Go CLI.

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

Schema references resolve through locally registered URNs. Validation makes no external API requests. In addition to schema structure, it checks publication dates, expiry dates, selected evidence, signal evaluations, and CI totals. The script validates design artifacts. Go acceptance tests and eleven CLI fixture tests verify runtime compliance with `go test -race ./...`.

Fixed `policy_hash` examples combine the effective policy with referenced catalog and exception content. The data is serialized as UTF-8 JSON with sorted keys and no extra whitespace, then hashed with SHA-256. Relative paths retain their literal values in the hash; file resolution uses the policy file's directory. Secret values are excluded.
