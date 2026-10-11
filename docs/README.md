# eolscan implementation contract

The [v0.3 design specification](EOL_Checker_Design_v0.3.md) incorporates the v0.2 review and four accepted design decisions. The Go CLI implements this specification. Its CLI, input scope, and output contract differ from the initial prototype.

The configuration contract is version `2`, and the report contract is version `2.0`. These versions describe the initial implementation contract and are independent of the document version.

- [Schemas](../schemas/): Partial policy input, effective policy, support catalog, exceptions, common types, and reports.
- [Examples](../examples/): Complete policies, local version assertions, generic EOL reviews, and complete reports.
- [Fixture manifest](../examples/fixtures/manifest.json): Conflicts, unreviewed evidence, unknown CI-required signals, evaluations before publication, and other fixed cases.

Products, URLs, dates, and reviews in the bundled catalogs and reports are fictional test data. The default policy disables the local catalog and includes no reviews for real products.

The design validator uses Python with jsonschema and PyYAML. These are development dependencies; they are not required to run the Go CLI.

```sh
uv run --with-requirements scripts/design-requirements.txt python scripts/validate_design.py
```

Schema references resolve through locally registered URNs. Validation makes no external API requests. In addition to schema structure, it checks publication dates, expiry dates, selected evidence, signal evaluations, and CI totals. The script validates design artifacts. Go acceptance tests and ten CLI fixture tests verify runtime compliance with `go test -race ./...`.

Fixed `policy_hash` examples combine the effective policy with referenced catalog and exception content. The data is serialized as UTF-8 JSON with sorted keys and no extra whitespace, then hashed with SHA-256. Relative paths retain their literal values in the hash; file resolution uses the policy file's directory. Secret values are excluded.
