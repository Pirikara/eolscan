# Public package detection cases

These are actual public versions used for [detection validation](../../docs/real-package-validation.md), not a runtime support catalog.

- `manifest.json`: Independently reviewed sources, categories, goals, and three policy profiles. EOL is a desired target outcome; NOT_EOL is a control goal; null records an observation without asserting a default outcome.
- `sbom.cdx.json`: All 47 versions; no injected repository mapping or lifecycle dates. Default and inactivity profiles use the same input.
- `policy.default.yaml`: Built-in default detection criteria with file caching enabled for response reuse.
- `policy.inactivity.yaml`: Default criteria plus a 730-day release-inactivity rule and MEDIUM CI threshold.
- `declarations.cdx.json` and `policy.declarations.yaml`: Seven publisher-retirement targets and two controls; only DECLARED_UNMAINTAINED determines EOL.
- `observations/2026-10-17/`: CLI reports, full effective policies, receipts, and current input snapshots.
- `observations/2026-10-15/`: Original 0.5.0 reports with frozen 39-case inputs and manifest.

Directory dates use Asia/Tokyo; CLI dates use UTC. The live validator exits nonzero for unmet reviewed goals. Preserve actual misses and unmodified raw reports; historical observations must use their own input/manifest snapshots when the corpus grows.
