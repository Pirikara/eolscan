# Public package detection cases

These are actual public package versions, reviewed for [real package detection validation](../../docs/real-package-validation.md). They are not a runtime support catalog.

- `manifest.json`: Independent sources, review notes, reference categories, and detection goals. `EOL` is a desired detection outcome; `NOT_EOL` is a control goal; null records an observation without an asserted default outcome.
- `sbom.cdx.json`: All 39 versions, without injected repository or lifecycle evidence.
- `inactivity.cdx.json` and `policy.inactivity.yaml`: Six misses, one inactivity candidate, and three controls, with a 730-day inactivity rule and a MEDIUM CI threshold.
- `observations/2026-10-15/`: Original CLI reports and execution receipts, effective policies, and independent registry/product API observations. Dates in the directory name use Asia/Tokyo; CLI evaluation dates use UTC.

The live validator exits nonzero while reviewed targets remain undetected. Keep actual misses visible when adding observations or changing the implementation. See the linked document for commands and the current limitations.
