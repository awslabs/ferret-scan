### 🐛 Bug Fixes

- **pkg/scan (`RedactFile`):** `RedactFileResult` gains `ConfigWarnings`, the configured values under
  `validators:` the redaction could not use, in the form and order `Result.ConfigWarnings` gives
  ([#903](https://github.com/awslabs/ferret-scan/issues/903)). `core.RedactFile` reported them, but
  `scan.RedactFile` dropped them, so a caller whose pattern RE2 rejects got a redacted copy that looked
  complete although the value that pattern was meant to find was never looked for. The field is a
  pointer, nil when every value was usable, so `RedactFileResult` stays comparable. Additive: no
  existing field or signature changes.
