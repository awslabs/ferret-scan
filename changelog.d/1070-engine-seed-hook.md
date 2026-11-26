### 🔨 Internal

- `pkg/redact`'s Engine has a test-only seam for seeding the synthetic scope (an unexported field set from `export_test.go`), so synthetic output can be asserted on the Engine path; no flag, environment variable or configuration key reaches it. (#1070)
- `PlainTextRedactor.RedactString` is unchanged: it delegates to the new `RedactStringInScope` with a nil scope and still draws a scope of its own per call.
