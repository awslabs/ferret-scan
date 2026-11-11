### 📚 Documentation

- **pkg/redact (package doc):** the thread-safety section no longer names a cross-validator signal
  processor and a confidence calibrator in `internal/validators/enhanced_integration.go`, a file
  the v2 refactor removed with both. The state a shared `Engine` serializes on is the dual-path
  bridge's metrics, which every `Redact` call updates under the bridge's mutexes; the advice to pool
  one engine per worker under high concurrency stands
  ([#774](https://github.com/awslabs/ferret-scan/issues/774)).
