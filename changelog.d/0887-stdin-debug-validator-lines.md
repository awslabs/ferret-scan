### 🐛 Bug Fixes

- **cli (`--stdin --debug`):** `--stdin --debug` and `--file - --debug` now print the validators' own
  debug lines, as `--file --debug` does ([#887](https://github.com/awslabs/ferret-scan/issues/887)).
  `core.ScanContent` and `core.ScanFile` built their validators without an observer, so a
  validator's debug output was never written. Measured on main over a one-line copyright notice:
  `--file --debug` printed 4 `[DEBUG]` lines, `--stdin --debug` 0; now `--stdin --debug` prints the
  intellectual-property validator's 3-line legal-notice summary and its observer detail. The fourth
  `--file` line, `[DEBUG] Parallel processing`, describes the file pipeline, which stdin does not use.
  Without `--debug` nothing changes. A `pkg/scan` caller that sets `Debug` now also gets the
  validators' observer lines, on its `LogWriter`.
