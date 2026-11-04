### ⚠️ Breaking Changes

- **cli (redaction):** a redaction audit log that cannot be written or validated now fails the run:
  `Error: Failed to export redaction audit log: …` and exit `1`, as for an `--output` that cannot be
  written, from `--redaction-audit-log` and from the `redaction.audit_log_file` / `index_file` config
  keys alike ([#865](https://github.com/awslabs/ferret-scan/issues/865)). It was a `Warning:` at exit
  `0`, so a run asked for the compliance record could finish green without one. Measured with
  `--redaction-audit-log /dev/null/audit.json`: exit `0` before, plain and with
  `--fail-on-incomplete`; exit `1` now in both and in pre-commit mode. The redacted copies already
  written are left in place, and the run stops before the findings report. A log path whose
  directory does not exist is such a failure: create the directory first.
