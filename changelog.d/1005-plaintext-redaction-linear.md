### ⚡ Performance

- **redaction (plain text):** redacting a text file no longer rebuilds the whole document and
  re-copies it into the position correlator once per finding, so the plain-text redactor's own
  work now grows with the number of values instead of with values times file size
  ([#1005](https://github.com/awslabs/ferret-scan/issues/1005)). The redacted copies and the audit
  log are byte-identical to the previous release's. The completeness sweep that runs after the
  positional pass is unchanged and is still quadratic in the number of distinct values; it now
  accounts for most of the remaining time on files with more than about 8,000 findings.
