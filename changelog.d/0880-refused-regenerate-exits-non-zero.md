### 🐛 Bug Fixes

- **cli (`--generate-suppressions`):** a regenerate that wrote no rule file now exits 1 and says so
  with an `Error:` line, on `--file` and on `--stdin` (gateway included)
  ([#880](https://github.com/awslabs/ferret-scan/issues/880)). Since #893 a rule file that does not
  parse is never rewritten, but the run printed `Warning: Failed to generate suppression rules: …
  could not be parsed …` and exited 0, so a CI job regenerating its baseline read the refusal as
  success. Measured on main with the issue's reproduction: rc 0 on `--file` and `--stdin`, text and
  json, and on the `--stdin --enable-redaction` gateway; now rc 1 on all five, the rule file still
  byte-identical, and the findings report rendered as before. A save that fails for another reason
  exits 1 the same way. A non-zero exit the run already had (pre-commit findings, a tool error,
  `--fail-on-incomplete`) is kept, and a rule file that does not exist yet is still created at rc 0.
  ⚠ A script that ran `--generate-suppressions` over a malformed rule file and relied on exit 0 now
  fails; fix the file or move it aside.
