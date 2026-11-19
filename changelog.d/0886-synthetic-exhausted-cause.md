### 🐛 Bug Fixes

- **redaction (synthetic, exhausted family):** a file refused because the synthetic strategy ran out
  of distinct replacements for one value family is now reported under its own cause, `synthetic
  replacement space exhausted`, in every format's unredacted disclosure (the text report's cause
  group, `unredacted[].cause` in json and yaml, the csv `Not Redacted Reason`, and the junit, sarif
  and gitlab-sast messages), instead of the generic `redaction refused`
  ([#886](https://github.com/awslabs/ferret-scan/issues/886)). The cause is read from the
  redactor's typed error (`errors.Is(err, redactors.ErrSyntheticSpaceExhausted)`), not from its
  wording. Nothing else changes: the file is still refused, still counted in `files_not_redacted`,
  and `--fail-on-incomplete` still exits 3. ⚠ A consumer that matches the cause strings sees a new
  value.
