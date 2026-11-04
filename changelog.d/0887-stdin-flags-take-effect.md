### 🐛 Bug Fixes

- **cli (`--stdin`):** `--disable-ip-types`, `--suppression-expires` (and `suppressions.expires_in`),
  `--list-profiles` and `--debug` now do on `--stdin` and `--file -` what they do on `--file`; the
  stdin path kept its own copy of the code that runs before the scan and skipped them, with no
  message ([#887](https://github.com/awslabs/ferret-scan/issues/887)). Measured on a four-line IP
  sample: each of the 5 sub-types removed 1 finding on `--file` and 0 on `--stdin`, and now 1 on both;
  generated rules carry `expires_at` on stdin (0 before); `--stdin --list-profiles` lists the
  profiles instead of scanning; `--stdin --debug` prints the validators' 6 `[DEBUG]`/`[INFO]` lines
  (0 before). The stdin path also prints the `Note: config disabled …` line, the warning for a
  `disabled_types` name that matches nothing, and the notice that `--redaction-output-dir` is not
  used, none of which it printed; the two disclosures are withheld when stderr carries the findings
  document (`--enable-redaction` with no `--output`).
