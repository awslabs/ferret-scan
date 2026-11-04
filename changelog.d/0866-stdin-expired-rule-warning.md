### 🐛 Bug Fixes

- **cli (suppressions):** `--stdin` now prints the `WARNING: N finding(s) are reported because their
  suppression rule has EXPIRED` line the file path has printed since #699, under `--quiet` and in
  pre-commit mode too; it is withheld only when stderr carries the findings document
  (`--enable-redaction` with no `--output`). Measured with two expired rules: `--stdin` printed no
  warning, and `--stdin --pre-commit-mode` blocked the commit with 0 bytes on stderr; both now print
  the same line as `--file` ([#866](https://github.com/awslabs/ferret-scan/issues/866)). The
  warning's remedy no longer names `ferret-scan-suppress --action cleanup`, a binary no release
  builds, nor "regenerate the rules", which re-running `--generate-suppressions` on the file does not
  do (an existing rule keeps its `expires_at`): it now says to edit or remove `expires_at`, use the
  web UI's bulk expiration control, or delete the expired rules and regenerate them.
