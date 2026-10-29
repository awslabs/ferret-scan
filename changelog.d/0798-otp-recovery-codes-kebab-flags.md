### 🐛 Bug Fixes

- **otp (hyphenated words as recovery codes):** kebab-case CLI flags, path segments and hyphenated
  prose are no longer reported as `RECOVERY_CODES` on a line that only mentions backup, recovery,
  emergency, 2FA or MFA ([#798](https://github.com/awslabs/ferret-scan/issues/798)). A bare topic
  word anywhere on the line gave it recovery context and the block pattern matches any run of
  hyphenated words, so a runbook line with `backup` in a path reported its flags: `data-bucket` and
  `only-show-errors` from an `aws s3 cp` into `$WORK/backup/data-bucket/`. Measured through the CLI
  on a `.md` file, the issue's six lines reported 16 findings at 50–65 (`update-function-code`,
  `high-risk`, `Multi-Factor`, …) and this repository's own docs, changelog and tests reported 23;
  now none of either. A block with a lowercase letter and no digit is now a recovery code only when
  an explicit `recovery codes` or `backup codes` label precedes it and its groups are equal in length
  (`2FA backup codes: … abcd-efgh`); a block with a digit or with no lowercase letter keeps the old
  rule, and the issue's controls report the same codes at the same confidence. Only findings are
  removed: no remaining finding changes type, text, line or confidence. Trade-off: a digit-free
  lowercase or mixed-case code on a line with only a bare topic word (`MFA backup: …`) is no longer
  reported.
