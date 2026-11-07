### 🚀 Features

- **output (narrowed runs):** a report from a run that did not look at everything now says so. When
  a check did not run, a confidence band is hidden or a detection sub-type was disabled (by
  `--checks`, `defaults.checks`, a profile, the pre-commit profile, `--confidence` or
  `disabled_types`), json and yaml gain a `scan` object beside `stats` (`checks_run`,
  `checks_not_run`, `checks_not_applicable`, `confidence_levels`, `profile`, `config.source`,
  `suppressions.rules_enabled` and `tool` with a 12-hex commit), junit gains `<properties>` on the
  `security-scan` suite, sarif gains `ferretScan*` keys in `run.properties`, `ferretScanCommit` on
  the driver and one `warning` on the existing `ferret-scan/detection-disabled-by-config`
  descriptor when checks did not run (`executionSuccessful` stays `true`), gitlab-sast gains
  `scan.messages`, and text gains one `Scope:` line (not in pre-commit text); csv has no slot
  ([#904](https://github.com/awslabs/ferret-scan/issues/904)). Measured on the issue's file with a
  copyright notice and an email address: `--checks SSN`, `defaults.checks: SSN` in a `--config`,
  `--profile ci` and `--profile precommit` gave a report byte-identical to a clean scan of a
  neutral file in all 7 formats, and now differ in all but csv. A run that ran in full gets none of
  this: its output is unchanged byte for byte in every format, as is every golden snapshot. Keys
  are additive only; exit codes and suppression hashes are unchanged. The descriptor's text now
  says checks or sub-types.
