### 🐛 Bug Fixes

- **cli (`--stdin`, config value warnings):** `--stdin` now prints the
  `Warning: config value <path>: <problem> — <effect>` line `--file` prints for a value under
  `validators:` its validator cannot use, and the report carries the same lines as data
  ([#903](https://github.com/awslabs/ferret-scan/issues/903)). Measured on main over 8 bad configs
  (`cloud_resources`, `intellectual_property`, `social_media`): `--file` printed all 8 and `--stdin`
  none, in default mode, `--quiet` and `--pre-commit-mode`; now `--stdin` prints the same 8 lines. json
  and yaml reports gain `stats.config_warnings` and sarif gains
  `invocations[].toolConfigurationNotifications[]`, on `--file` and `--stdin`, so the `--stdin
  --enable-redaction` gateway, whose stderr is the findings document, carries the warning in that
  document instead of dropping it (0 of 8 on main, 7 of 8 now; the eighth row has no finding, so no
  document is written). Both appear only when a value was unusable: a usable config's report keeps
  every byte. Findings and exit codes are unchanged.
