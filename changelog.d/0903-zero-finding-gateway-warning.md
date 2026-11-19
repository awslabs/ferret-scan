### 🐛 Bug Fixes

- **config warnings, `--stdin --enable-redaction`:** an input with no finding now discloses a configured
  value the validators could not use (a custom pattern RE2 rejects). Before, stderr stayed empty, so a
  gateway reading stderr as the findings document saw nothing, and the scan that found nothing may have
  found nothing because the pattern was dropped. With `--format json`, `yaml` or `sarif`, stderr is the
  report with an empty result list and the warning in `stats.config_warnings` (or SARIF's
  `toolConfigurationNotifications`); with any other format, or on a terminal, stderr carries the same
  `Warning: config value …` line `--file` prints. ⚠ A zero-finding gateway run whose config holds an
  unusable value now writes to stderr where it wrote nothing; a run with a usable config still writes
  nothing. `RedactFileResult.ConfigWarnings` (the other half of the issue's box 6) was already in
  [#987](https://github.com/awslabs/ferret-scan/pull/987)
  ([#903](https://github.com/awslabs/ferret-scan/issues/903), box 4).
