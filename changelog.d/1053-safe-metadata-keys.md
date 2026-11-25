### 🐛 Bug Fixes

- **formatters (json, yaml, sarif, gitlab-sast):** a finding's `metadata` now carries the validators'
  own verdict keys `country`, `checksum_valid`, `check_digit_valid` and `confidence_ceiling`. The
  report's metadata allowlist (`safeMetadataKeys`) did not list them, so nationalid's `country` and
  its `checksum_valid=false` on a LOW finding, and phone's `country` and `confidence_ceiling`, were
  dropped unless `--show-match` was set, while phone's `format` and `pattern_name` reached the
  report. None of the four can hold the matched value: a country label or code, two booleans, a
  number ([#1053](https://github.com/awslabs/ferret-scan/issues/1053)). ⚠ The set of metadata
  keys a report can carry grows by these four: a consumer that compares the `metadata` object of a finding byte for byte, or rejects unknown keys, sees them on findings
  whose validator sets them.
