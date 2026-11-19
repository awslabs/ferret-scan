### 🐛 Bug Fixes

- **config warnings, `--debug`:** a `Warning: config value …` about a value read from a profile's
  `validators:` block now names the profile in its path, as the unknown-key warning does
  (`profiles.zz.validators.cloud_resources.custom_patterns[0]`); before, it read like a value from
  the base config. ⚠ A value that is bad in both the base block and the profile is now two warnings, one naming
  each block, where it was one. `--debug` now writes the validators' configure-time lines
  (`Cloud Resource Validator initialized: … N custom patterns`, the internal-URL pattern counts) on
  `--file` and `--stdin`; the observer was attached after the validators had been configured, so they
  were never written
  ([#903](https://github.com/awslabs/ferret-scan/issues/903), the profile label and box 8).
