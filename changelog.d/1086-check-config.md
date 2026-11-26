### 🚀 Features

- **`--check-config`:** reads the configuration the way a scan would (`--config`, else discovery; `--profile`,
  else the built-in `precommit` profile in pre-commit mode), builds every validator from it, scans nothing,
  and prints to stdout the config in use and where it came from, a load failure, unknown keys, disabled
  detection sub-types, every configured value a validator could not use (the `Warning: config value …` lines
  a scan prints), the profile, a line saying that pre-commit mode would refuse a config discovered in the
  working directory (#293), and a `config check: OK` / `config check: N problem(s)` summary. It exits 1 when
  anything configured did not take effect and 0 otherwise. The pre-commit refusal does not apply to it, and
  `--web --check-config` is refused at startup. This is the deliberate check that `--version` used to give by
  accident ([#1086](https://github.com/awslabs/ferret-scan/issues/1086)).
