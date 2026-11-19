### 🐛 Bug Fixes

- **`--quiet`, config notes:** a `--quiet` typed on the command line now withholds the two TM-13 Notes on
  stderr, `Note: using project config … found in the working directory` and `Note: config disabled N …
  detection sub-type(s)`, on `--file` and `--stdin`. Both facts are in the report itself since #1007 (the
  scope block names the config source and the narrowed checks; `stats.disabled_detection_types` lists the
  sub-types), so the stderr copy was duplication. ⚠ Two things still print: under `--format csv`, which
  has no scope block, stderr is the only place the facts appear; and `Warning: config asked to disable …
  they had NO effect`, which says the config did not take effect. A pre-commit run without `--quiet`, a
  `--quiet=false`, and a `quiet: true` set in a config file or profile keep both Notes: a config file
  shipped in a pull request can disable detection, and it must not be able to silence the Note that names
  it ([#1008](https://github.com/awslabs/ferret-scan/issues/1008), item 3).
