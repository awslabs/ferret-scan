### 🐛 Bug Fixes

- **cli (`--quiet`):** a `--file` run no longer prints one `Warning: Skipping <path>: excluded by
  .gitignore` line per path the operator's own `--exclude` or `.gitignore` left out. They are one
  `Note: N path(s) left out as requested (.gitignore: A, --exclude: B)` line, with the paths listed
  under `--verbose` or `--debug`, and `--quiet` withholds it. `--quiet` now also withholds the
  `Suppressed N findings …` line and the `N enabled suppression rule(s) … matched no finding` note on
  `--file`, and the latter on `--stdin` (its `Suppressed` line already was); the counts stay in
  `stats.suppressed` and `stats.suppression_rules_unmatched`. ⚠ A script that grepped stderr for
  `Warning: Skipping` to find excluded paths reads `Note: … left out as requested` (and `--verbose`
  for the list) instead. The pre-commit default (`PRE_COMMIT=1` without `--quiet`) still prints the
  suppression notes, as before; the two TM-13 config Notes are unchanged
  ([#1008](https://github.com/awslabs/ferret-scan/issues/1008), items 1 and 2).
