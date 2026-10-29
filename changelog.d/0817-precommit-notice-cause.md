### 🐛 Bug Fixes

- **cli (pre-commit not-examined notice):** the one-line `--pre-commit-mode` notice for files that
  were not fully examined now names the cause instead of reading `(contents unreadable)` for every
  one ([#817](https://github.com/awslabs/ferret-scan/issues/817)). The line was one `Fprintf` with
  that literal, written while the unreadable channel was the only one feeding it, so a file a
  `--validator-budget` cut short and a `.pdf` holding plain text, both read in full, sent the
  developer to permissions and encodings. It now prints the full report's own labels
  (`unscannedCause.String()`), one alone or a count each in the full report's order. Measured on
  main after v2.5.5: the issue's `--validator-budget all=1ns` run, a 1 MB file under `PHONE=1ns`,
  the `.pdf`, a chmod-000 file and a three-cause directory all printed `(contents unreadable)`; they
  now print `(coverage cut short)`, `(coverage cut short)`, `(cannot parse)`, `(cannot read)` and
  `(1 cannot read, 1 cannot parse, 1 coverage cut short)`. On a cut-short in a run that exits 0 the
  line ends with the full report's `Add --fail-on-incomplete to make this a non-zero exit (3).`,
  withheld when the gate is already on (flag, config or profile: exit 3) and when a finding blocks
  the commit (exit 1). Exit codes, the full report and machine formats are unchanged.
