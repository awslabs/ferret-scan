### 🐛 Bug Fixes

- **cli:** a repeated `--exclude` now adds to the list instead of replacing it, so
  `--exclude '.git/**' --exclude 'build/**'` excludes both, exactly as `--exclude '.git/**,build/**'`
  does ([#943](https://github.com/awslabs/ferret-scan/issues/943)). The flag kept only the last
  occurrence and said nothing, so that command scanned `.git/` and reported what is in it (commit
  authors in `.git/logs/HEAD`, for example). `--checks`, `--confidence`, `--disable-ip-types` and
  `--validator-budget` take a comma-separated list too and now append on a repeat the same way:
  `--checks SSN --checks EMAIL` runs both checks where it used to run EMAIL only. A command that
  relied on the last occurrence winning now gets the union: `--confidence all --confidence high`
  shows every level, not high only. `--checks all --checks SSN` now exits 1 with "'all' cannot be
  combined with other check names", as `--checks all,SSN` always did, where it used to run SSN only;
  drop one of the two. An empty repeat no longer resets the list: `--checks SSN --checks ''` now
  runs SSN only, where the empty last value used to mean every check. A repeated
  `--validator-budget` entry for the same check is refused as a duplicate, as it already was within
  one value. `--help` says which flags are repeatable.
