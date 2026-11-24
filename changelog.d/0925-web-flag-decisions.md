### 🐛 Bug Fixes

- **`--web`, eight flags decided:** `--profile`, `--disable-ip-types` and `--validator-budget` now apply to every
  `/scan` the way they apply to `--file` (before, `--profile` and `--disable-ip-types` were accepted and ignored,
  and `--validator-budget` was refused), and `--debug` writes the scan's debug log to the server's stderr (it was
  accepted and ignored). An unknown `--profile` refuses to start. ⚠ `--respect-gitignore` and `--limit` were
  accepted and did nothing with `--web`; they are now refused at startup (exit 1, the message names the flag),
  because an upload has no directory tree and the page shows every finding. `--list-profiles` and
  `--max-live-bytes` stay refused, now with reasons that say what to use instead. A script that passed
  `--respect-gitignore` or `--limit` to `--web` must drop them
  ([#925](https://github.com/awslabs/ferret-scan/issues/925)).
