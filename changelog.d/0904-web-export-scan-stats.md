### 🐛 Bug Fixes

- **web:** `/export` reports now carry the CLI's `scan` scope block and `stats` block, in every format that has a slot for them (#904). `/scan` keeps the scope it computed and the run's stats beside the findings, and `/export` renders them, adding the stats when several scan ids are exported together. A narrowed web scan exported to JSON, YAML, SARIF, JUnit, GitLab SAST or text now says what it did not run, as the CLI's `--file` report does.
  ⚠ Exported JSON and YAML gain `stats` (and `scan` when the run was narrowed) keys, so a script that compared whole export bodies sees new content.
