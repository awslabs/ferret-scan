### 🐛 Bug Fixes

- **cli (`--stdin`):** the stdin findings report is no longer just `{"results": [...]}`. json and
  yaml now carry the `stats` block `--file` writes, for one virtual file (`total_files: 1`), with
  `stats.disabled_detection_types` for a `--config` that switches a sub-type off and
  `stats.files_not_examined: 1` for a cut-short scan, which junit, sarif and gitlab-sast now also
  disclose ([#904](https://github.com/awslabs/ferret-scan/issues/904)). `--stdin --pre-commit-mode
  --output r.json` on clean input wrote 0 bytes where `--file` writes the document; it now writes
  it, as `docs/PRE_COMMIT_INTEGRATION.md` already said. Text output on stdin is unchanged.
- **cli (project config note):** the note for a config found in the working directory names the
  checks it limited the run to, `…; it limits checks to EMAIL (18 of 19 not run).`, instead of
  saying only that it "can disable detection types"; the old wording stays when the config narrowed
  no check, or `--checks` or the built-in pre-commit profile chose them
  ([#904](https://github.com/awslabs/ferret-scan/issues/904)).
