### 🔨 Internal

- **self-scan:** the repository's scan of its own tree is one script, `scripts/self-scan.sh`
  (`make self-scan`), that blocks on HIGH. It reads a committed profile, `.ferret-scan/selfscan.yaml`,
  whose six excludes each carry a measured reason, and gates shippable files with every check and
  `*_test.go` with `SECRETS` only, counting from `stats` and printing `stats.suppressed` beside the
  count; excluded paths get a report-only MEDIUM+ pass, `--base <ref>` prints the HIGH findings that
  are new, lost and changed against a ref with the text hashed, and exit 2 means the scan could not
  vouch for its result. On `main` the tree held 6,222 HIGH findings outside `.git/`; the excludes
  leave 648, and a reviewed 710-rule ledger (every rule enabled, no expiry, `fixture:` or
  `detector FP: #NNN`) is ready to replace the 245-rule baseline whose rules had all expired.
  `docs/testing/SELF_SCAN.md` lists the reserved example values the validators demote, measured
  ([#927](https://github.com/awslabs/ferret-scan/issues/927)).
