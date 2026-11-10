### 🔨 Internal

- **self-scan:** the repository's scan of its own tree is one script, `scripts/self-scan.sh`
  (`make self-scan`), that blocks on HIGH, and the CI workflow now runs it in block mode on every pull
  request and push. It reads a committed profile, `.ferret-scan/selfscan.yaml`, whose excludes each
  carry a measured reason, and gates shippable files with every check and `*_test.go` with `SECRETS`
  only, counting from `stats` and printing `stats.suppressed` beside the count; excluded paths get a
  report-only MEDIUM+ pass, `--base <ref>` prints the HIGH findings that are new, lost and changed
  against a ref with the text hashed, and exit 2 means the scan could not vouch for its result. On
  `main` the tree held 6,222 HIGH findings outside `.git/`; the excludes leave 672, and the committed
  ledger `.ferret-scan-suppressions.yaml` now holds 666 reviewed rules for them, every rule enabled
  with no expiry and a reason of one of three kinds (`fixture:`, `detector FP: #NNN` for the eleven
  detector false-positive classes #930–#940, `public:`), replacing the 245-rule baseline whose rules
  had all expired. The three real values the first run found were removed in #942.
  `docs/testing/SELF_SCAN.md` lists the reserved example values the validators demote, measured
  ([#927](https://github.com/awslabs/ferret-scan/issues/927)).
