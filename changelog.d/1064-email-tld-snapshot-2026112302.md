### 🐛 Bug Fixes

- **email (TLD snapshot):** the embedded IANA root zone is refreshed from `# Version 2026110304`
  (1436 TLDs) to `# Version 2026112302` (1435 TLDs). One TLD, `xihuan`, was withdrawn from the
  root zone since the last snapshot and is now treated as unrecognised, so an address on it is
  capped into the LOW band by `unrecognisedTLDCeiling` (measured: `user@example.xihuan` 53 → 43);
  no TLD was delegated, so no real address changes band in the other direction. Regenerated with
  `scripts/check-tlds.sh update`, which reproduces the committed file byte-for-byte against an
  unchanged root zone; `check` now reports the snapshot current
  ([#1064](https://github.com/awslabs/ferret-scan/issues/1064)).
