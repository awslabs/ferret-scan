### 🐛 Bug Fixes

- **secrets (quoted values with a hyphen, `ASIA` key IDs, joined key names):** three gaps in the
  secrets validator are closed ([#881](https://github.com/awslabs/ferret-scan/issues/881)). The
  entropy path's character class was built with `regexp.QuoteMeta` alone, whose `\-_` became the
  range `\`..`_`, so `]` and `^` were admitted and `-` was not: no quoted value with a hyphen
  (base64url, a JWK member, `sk-ant-...`, `{"client_secret": "..."}`) was ever scored. `-` is now
  admitted; a value that is wholly an exact-length `sha1/256/384/512-` integrity digest (lockfile
  `"integrity"`, nix `"narHash"`, `<script integrity>`, CSP `'sha256-...'`) and a hyphenated object
  key are skipped, and an uncorroborated hyphenated value publishes its 55 cap so a CSV/TSV
  document cannot lift it to MEDIUM. `ASIA` temporary (STS) access key IDs are now reported as
  `AWS_ACCESS_KEY` with `aws_key_kind: temporary`: HIGH beside a secret access key or session token
  value on the same or an adjacent line, at most 55 otherwise, 15 for `ASIAIOSFODNN7EXAMPLE`; the
  row, `isAWSAccessKey` and the pairing regex share one definition. A joined key name (`apikey`,
  `privkey`, `accesstoken`, ... in any case) now corroborates its value as `api_key` does, except
  a rooted file path holding a `.` (certbot's `privkey = /etc/letsencrypt/.../privkey.pem`).
  Measured, main vs this branch: the 13 joined spellings with `:` and `=`, nothing to 100 (78 of 78
  cells); `apikey = "<v>"`, 55 to 100; the 22-shape x 8-context token matrix, 96 to 111 findings;
  a 50-row CloudTrail export, the 40 `ASIA` rows from nothing to LOW; under `--enable-redaction`
  (`simple` and `format_preserving`), 177 to 67 of 334 raw fixture values left in the clear; the Go
  module cache and the Go distribution, +55 and +8 findings, 0 lost, 0 changed; golden corpus and
  `make score` unchanged. **Upgraders:** a labelled `ASIA` value that main reported as
  `API_KEY_OR_SECRET` (`SERVICE_API_KEY=ASIA...` at 100) is now `AWS_ACCESS_KEY` at 55, so its
  suppression hash moves and a rule for it must be regenerated; a joined-stem assignment that
  reported nothing can now fail a pre-commit run.
