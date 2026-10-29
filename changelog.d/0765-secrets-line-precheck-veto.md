### 🐛 Bug Fixes

- **secrets (line pre-check):** a `"url"`, `"checksum"` or version/boolean member anywhere on a line no
  longer switches off token and keyword detection for that line
  ([#765](https://github.com/awslabs/ferret-scan/issues/765)). `containsSecretIndicators`, the pre-check
  in front of the keyword pass, ran three whole-line substring checks before its provider-literal
  admits, and a hit dropped the line: one `"url": "https://github.com/…"` member, a
  `"bucket": "shared-assets"` beside a `"checksum"` key (`shared` holds `sha`) or a trailing
  `"verbose": true` hid an AKIA key ID, a `ghp_`/`glpat-`/`xoxb-` token, a JWT or a keyword-assigned
  password anywhere else on it. Nothing reached the redactor, so no redacted copy was written,
  `--pre-commit-mode` exited 0 and the `--stdin --enable-redaction` gateway passed the token through.
  Measured on v2.5.5 with the issue's nine trigger files and their one-word controls: seven reported
  nothing where the control reported every value, one (`"url"` beside a 40-character password) lost
  its AKIA key ID on every draw and the password on 10 of 31, and one reported only the token that
  #766's URI source finds outside the pre-check; 99 of 143 cells of 13 secret shapes × 11 trigger
  contexts reported nothing; `glpat-`, `xoxb-`, AKIA, JWT and 12–20-character passwords were found 0
  of 40 times after a `"url"` or `"integrity"` member and 40 of 40 after `"name"`. Now the
  provider-literal admits (JWT, every provider prefix, PEM markers) run first, and the three checks
  are replaced by one veto that skips a line only when it is wholly one benign manifest member — a
  version under 20 bytes, a boolean, an SRI digest or a URL with no user info, query or `=` — with no
  keyword stem anywhere on it, and was skipped before. Every trigger now reports what its control
  reports (31 of 31 seeded draws), all 143 cells and every matrix cell (40 of 40) detect the value,
  the lockfile decoy stays silent, both redacted copies hold no value, both pre-commit runs exit 1
  and the gateway emits no token. **New findings only:** on the matrices,
  the reproduction, 39 public npm lockfiles and 3,691 public files that hit one of the old checks, no
  existing finding changes type, text, line or confidence, and main's suppression rules still suppress
  every one of them; on a line whose token in URL user info is also a provider literal, the finding's
  `detection_method` now reads `keyword_pattern` instead of `uri_userinfo`. One shape, absent from all
  of those sets, does change an existing finding: a password in the user info of a `"url"`,
  `"resolved"` or `"homepage"` URL on a registry or forge host whose user name ends in a keyword stem
  (`https://deploy-token:<pw>@registry…`) is now reported, as on every other line, as the keyword
  pass's wider `<pw>@host/path` span, so a rule written against the narrower finding must be
  regenerated. The veto still skips 99.1% of the lockfile lines the old checks skipped; SECRETS CPU on
  those lockfiles is 3–6% above v2.5.5 (deleting the checks outright measured 2.7x).
