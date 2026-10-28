### 🐛 Bug Fixes

- **secrets (masked token with its provider prefix):** a mask that keeps the token's provider
  prefix, `gho_` and 36 `*` as several tools print a token in a log, is no longer reported as
  `API_KEY_OR_SECRET`. The already-masked veto in `plausibleUnquotedSecret` (#522) required the
  value to be entirely `*`, so one kept prefix defeated it. A prefix from the provider grammar
  table followed by at least 8 `*` and nothing else is now masked output, in that veto and in the
  URI user-info disposition table; a `gho_` token with a random body and `gho_****abcd****` report
  exactly as before. Measured on main vs this branch: the issue's line, 75 MEDIUM to nothing in
  plain text and 100 HIGH to nothing in a `.docx` with a tab-separated cover block (+20); the same
  mask as a URI password, 75 to nothing; every table prefix under a stem key, 75 to 85 to nothing
  ([#807](https://github.com/awslabs/ferret-scan/issues/807)).
