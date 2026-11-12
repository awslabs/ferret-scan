### 🐛 Bug Fixes

- **secrets**: an unquoted assignment value now ends where it does. At a two-byte `\n`, `\r` or `\t`
  escape that is followed by the next `key=`/`key:`, another escape or the end of the value (a
  quoted source string such as `"password=x\nuser=y"` no longer reports `x\nuser=y`, and
  `...KEY\n` loses its trailing `\n`); and at `&` in a URL fragment's parameters, as it already did in
  a query string (`cb#access_token=<a>&refresh_token=<b>` reports the two tokens apart instead of one
  span running to `expires_in=3600`). A `#` at the start of a line or after a space still marks a
  commented-out assignment, taken whole. Because the span is what redaction rewrites and what a
  suppression rule hashes, a rule written for one of the old over-long spans goes stale.
  ([#932](https://github.com/awslabs/ferret-scan/issues/932))
