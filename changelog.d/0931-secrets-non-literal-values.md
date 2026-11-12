### 🐛 Bug Fixes

- **secrets**: the value of a secret-named assignment is no longer reported when it is not a literal:
  a regular expression (`trade_secret: "\\b(Confidential|Trade\\s+Secret|...)"`, the shipped
  `config.yaml`'s own pattern), a rooted file path (`private_key=/etc/ssl/private/server.key`), a
  member chain, dotted call or concatenation operand (`config.secret_key`, `process.env.JWT_SECRET`,
  `os.getenv(DB_PASSWORD_ENV)`, `+name[2]+`), ferret-scan's own `simple` redaction marker
  (`[API_KEY_OR_SECRET-REDACTED]`, also as a JSON string ending in `\n`) or a separator-keeping `*`
  mask, and a provider prefix around a placeholder body (`glpat-` and a run of `x`, Slack's documented
  `xoxb-not-a-real-token-this-will-not-work`). Each read HIGH (75-100) before; a redacted copy
  therefore re-scanned as still leaking. The rule reads only the value's own bytes. In Python, JS/TS,
  Go and HCL files an unquoted value in code position is still left to the lexical gate (#753).
  ([#931](https://github.com/awslabs/ferret-scan/issues/931), [#981](https://github.com/awslabs/ferret-scan/issues/981))
