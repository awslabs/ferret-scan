### 🐛 Bug Fixes

- **secrets**: the detect-secrets pragma `pragma: allowlist secret` (which ferret-scan itself appends
  to every `hash:` line of a generated suppression file) no longer counts as a credential label. Its
  word `secret` raised the value beside it: a quoted 64-hex rule hash read 55 (LOW) alone and 95-100
  (HIGH) with the pragma; it now reads the same with and without it. The pragma does not exempt its
  line: a real credential beside it is reported exactly as without the comment (use a suppression
  rule to accept a finding). ([#933](https://github.com/awslabs/ferret-scan/issues/933))
