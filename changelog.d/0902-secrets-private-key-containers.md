### 🐛 Bug Fixes

- **secrets**: private keys written outside 5-dash PEM are now reported: PuTTY `.ppk` files (any
  version, encrypted or not, indented, CRLF or `\n`-escaped in a JSON string) and ssh.com `---- BEGIN
  SSH2 ... PRIVATE KEY ----` blocks as `SSH_PRIVATE_KEY`, any other 4/5-dash `... PRIVATE KEY` armour
  label as `SSH_PRIVATE_KEY`, and OpenVPN static / tls-crypt-v2 keys and age identities as
  `API_KEY_OR_SECRET`, each with its own `detection_method`. In the issue's reproduction the four
  container files go from no finding to 95-100. A PEM written on one line (space-joined or a JSON
  string) is reported once instead of 2-3 times; the multi-line finding is the one kept, so a
  suppression rule written for a dropped copy goes stale. A finding whose whole text is such a
  container keeps its type, text and line and now scores like a PEM (a `.ppk` under
  `"private_key"`: 72 to 100). ([#902](https://github.com/awslabs/ferret-scan/issues/902))
