### ⚠ Breaking Changes

- **cli:** `--stdin` with an unknown `--profile`, or with a `--suppression-expires` /
  `suppressions.expires_in` value that does not parse, now exits `1` before reading stdin and writes
  nothing to stdout, as `--file` does; it used to scan with the defaults, or accept the value, at
  exit `0` ([#887](https://github.com/awslabs/ferret-scan/issues/887)). In the redaction gateway a
  mistyped profile that adds an internal-URL pattern passed the URL through in clear with 0 bytes on
  stderr. On `--stdin`, `--disable-ip-types` now removes the sub-types it names, so a pre-commit run
  can exit `0` where it exited `1`. On `--file`, `--disable-ip-types` now outranks a profile's
  `disabled_types`, as documented: the flag's list replaces the set config and profile chose, and the
  Note names the flag's sub-types (measured: a profile disabling patent plus the flag disabling
  copyright used to hide patent and report copyright; it now does the reverse). No finding text, line
  or type changes, so no suppression hash moves.
