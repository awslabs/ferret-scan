### 🐛 Bug Fixes

- **config (validator values):** a value under `validators:` that its validator cannot use is now named
  on stderr instead of being dropped in silence
  ([#903](https://github.com/awslabs/ferret-scan/issues/903)): a regex RE2 rejects, with the PCRE
  construct named (`"(?<=" is a PCRE lookbehind`; RE2 reports it as `invalid named capture`), an entry
  of the wrong type, a scalar where a list belongs, an unknown or wrong-case `enabled_providers` name,
  a non-bool provider (`aws: no` is the string "no" in YAML 1.2), an unknown
  `intellectual_property_patterns` name. One line per value,
  `Warning: config value <path>: <problem> — <effect>`, for `cloud_resources`,
  `intellectual_property` and `social_media`; the pattern text is not echoed. Measured on main over the
  issue's 19 bad configs: every one lost its detection, disable or allowlist, 17 printed nothing in any
  `--file` mode and the other 2 a generic line naming no pattern; now all 19 print the warning in
  default, `--verbose`, `--debug`, `--quiet` and `--pre-commit-mode` (it is not gated), with findings
  and exit codes unchanged, and valid configs print nothing. `core.ScanResult`, `core.RedactResult` and
  `pkg/scan`'s `Result` carry the lines as `ConfigWarnings`; `--web` prints them once at startup. The
  three validators' `Configure` no longer writes to os.Stderr: `pkg/scan` with a `LogWriter` wrote
  2016 B past it over 14 calls on main and writes 0 B, and `--stdin --enable-redaction --format json`
  with a bad IP pattern override writes a findings document that parses (2422 B, unparseable, on
  main). The "Internal URL detection disabled: all configured internal URL patterns are invalid",
  "invalid intellectual_property_patterns.<name> regex" and "Social media detection disabled: all
  configured social media patterns are invalid" lines are replaced by the per-value warnings, and the
  configure-time `[DEBUG]`/`[INFO]` lines these validators printed under `--debug` now go to the debug
  observer only. `--stdin` does not print the warnings yet.
