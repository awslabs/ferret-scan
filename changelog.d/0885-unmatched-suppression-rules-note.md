### 🐛 Bug Fixes

- **suppressions (rules that matched nothing):** a scan now says when an enabled suppression rule for a
  file it examined in full matched no finding, which happens when the finding moved, changed or was
  removed ([#885](https://github.com/awslabs/ferret-scan/issues/885)). One stderr line,
  `Note: N enabled suppression rule(s) for files scanned in this run matched no finding (…): <ids>.
  Run --generate-suppressions to re-anchor the ones whose finding only moved.`, on `--file` and
  `--stdin`, and `stats.suppression_rules_unmatched` in the json and yaml reports (absent when there is
  none). Measured with #885's fixture (5 rules, then one line inserted at the top): main reported
  `active=5 suppressed=0` and named nothing on either path; now both name the 5 rules and count them,
  at the same exit code. A rule for a file the run did not read, or of a type a narrowed run did not
  look for, is not counted, and a `--generate-suppressions` run does not name the rules it re-anchored
  or migrated to the current hash formula. On the `--stdin --enable-redaction` gateway, whose stderr is
  the findings document, the count rides in the document and the note is not printed.
