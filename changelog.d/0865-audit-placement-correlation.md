### 🐛 Bug Fixes

- **Redaction audit log: `placement` names how a text value was located.** For text files (and SVG
  and RTF) each `content_redactions[].placement` gains `correlation` (`exact`, `fuzzy` or
  `heuristic`, present when `method` is `position_correlation`) and `corrected: true` when the placed
  position held other text and was found again by searching. The issue's `dup.txt` (one card twice
  on a line) logged `score` 0.8 and 0.56 and nothing else; it now says `fuzzy` and `fuzzy`,
  `corrected`. Additive: `method` and `score` are unchanged. A registry oracle and a declared-field
  guard now check every registered redactor's audit log against the run
  ([#865](https://github.com/awslabs/ferret-scan/issues/865)).
