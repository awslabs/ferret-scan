### 🚀 Features

- **suppressions (re-anchoring):** `--generate-suppressions` now moves a rule whose finding moved to
  another line, instead of leaving it matching nothing and appending a disabled duplicate. A rule moves
  only to the same value on the same line text in a file of the same name, only when the move is
  one-to-one (a repeated line is left alone), and only its `hash`, `metadata.line_number` and
  `last_seen_at` change; scan-time matching stays exact, and the run that regenerates is not affected.
  On the issue's 39-file set (473 rules generated at v2.4.0, 612 findings at the v2.6.0 development
  head), one regeneration re-anchored 253 rules and refused 5, and the rescan suppressed 492 findings
  instead of 238; the file holds the 473 rules plus 120 new ones, where it used to grow to 846. The
  search makes at most 500,000 comparisons per run (`MaxReanchorComparisons`, about 0.6 s), and a run
  that reaches the limit says so ([#885](https://github.com/awslabs/ferret-scan/issues/885)).
- **suppressions (generation report):** `--generate-suppressions` prints what it did (rules added,
  refreshed, re-anchored and migrated, and the rules it left alone as ambiguous, unmatched or not
  evaluated) on `--file` and `--stdin`, instead of the fixed "existing rules had last_seen_at updated,
  new rules added" it printed whatever had happened
  ([#885](https://github.com/awslabs/ferret-scan/issues/885)).
