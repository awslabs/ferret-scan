### 🐛 Bug Fixes

- **redaction, `.txt` `.csv` `.html` and every text-substituting redactor:** a reported value of 8 or more
  bytes is now also masked where it starts or ends a longer token (a name followed by more letters, a
  member ID followed by `_` and a suffix). Before, the completeness sweep left any occurrence alone when
  a letter, digit or `_` abutted it: two public corpus files kept 33 reported values (174 occurrences)
  in the copy under `simple` and `format_preserving`, none of them standalone. An occurrence with a
  word byte on both sides (a value inside a hex constant) is still left alone, and values of 4 to 7
  bytes keep the standalone-only rule. The sweep now also repeats when a `format_preserving`
  replacement, which keeps a value's last characters, spells another reported value again with the
  bytes after it. Detection, reports, counts and suppression hashes are unchanged
  ([#968](https://github.com/awslabs/ferret-scan/issues/968)).
