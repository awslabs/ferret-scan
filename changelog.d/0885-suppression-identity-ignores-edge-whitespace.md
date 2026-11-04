### 🐛 Bug Fixes

- **suppressions (identity):** converting a file between LF and CRLF, re-indenting it or adding a
  trailing space no longer un-suppresses its findings. The identity hash digested the context windows
  raw, so near a line edge a `\r`, the indentation or a trailing space changed it: on 39 of this
  repository's files (581 findings), rules generated on the LF copy suppressed 86 findings of the CRLF
  copy, 113 of a re-indented copy and 86 of a copy with trailing spaces, and rules generated on the
  CRLF copy 86 of the LF copy. New rules use formula v5, which leaves the whitespace at the outer edges
  of the windows and of the value out (581 of 581 in every case), and existing v2 and v1 rules are also
  matched with the other line ending (581 of 581 both ways, 0 findings matched by another finding's
  rule). Existing rules stay indent-sensitive until `--generate-suppressions` migrates them: it now
  rewrites the hash of a rule it matched through an older formula, and changes nothing else in it
  ([#885](https://github.com/awslabs/ferret-scan/issues/885)).
