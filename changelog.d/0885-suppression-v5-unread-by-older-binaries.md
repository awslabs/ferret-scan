### ⚠️ Breaking Changes

- **suppressions (identity):** rules written or migrated by this version use hash formula v5, which
  older binaries do not read. For a finding with whitespace or a `\r` at the outer edge of its context
  windows or its value, the v5 hash differs from the v2 hash those binaries compute, so they stop
  matching that rule: on this repository's own tree, 8,453 of the 13,330 rules a regeneration writes
  (mostly findings on indented lines), and 17 of the 368 rules for the golden-corpus inputs. Every other
  rule is the same hash under both. Upgrade every binary that reads a shared suppression file before
  regenerating it ([#885](https://github.com/awslabs/ferret-scan/issues/885)).
