### 🐛 Bug Fixes

- **context (document type from the whole document):** whether a document is typed TSV or CSV,
  worth +20 on every finding of every validator in it, now depends on what the whole document holds,
  not on its first screen or its layout. `DetectStructure` typed a document from its first 2000
  characters, counted any line with two tabs as a TSV row (indentation included) and any line with
  two commas as a CSV row. Now every line of a document up to 32 KiB and 2000 lines is read, and 16
  evenly spaced windows of lines beyond that; indentation tabs and commas inside double quotes
  separate no fields; and a CSV table's rows must share one field count and not end a sentence.
  Measured on main vs this branch with `--confidence all`: a ten-row tab-separated title block above
  800 lines of prose took an `API_KEY_OR_SECRET` from 85 MEDIUM to 100 HIGH and an e-mail address
  from 93 to 100, and now leaves both where they score without it; tab-indented Go source typed TSV
  (100 HIGH for an assignment that scores 85 MEDIUM indented with spaces) and no longer does. Over
  this repository's own 1,909 files, the 177 Go files main typed TSV stop typing so, and of 1,039
  prose documents written one paragraph a line main typed 193 CSV and this branch 7. Tables,
  spreadsheet rows and CSV exports keep the boost: 120 findings in six such fixtures are unchanged.
  The secrets validator's dead `YAML` document-type case is removed: nothing produced it, and a YAML
  file's `key: value` lines type it Configuration (+15). Golden corpus: one case retyped from CSV to
  JSON (JSON lines), no band moved; `make score` unchanged
  ([#849](https://github.com/awslabs/ferret-scan/issues/849)).
