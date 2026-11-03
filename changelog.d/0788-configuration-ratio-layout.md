### 🐛 Bug Fixes

- **context (Configuration type from layout):** whether a file is typed Configuration, worth +15 on
  every secrets candidate in it, no longer depends on how the file is laid out. `DetectStructure`
  took every structure's share over each element of a newline split, so a trailing newline added an
  empty line to the denominator; comment and blank lines counted against Configuration; and its key
  pattern was anchored at column 0, so an indented key (INI under a `[section]`, a YAML map) never
  counted. The trailing empty element is now dropped from every share, the Configuration share is
  taken over the lines that are neither blank nor comment-only (`#`, `;`, `//`), and a key may be
  indented. The other shares keep their blank and comment lines: their CSV and TSV patterns are
  layout-sensitive in their own way (any two commas, indentation tabs), and taking them over the same
  subset typed tab-indented Go source TSV, +20 on every finding of every validator. Measured on main
  vs this branch: #785's six credential lines, 85 with a trailing newline and 100 without on main,
  100 both ways; `password=<v>` under three comment lines, 97 to 100; the same keys indented under
  `[db]`, 85 to 100. Golden corpus: 0 findings added or lost, 5 band moves, all MEDIUM to HIGH, each
  a fixture with a trailing newline or indented keys (an `alembic.ini`, a Python module's embedded
  `.env` body, and 2 `PASSPORT` values whose file types CSV once the trailing newline is gone, as it
  does on main without it). An indented `name = value` in source code is a key line too, so a module
  of assignments can type Configuration. `make score` unchanged
  ([#788](https://github.com/awslabs/ferret-scan/issues/788)).
