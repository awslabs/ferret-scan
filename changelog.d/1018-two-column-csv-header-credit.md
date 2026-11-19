### 🐛 Bug Fixes

- **tabular (CSV/TSV column headers):** a two-column file is now read as a table when it has the
  evidence three columns do not need ([#1018](https://github.com/awslabs/ferret-scan/issues/1018)).
  The table reader started at three fields, so `phone,qty` held PHONE at 85 with no header credit
  and `name,passport_number` reported no PASSPORT at all, while the three-column spelling of the
  same data gave 100. A two-column file is a table when both header cells are at most three words
  without a digit, at least three data rows all have two fields, and a data cell holds a digit;
  `Smith, John` lists, prose with a comma per line and all-word tables such as `name,city` still
  read as text. Measured on main with synthetic values: `phone,qty` with three rows: PHONE 85 ×3,
  now 100 ×3; `name,passport_number` with three rows: 0 findings, now 3 PASSPORT.
