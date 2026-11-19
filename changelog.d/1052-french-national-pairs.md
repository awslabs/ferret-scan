### 🐛 Bug Fixes

- **phone:** a French national number written as a `0`, a digit 1-9 and four pairs with ONE separator,
  a space, a dot or a dash (`01 42 34 56 78`, `01.42.34.56.78`, `01-42-34-56-78`), is now reported and
  reads the confidence the compact `0142345678` and `+33 1 42 34 56 78` read (100 with a phone label).
  Before, none of the three spellings produced a finding, so they stayed in clear under
  `--enable-redaction`. ARCEP's reserved fiction blocks hold at LOW 15 in these spellings too
  (`01 99 00 47 18`). A mixed separator (`01 42.34 56-78`), a sixth pair (`01.42.34.56.78.90`) and a
  missing one stay unreported. ⚠ A run that scans text with such numbers now reports (and redacts)
  them, so finding counts rise on French documents; so does a date-like `01.02.03.04.05`, as it
  already did when written compact. ([#1052](https://github.com/awslabs/ferret-scan/issues/1052))
