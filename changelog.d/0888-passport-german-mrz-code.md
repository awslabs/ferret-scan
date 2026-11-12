### 🐛 Bug Fixes

- **passport (MRZ):** a German passport MRZ, whose issuing state is `D<<` (ICAO Doc 9303 Part 3
  gives Germany the one-letter code `D`), is now reported on line 1 as well as line 2
  ([#888](https://github.com/awslabs/ferret-scan/issues/888)). Line 1 carries the holder's name and
  matched nothing, so under `--enable-redaction` it stayed in clear while line 2 was masked; it now
  scores 80 as `MRZ_TD3`, like the `FRA` twin. A German line 2 scores 85 like `FRA`'s and `CAN`'s
  instead of 75. Identity-card MRZs (TD1, TD2) are still not reported as `PASSPORT`.
