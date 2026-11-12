### 🚀 Features

- **passport (national shapes):** `PASSPORT` reports a German passport number with a digit second
  (`C1234567K`, and older numbers with a `0` such as `C01X00T47`) and the current Canadian series
  of 1 letter, 6 digits and 2 letters (`R123456KX`), at 100 under `Passport Number:`, in prose
  (`my passport no is ...`), in a passport CSV column and under a label on the line above (90)
  ([#888](https://github.com/awslabs/ferret-scan/issues/888)). Both need the passport label right
  before the value, in any letter case: with only the existing context rules 12 of the issue's 12
  national decoys (`passport scanner model L1024N160`, `passport kiosk S482071US`, ...) reported at
  77.5-100; behind the label, none. A value that fits both shapes (`R123456KX`) is the Canadian
  bucket's. A German number with a letter second stays `EU`. The French shape is not added: no
  primary source for its layout was found. ⚠ `metadata.country` gains two values, `Germany` and
  `CanadaCurrent`; it names the shape bucket, not the issuing state. Clean files can report new
  findings.
