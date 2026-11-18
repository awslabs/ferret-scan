### 🚀 Features

- **passport (national shapes):** `PASSPORT` reports a German passport number with a digit second
  (`C1234567K`, and older numbers with a `0` such as `C01X00T47`), the current Canadian series of
  1 letter, 6 digits and 2 letters (`R123456KX`) and the French 2 digits, 2 letters and 5 digits
  (`12CF34567`, the layout France Titres (ANTS) states), at 100 under `Passport Number:`, in prose
  (`my passport no is ...`) and in a passport CSV column, and at 90 under a label on the line above
  ([#888](https://github.com/awslabs/ferret-scan/issues/888)). All three need the passport label
  right before the value, in any letter case: with only the existing context rules 12 of the
  issue's 12 national decoys (`passport scanner model L1024N160`, `Passport renewal invoice
  24FR00317`, ...) reported at 77.5-100; behind the label, none. A value that fits both the German
  and the Canadian shape (`R123456KX`) is the Canadian bucket's. A German number with a letter
  second stays `EU`. ⚠ `metadata.country` gains three values, `Germany`, `CanadaCurrent` and
  `France`; it names the shape bucket, not the issuing state. Clean files can report new findings.
