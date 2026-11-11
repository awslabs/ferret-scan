### 🐛 Bug Fixes

- **ssn, passport (byte counts, passport labels):** a nine-digit value whose own context says what
  else it is no longer reads HIGH. A bare nine-digit run followed by a byte unit (`bytes`, `-byte`,
  `B`, `KiB` and the rest of the IEC and SI family) is reported as `SSN` at no more than LOW 55,
  the ceiling the validator already gives a value whose column header names another identifier,
  and it publishes that ceiling so no document adjustment lifts it; the passport validator no
  longer reports it at all. A value labelled as a passport number, on its line or by a
  `Passport Number` field label on the line above, is held to the same ceiling as an `SSN` unless
  an SSN label is on its line, and keeps its `PASSPORT` finding. Measured on this repository's own
  lines: 4 `SSN` findings at 95 HIGH and 1 `PASSPORT` at 90 HIGH become `SSN` LOW 55 and no
  passport finding, while every value is still reported and redacted; a labelled SSN, hyphenated or
  bare, and a labelled passport number keep their score
  ([#939](https://github.com/awslabs/ferret-scan/issues/939)).
