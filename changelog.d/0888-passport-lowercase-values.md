### 🚀 Features

- **passport (letter case):** a passport number written with lowercase letters (`gk123456`,
  `Gk123456`, `de1234567`) is now detected and redacted when a passport label sits right before it
  ([#888](https://github.com/awslabs/ferret-scan/issues/888)). The US, Canadian and EU shapes matched
  `A-Z` only, so 0 of 13 labelled lowercase or Title-case values were reported by any validator, and
  `printf 'Passport Number: GK123456\nPassport Number: gk123456\nPassport Number: Gk123456\n' |
  ferret-scan --stdin --enable-redaction --checks PASSPORT` masked the first line only. Now 12 of 13
  are reported, with the confidence and bucket of their uppercase twin, and all three lines are
  masked. A value containing a lowercase letter is reported only when a passport label ends at most
  50 bytes before it (`Passport Number:`, `passport_number:`, `passport no is`, `showed passport`),
  its CSV column header names a passport, or it begins the line under a passport field label, and
  it is not a placeholder (`redacted1`, `tbd123456`, `invalid01`). Without that gate the same change reported 19
  false positives in 10 of 12 decoy files that mention passport near a lowercase id (logs, a
  `passport.js` comment, a `.../passport:v20241012` image tag) and all 9 labelled placeholders at
  85; with it, none. Not covered: a lowercase value whose label comes after it. Uppercase values,
  uppercase placeholders and the MRZ (uppercase only, per ICAO 9303) are unchanged. Letters are
  ASCII only: the patterns spell `[A-Za-z]`, not `(?i)`, which in Go also matches U+212A (Kelvin
  sign) and U+017F (long s).
