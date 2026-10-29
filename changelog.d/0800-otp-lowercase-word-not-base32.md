### 🐛 Bug Fixes

- **otp (lowercase word as base32):** a lowercase English word of 16+ letters on a line that names
  MFA is no longer reported as an `OTP_SECRET`
  ([#800](https://github.com/awslabs/ferret-scan/issues/800)). The lowercase base32 pass uppercases
  a candidate and admits it on `isValidBase32`, which every all-letter string of 16–64 characters
  passes because every letter is in the base32 alphabet, while `isLikelyWord` knows only patterns
  and a short word list. Measured on main with `--show-match` on the issue's two lines:
  `responsibilities` 95 HIGH and `operationalizing` 70 MEDIUM; on similar lines
  `intellectualproperty` and the run-together `configurationsvalidators` scored 90 and
  `cryptographically` 85. Now a digit-free lowercase candidate whose letters are shaped like English
  (vowel share, `y` included, from 1/4 to 3/5 and no run of five consonants) is dropped, and all
  five report nothing. A value with a digit is never tested, so a lowercase secret with a digit
  scores as before (a generated 32-character one: 100 and 80 on the issue's lines), and the
  uppercase pass is unchanged. The cost is the rare digit-free random secret shaped like a word:
  about 0.7% of 16-character lowercase secrets and under 0.01% of 32-character ones, against 3.6% if
  a digit were required.
