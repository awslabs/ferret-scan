### 🐛 Bug Fixes

- **creditcard (bare digit run with no card word):** a Luhn-valid 13-19 digit run with no group
  separators and no keyword on its line scored 95 HIGH on its digits alone, because
  `calculateConfidence` adds +15 for a known vendor prefix, +10 for non-repeating digits and +10
  for entropy to a base of 60 and nothing required card context for HIGH; one random run in ten
  passes Luhn, so request counters and row counts were reported as confirmed cards. Such a run is
  now held to MEDIUM 75 unless a card word names it on its line, inside an identifier on the line
  (`cardNumber`, `card_number`) or in its CSV column header; group-separated PANs and lines with a
  negative keyword score as before. The ceiling is published as `confidence_ceiling`, so the
  document bridge cannot lift it back: an unknown-vendor counter in a CSV row that the validator
  scored 70 was reported at 90 HIGH on main and is 75 MEDIUM now. The value is still reported and
  redacted. Measured main vs branch: the issue's `Row counter reached 4145723220667500` and bare
  13/14/15/19-digit counters 95 HIGH → 75 MEDIUM; `card: 4145723220667500` (100),
  `4145 7232 2066 7500` (95), `{"cardNumber": "4532015112830366"}` (95) and a `card_number` CSV
  column (100) unchanged; golden corpus and `make score` unchanged
  ([#802](https://github.com/awslabs/ferret-scan/issues/802)).
