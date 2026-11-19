### 🐛 Bug Fixes

- **redaction (`--redaction-strategy synthetic`):** a synthetic SSN replacement is never a
  Luhn-valid nine-digit number any more ([#1020](https://github.com/awslabs/ferret-scan/issues/1020)).
  The 666 and 9xx areas the generator draws lead with 6 and 9, which the Canadian SIN check accepts,
  so about one draw in ten passed it and could re-detect as `CA_SIN` in the redacted copy. Measured
  on main over 100,000 draws: 10,111 were Luhn-valid and 7,597 of those lead with a digit a SIN may
  start with; now 0 of 100,000. A draw that would pass has its last digit moved, so the other nine in
  ten are exactly as before.
