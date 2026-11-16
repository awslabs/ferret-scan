### 🐛 Bug Fixes

- **passport (MRZ):** a passport's second MRZ line (document number, date of birth, sex, expiry) is
  now reported and redacted when its personal-number field is unused and the issuing State prints
  `<` rather than `0` as that field's check digit, which ICAO Doc 9303 Part 4 (4.2.2.2, position
  43) allows ([#1010](https://github.com/awslabs/ferret-scan/issues/1010)). The check-digit gate
  wanted `0` there, so such a line 2 was never reported: `--enable-redaction` masked line 1 (the
  name) and left line 2 in clear. `<` is accepted only there and only when positions 29-42 are all
  fillers; it is still rejected for every other check digit and beside a non-empty personal number.
