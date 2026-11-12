### 🐛 Bug Fixes

- **medicalid (published example NPI):** `1234567893`, the worked example of CMS's NPI check-digit
  specification, is reported as `NPI` at LOW 15 instead of 90-100 HIGH (`NPI: 1234567893` read 90,
  `Provider NPI: 1234567893 on the claim.` 100). It publishes `confidence_ceiling: 15`, so no document
  adjustment lifts it, and records `not_published_example: false` in `validation_checks`. The value is
  capped, never dropped, so it is still redacted. Every other NPI keeps its score, including the
  NPI-Luhn-valid `1234567885`. ([#930](https://github.com/awslabs/ferret-scan/issues/930))
- **phone (Manchester drama block):** Ofcom's Manchester drama block `0161 496 0000`..`0999`,
  nationally or as `+44`/`0044`, `(0)` included, is held at LOW 15 with the ceiling published, like the
  London, no-area and mobile blocks: `Phone: 0161 496 0815` read `PHONE` 100 and now reads 15, still
  reported and redacted. `0161 497 0000` and `0161 496 1000` keep their 100. The other area blocks Ofcom
  publishes (0113-0118, 0121, 0131, 0141, 0151, 0191, 028, 029) are not capped yet.
  ([#930](https://github.com/awslabs/ferret-scan/issues/930))
