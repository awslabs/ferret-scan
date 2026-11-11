### 🐛 Bug Fixes

- **bankaccount (published example IBAN):** `GB82 WEST 1234 5698 7654 32`, the worked example the
  Wikipedia IBAN article prints for a "fictitious United Kingdom bank", is reported as `IBAN` at
  LOW 15 instead of 100 HIGH, in its compact, spaced, hyphenated and lower-case spellings and
  whatever keywords surround it. It publishes `confidence_ceiling: 15`, so no document adjustment
  lifts it, and records `not_published_example: false` in `validation_checks`. The value is capped,
  never dropped, so it is still redacted. A mod-97-valid IBAN one account digit away, and every
  other IBAN, keep their score. Part of
  [#930](https://github.com/awslabs/ferret-scan/issues/930): the German example IBAN, the VINs and
  the CMS example NPI stay as they are until the golden and score fixtures that use them as real
  values are replaced.
