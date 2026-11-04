### 🐛 Bug Fixes

- **bankaccount (IBAN):** IBANs printed in groups of four are now found before a short word, with
  hyphens or two spaces between groups, and for all 89 SWIFT IBAN Registry countries
  ([#862](https://github.com/awslabs/ferret-scan/issues/862)). A spaced IBAN followed by a word of
  1-4 characters (`IBAN: <IBAN> BIC: <BIC>`, ` EUR`, ` for payroll`, ` 2026`) was dropped for the 29
  countries whose IBAN length is a multiple of 4, so redaction masked the BIC and left the IBAN in
  cleartext at exit 0; hyphen-, en-dash- and double-space-grouped IBANs were never found, and the 15
  registry countries missing from the hand-written list (EG, RU, OM, SO and eleven more) were never
  reported in any form. On the issue's sweep (one IBAN per registry country per form), every form
  now reports 89 of 89, where main reported 74, 45 or 0; the issue's 14-IBAN repro reports 14 instead
  of 4, and stdin redaction leaves none of them in cleartext instead of 10. A value joined by `_` is
  reported when its identifier names it (`iban_DE89…`) and not otherwise (`statement_DE89….pdf`). The
  country table is now generated from the registry, with a drift check.
- **bankaccount (IBAN):** an IBAN candidate must also match its country's registered BBAN structure
  (which positions are digits, letters or either), so values that pass mod-97 but cannot be an IBAN of
  their country are no longer reported: 195 of 20,000 seeded letter-bearing `DE` tokens and 13 rows of
  a seeded 4 MiB `xxd` dump were reported at 85 on main, and none is now; on 300,000 seeded grouped
  licence keys the count goes from 209 to 48. A suppression rule written against one of those values
  now matches nothing; no other IBAN finding changes its text, span or confidence.
