### 🐛 Bug Fixes

- **phone (confidence from phone evidence):** a digit run's PHONE score came from line punctuation
  and keyword substrings rather than from anything saying it is a phone number: a tab, two commas,
  two semicolons or two pipes added +15, keywords were substring-matched on text including the match
  (`string` counted as `ring`, `network` as `work`, `hotel` as `tel`, `800` inside the digits) with
  full weight only in the line's own case, every ten-digit US/CA match passed the country check, and
  a quoted run failed the structural gate. Go's FNV offset basis after a tab scored 100 HIGH,
  `Ricardo 297-201-0001` 50 and `{"phone": "2972010001"}` 5. Confidence now comes from whole-word
  phone words and phrases (`phone`, `tel`, `fax`, `call`, `phone number`, `direct line`,
  `phoneNumber`, ...) outside the match in any case, a phone label on the value, a phone column
  header and a formatted toll-free area code; a match nothing corroborates is held to 85 and a
  reserved fictional number to 15, both published as `confidence_ceiling` so the document bridge's
  +20 for a CSV cannot lift them; a quoted value counts when something names it a phone; and a
  ten-digit number the North American plan cannot assign keeps its finding but loses the +5, the
  passed `valid_country` check and the `US/CA` label. Which findings are reported is unchanged, so
  no value is left unredacted, format-preserving output is byte-identical and v2 suppression rules
  keep matching; legacy v1 rules hash confidence, so their findings resurface. Where a PHONE finding
  shares its bytes with another type's, the `simple` label and the `synthetic` value now follow the
  higher-confidence type (`Checking account number 2972030405 at the bank` reads
  `[US_BANK_ACCOUNT-REDACTED]`, was `[PHONE-REDACTED]`). Measured main vs branch: Go 1.27.3 stdlib
  (203 files, 4,638 findings both) HIGH 1,545 → 0, and the pre-commit hook exits 0, was 1, on
  `hash/fnv/fnv.go`, `math/const.go` and `compress/flate/deflatefast.go`; a 4,800-value non-phone
  sweep HIGH 2,000 → 0; a 620-label recall set at MEDIUM or above 558 → 616; `415-555-0123` in a
  `name,phone,city` CSV 35 → 15 ([#882](https://github.com/awslabs/ferret-scan/issues/882)).
