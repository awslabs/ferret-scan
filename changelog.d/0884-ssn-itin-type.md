### 🚀 Features

- **ssn (ITIN):** the SSN validator now reports IRS Individual Taxpayer Identification Numbers as a
  new type, `ITIN`, under `--checks SSN`, as the credit-card validator reports `VISA`. Every area of
  900 or above was rejected as an invalid SSN, so `ITIN: 912-70-3456`, `SSN: 912-70-3456` and
  `Taxpayer ID: 912-70-3456` reported nothing and stayed in cleartext under `--enable-redaction`: 60
  seeded ITINs were 0/60 in each display form and are 60/60 now (HIGH when labelled, MEDIUM as a
  bare `9XX-XX-XXXX`). A separated `9XX-XX-XXXX` or `9XX XX XXXX` is always checked, nine bare digits
  only under an `ITIN` or `Individual Taxpayer Identification Number` label; that gate adds 0
  findings on the Go 1.27.3 tree and the Go module cache (26,858 files) and on 400 Chilean mobiles
  (`+56 9XXXXXXXX`), where accepting every form added 70 and 168. The SSA advertising block
  `987-65-4320`..`4329` and `999-99-9999` are never reported. No existing finding changes type, text,
  line, confidence or suppression hash; `ITIN` is a new SARIF `ruleId`, and a HIGH-gated pre-commit
  hook can now fail on a labelled ITIN ([#884](https://github.com/awslabs/ferret-scan/issues/884)).
- **redaction (synthetic):** a synthetic SSN no longer draws a 9xx area with an ITIN group: with the
  old generator 63-80 of 300 synthetic replacements re-detected as `ITIN`, now 0
  ([#884](https://github.com/awslabs/ferret-scan/issues/884)).
