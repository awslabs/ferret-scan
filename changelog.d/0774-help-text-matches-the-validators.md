### 📚 Documentation

- **help (`--help <check>`):** the Contextual Analysis section no longer prints "up to +25% or -50%
  adjustment", "+5% each" and "-10% each" for every check. No check scores that way: VIN adds 25 and
  takes 15 per keyword within +/-50, and PHONE adds 15 and takes 35 within -80/+40. The section now
  lists the keywords and leaves the weights to each check's own description
  ([#860](https://github.com/awslabs/ferret-scan/issues/860),
  [#882](https://github.com/awslabs/ferret-scan/issues/882)).
- **help (`DRIVERS_LICENSE`, `BANK_ACCOUNT`, `MEDICAL_ID`):** `--help DRIVERS_LICENSE` no longer says
  it detects US numbers "from the top 10 states" and lists the 11 shapes it reports under the `format`
  value a finding carries: New Jersey and Wisconsin were implemented and missing, and GB DVLA, Ontario
  and Quebec were added by [#861](https://github.com/awslabs/ferret-scan/issues/861). It also says
  that `format` names the shape, not the issuing state. `--help BANK_ACCOUNT` says 89 SWIFT IBAN
  Registry countries checked for registry length, BBAN structure and mod-97
  ([#862](https://github.com/awslabs/ferret-scan/issues/862)) instead of "70+ country formats", and
  `--help MEDICAL_ID` lists seven types, UK NHS and Scottish CHI numbers included
  ([#859](https://github.com/awslabs/ferret-scan/issues/859)).
