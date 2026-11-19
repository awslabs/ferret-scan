### 🚀 Features

- **nationalid:** the `NATIONAL_ID` check gains a sixth type, Mexico's RFC (`MX_RFC`, a company's 12
  characters or a person's 13), verified by the SAT's check-digit table; the SAT's two generic RFCs
  (`XAXX010101000`, `XEXX010101000`) are reported at LOW (15). A labelled value of the right shape
  whose check digit fails is now reported at LOW (40) with `checksum_valid=false`, instead of not at
  all, so it is still redacted. A Chilean RUT is read with no separators (`RUT: 123456785`).
  ⚠ New findings: labelled check-failing CPF, RUT, CUIL, SIN, CURP and RFC values, and every RFC under
  an `RFC` label, appear in a scan (LOW, so a `--confidence high,medium` gate does not see them), and
  `--checks NATIONAL_ID` output gains the `MX_RFC` type and the `checksum_valid` metadata key.
  ([#884](https://github.com/awslabs/ferret-scan/issues/884))
