### 🚀 Features

- **nationalid:** a new `NATIONAL_ID` check reports five Americas national identification numbers
  under types of their own: Brazil's CPF (`BR_CPF`), Chile's RUT/RUN (`CL_RUT`), Argentina's CUIL
  and personal CUIT (`AR_CUIL`), Canada's Social Insurance Number (`CA_SIN`) and Mexico's CURP
  (`MX_CURP`). A value is reported only beside its own label on the same line and only when its
  check digit and structure pass; a valid value with no label is not reported. Before this, the
  #884 new-hire file kept all five numbers byte for byte in its redacted copy. Redaction masks every
  letter and digit and keeps the separators (`format_preserving`), or writes a replacement in the
  same shape that fails the check digit, so the copy never re-detects (`synthetic`).
  ⚠ `--checks all` (the default) now runs `NATIONAL_ID`, so labelled CPF, RUT, CUIL, SIN and CURP
  values in a scanned tree are new HIGH findings, and a `--checks` list or config naming checks
  explicitly does not get them until it adds `NATIONAL_ID`.
  ([#884](https://github.com/awslabs/ferret-scan/issues/884))
