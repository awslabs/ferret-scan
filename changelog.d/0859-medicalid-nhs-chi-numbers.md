### 🚀 Features

- **medicalid (UK NHS and Scottish CHI numbers):** new `MEDICAL_ID` subtypes `NHS_NUMBER`
  (England, Wales, Isle of Man; Northern Ireland's H&C number shares the format) and `CHI_NUMBER`
  (Scotland), reported only beside a label bound to the value
  ([#859](https://github.com/awslabs/ferret-scan/issues/859)). No type owned them before: a
  labelled NHS number was reported only as a US/CA `PHONE`, so format-preserving redaction kept its
  last four digits, and `CHI number: 150100 0004`, `{"nhsNumber": "9990000018"}` and
  `{"chiNumber": "1501000004"}` reported nothing and stayed in cleartext under
  `--enable-redaction`. A bound value with a valid mod-11 check digit (and, for a CHI, a real DDMMYY
  date) scores 90; one that fails either is reported at 40 or less, not dropped. The bindings are a
  label or key right before the value (`NHS number:`, `nhs_number`, `nhsNumber`, `<chiNumber>`), its
  column header, a label line above, the FHIR system `https://fhir.nhs.uk/Id/nhs-number` and HL7
  `^^^NHS^NH`; a bare `NHS` or `CHI` never binds, because the check digit alone passes 9.09% of
  random 10-digit strings and every numeric ISBN-10. NHS England's never-issued `999` range and
  repdigits are capped at 15 with `confidence_ceiling`. `PHONE`, `MRN` and `NPI` findings are
  unchanged, and a value they share with an NHS or CHI finding is now masked in full. Measured on
  the issue's 17 cases: every one reports its new type (the `999` ones at 15) and nothing in
  cleartext; on 1,000 generated values per population every labelled layout is HIGH; `--checks
  MEDICAL_ID` on 25,511 real files and all checks on ferret's own tree are unchanged. The new
  findings appear unsuppressed once, since `Type` is part of the suppression hash.
