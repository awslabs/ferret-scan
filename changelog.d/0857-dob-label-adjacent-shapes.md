### 🐛 Bug Fixes

- **dob (labelled dates of birth in standard shapes):** a date of birth directly after an explicit
  label is detected in the shapes that were missed: ISO 8601 date-times (`toISOString()` output; the
  finding is the date part, so redaction leaves `T00:00:00.000Z`), `1987/03/14`, `1987.03.14`,
  `1987-3-14`, Oracle's `14-MAR-1987` and `14-Mar-87`, SAS `14MAR1987`, `MARCH 14, 1987`,
  `Mar. 14, 1987`, `Sept`, `14th of March 1987` and `1987 March 14`. Before, the issue's six
  labelled dates gave 1 finding and `--enable-redaction` left five in cleartext; now 6 findings at
  90 and all six are redacted. These shapes are mostly timestamps and file names, so they are
  reported only when a DOB label (`Date of Birth:`, `DOB`, `{"dob": "`, `<DateOfBirth>`) ends at
  most 8 separator bytes before the value; the same value without such a label, or after
  `dob_updated_at`, `dobUpdatedAt` or `"dob": null, "createdAt":`, reports nothing. Labels are
  matched as labels, so camelCase keys (`dateOfBirth`, `DateOfBirth`, `patientDob`, `memberDOB`)
  score 90 instead of 5, and `D.O.B.: 03/14/1987, blood sample collected` is no longer dropped by
  the synthetic-data rule, whose own label list lacked `d.o.b` (a marker before the label still
  suppresses: `Test D.O.B.:`, `Test dateOfBirth:`). Measured on main vs this branch: the issue's
  45-shape matrix under four contexts, 64 to 136 findings (16 of 43 English shapes to 38, plus both
  `Sept` forms, all at 90 after a label; unlabelled values unchanged); 1,726 text files (Go
  toolchain testdata and this repository's Markdown, 1,717 scanned), 163 DOB findings and 1,889 of
  every type, identical; 31 decoys, identical except the labelled DOB on `Name: Jane Doe, DOB:
  14-MAR-1987, Last visit: 2024-03-14T09:00:00Z` (the visit timestamp is still not reported). Every
  value the old patterns matched keeps its text, line and context, so its suppression hash is
  unchanged. A camelCase-keyed finding moves from LOW to HIGH, so a pre-commit gate at `high` can
  newly fail on one, and a legacy v1 rule (which hashes the confidence) written at 5.00 must be
  regenerated. On a `birthdate` line the SARIF `positiveKeywords` now also lists `birth date`
  ([#857](https://github.com/awslabs/ferret-scan/issues/857)).
