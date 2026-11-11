### 🐛 Bug Fixes

- **personname:** a name that appears on one line both bare and inside a longer match
  (`Signed by John Smith, witnessed by Dr. John Smith.`) is now reported twice, so the bare copy is
  redacted too. Overlapping matches were deduplicated by comparing TEXTS, which dropped the bare
  occurrence as "contained" in the titled one wherever it sat; containment is now by span, and the
  occurrence inside `Dr. John Smith` still collapses into it. On the issue's fixture `main` left 2
  of 2 names in clear under `simple`, `format_preserving` and `synthetic` (re-scan: 2 survivors);
  now 0 under all three in `.txt`, `.docx`, `.doc`, `.xls` and `.ppt`. With the titled copy first
  on the line, `.txt` is fully masked and the OOXML and legacy Office writers refuse the file
  (naming `PERSON_NAME`) where `main` wrote the name in clear and reported success.
  ([#966](https://github.com/awslabs/ferret-scan/issues/966))
