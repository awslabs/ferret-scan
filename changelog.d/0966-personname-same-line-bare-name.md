### 🐛 Bug Fixes

- **personname:** a name that appears on one line both bare and inside a longer match
  (`Signed by Jane Doe, witnessed by Dr. Jane Doe.`) is now two findings, so the bare copy is
  redacted too. Overlapping matches were deduplicated by comparing TEXTS, which dropped the bare
  occurrence as "contained" in the titled one wherever it sat; containment is now by span, and the
  occurrence inside `Dr. Jane Doe` still collapses into it. On the issue's fixture `main` left 2
  of 2 names in clear under `simple`, `format_preserving` and `synthetic` (its re-scan reports both
  again); now 0 in `.txt` and `.docx` under all three and in `.doc`, `.xls` and `.ppt` under the two
  they offer. With the titled copy first on the line, `.txt` is fully masked and the OOXML and
  legacy Office writers refuse the file (naming `PERSON_NAME`) where `main` wrote the name in clear
  and reported success. The same text comparison also dropped a name contained in a longer,
  different one anywhere on its line (500 of the 15,931 names on a 256 KiB line of distinct names,
  each a surname prefix of another), and cost O(n²) per line: that line took 35.8 s on `main` and
  5.8 s now.
  ([#966](https://github.com/awslabs/ferret-scan/issues/966))
