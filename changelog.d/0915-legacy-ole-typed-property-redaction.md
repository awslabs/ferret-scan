### 🐛 Bug Fixes

- **redaction (legacy .doc/.xls/.ppt):** a reported number, date or flag stored as a typed property
  (a custom property of type Number is a VT_I4, Date a VT_FILETIME) is now overwritten with zeros in
  its property set, and the copy is checked before it is written: a reported value the redactor
  finds in no stream, or one still readable after the overwrite, refuses the file with the cause in
  `stats.files_not_redacted`, the not-redacted warning and a failing `--fail-on-incomplete`. Such a
  value has no text in the stream, so it was never overwritten and the copy was reported as
  redacted; on the public `govdocs1--000696.doc` a 10-digit VT_I4 custom property was reported again,
  byte for byte, by a re-scan of the copy under both strategies. That re-scan now reports 0 of the
  original 26 findings (was 1, plus 6 findings on masked fields). A property value that is only the
  `*` mask is no longer collected as metadata, so a redacted copy no longer yields
  `Author: *****`-style findings ([#915](https://github.com/awslabs/ferret-scan/issues/915)).
