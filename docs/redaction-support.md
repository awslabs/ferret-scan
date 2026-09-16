# Redaction support by file type

<!-- GENERATED FILE — do not edit by hand.
     Regenerate with:
       UPDATE_REDACTION_DOCS=1 go test ./internal/core/ -run TestRedactionSupportPageIsUpToDate
     The contents come from the live redactor registry in internal/core/redact.go, so this
     page cannot claim a capability the build does not have. -->

`--enable-redaction` writes a redacted copy of a file **of the same type**. Detection is
independent of this table: every type the scanner can read is scanned and reported whether or
not it can be rewritten.

## Cannot be rewritten

These types are recognised and **scanned**, and their findings are reported — but no redacted
copy is written. The file is named in the report with the cause `no redactor for this file
type`, and **no output is produced at all** rather than a copy that still holds the values.
That is deliberate: a file in a directory named `redacted` that still contains an SSN is the
artefact a user forwards.

| type | why |
|---|---|
| `.bmp` | image metadata redaction is implemented for JPEG and PNG only; other formats are recognised but refused rather than copied through with their metadata intact |
| `.gif` | image metadata redaction is implemented for JPEG and PNG only; other formats are recognised but refused rather than copied through with their metadata intact |
| `.pdf` | PDF content redaction is not implemented; findings are reported but the file cannot be rewritten, and no output is written rather than a copy that still holds the values |
| `.tif` | image metadata redaction is implemented for JPEG and PNG only; other formats are recognised but refused rather than copied through with their metadata intact |
| `.tiff` | image metadata redaction is implemented for JPEG and PNG only; other formats are recognised but refused rather than copied through with their metadata intact |
| `.webp` | image metadata redaction is implemented for JPEG and PNG only; other formats are recognised but refused rather than copied through with their metadata intact |

## Can be rewritten

- `.3g2`
- `.3gp`
- `.conf`
- `.csv`
- `.doc`
- `.docm`
- `.docx`
- `.flac`
- `.ini`
- `.jpeg`
- `.jpg`
- `.json`
- `.log`
- `.m4a`
- `.m4v`
- `.md`
- `.mov`
- `.mp3`
- `.mp4`
- `.odp`
- `.ods`
- `.odt`
- `.otp`
- `.ots`
- `.ott`
- `.png`
- `.ppt`
- `.pptm`
- `.pptx`
- `.rtf`
- `.svg`
- `.text`
- `.txt`
- `.wav`
- `.xls`
- `.xlsm`
- `.xlsx`
- `.xml`
- `.yaml`
- `.yml`

## Checking this from a script

A run that could not redact everything it reported says so on stderr and in the structured
output. In JSON the `unredacted` array carries one entry per such file, each with a `cause`
and a `detail`; the same disclosure appears in every other output format. Do not rely on the
exit code alone.
