### 🐛 Bug Fixes

- **office (text extraction, redaction):** a paragraph is now a boundary the validators respect. The
  Office reader ended a slide's paragraph and an OpenDocument paragraph with a space, so a name at the
  end of one paragraph and a capitalised word at the start of the next were reported as one
  `PERSON_NAME` (`<first> <last> English`); it now ends them with a newline. Runs inside one paragraph
  and an `.ods`/`.ots` sheet's cells stay joined by a space, and `.docx`/`.xlsx` are unchanged. ⚠ The
  line numbers of findings in `.pptx`/`.pptm`/`.odp`/`.odt`/`.ott` files change (a slide was one line;
  it is now one line per paragraph), so a baseline or suppression keyed on a line number in those files
  is re-anchored; findings that crossed a paragraph change or disappear. The redactor's boundary map
  follows the reader. Part of
  [#914](https://github.com/awslabs/ferret-scan/issues/914).
