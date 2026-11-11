### 🐛 Bug Fixes

- **redaction (Office/OpenDocument values across text nodes):** a value the scanner reports across a
  boundary between text nodes of an `.xlsx`/`.xlsm`, `.pptx`/`.pptm` or OpenDocument file is now
  rewritten in every node it covers, and a copy that would still carry one is refused instead of
  written ([#914](https://github.com/awslabs/ferret-scan/issues/914)). The scanner joins a slide's runs
  and an OpenDocument paragraph or cell with a space and a sheet's cells with a tab, so a name in one
  paragraph and a word in the next read as one PERSON_NAME and three numeric cells as one PHONE; the
  redactor looked for the value inside one node, found none, rewrote nothing and reported success.
  Measured on v2.6.0 over the public corpus: 65 such values left in the copies of four files, each
  written at exit 0 with nothing in `stats.files_not_redacted`; now 0, under `simple` and
  `format_preserving`. `simple` writes its token in the first node and removes the rest of the value
  from the others; a same-length mask is cut at the node boundaries, so a masked cell keeps its width.
  A covered worksheet cell is rewritten as an inline string, so a shared string other cells show is
  not edited. Every copy is now read back through the scanner's own Office reader before it is
  written; a value it still finds (one spanning a Word `<w:tab/>`, for instance, which is not
  rewritten yet) refuses the file as `reported value not found in the writable bytes`, so it is listed
  in `stats.files_not_redacted`, the not-redacted warning prints, and `--fail-on-incomplete` exits 3.
  Findings are unchanged (golden corpus and `make score` identical).
