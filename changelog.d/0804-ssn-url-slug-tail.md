### 🐛 Bug Fixes

- **ssn (URL slug tail):** the nine-digit tail of a profile link such as
  `https://www.linkedin.com/in/michael-o-291135150` is no longer reported as a bare SSN
  ([#804](https://github.com/awslabs/ferret-scan/issues/804)). The candidate pattern's `\b` treats
  `-` and `/` as word boundaries, so the tail was admitted, and nothing read where the digits sat:
  alone on a line it scored 50 LOW, on a tab-separated résumé row the two-tab tabular boost (+25,
  uncapped on a table) took it to 95 HIGH in plain text and in a `.docx` alike, a CSV row reached
  100 HIGH, and a `Social:` label alone gave 95 HIGH. Measured on main with `--show-match`, the
  issue's own lines scored 50 and 30 LOW (its `example.com` address costs the row 65 points). Now a
  bare nine-digit run after `-` or `/` in the path of an `http://` or `https://` URL is a URL
  component and is not reported, and every one of those lines reports nothing. A value is still
  reported, at the same confidence, when the line or its column header names the identifier
  (`SSN`, `tax id`, `employee id`), when it is a query value (`?ssn=`), a fragment or a file name
  (`.pdf`), under `s3://`, `file://` or `ftp://`, in the next JSON or CSV field, in the dashed
  form, or when the same digits also stand alone on the line. Golden corpus and `make score`
  unchanged.
