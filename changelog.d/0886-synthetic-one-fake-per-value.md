### 🐛 Bug Fixes

- **redaction (synthetic):** `--redaction-strategy synthetic` now gives a value ONE fake for the whole
  run, in every file and format, and never gives two values the same one. Every occurrence used to be
  drawn on its own: an SSN written four times in a `.txt` became four different SSNs (also on
  `--stdin`, `.svg` and `.rtf`), and the documented CSV-directory recipe gave one customer's SSN three
  fakes across two files, so an SSN or email join returned 0 of 3 rows; it now returns 3. Spellings of
  one value share its fake in their own shape (`234-56-0001` and `234 56 0001`; `(312) 555-0142` and
  `+1 312 555 0142`; an email in any case; `Torres, Michael`, `MICHAEL TORRES` and `Michael Torres`,
  which keep their order, comma and case). A second run draws new fakes; `--stdin`, a `pkg/scan` call
  and each `pkg/redact` request are a run of their own. A `.docx` audit log now records the
  replacement written (8 of 8 `redacted_text` values occur in the file, was 3 of 8). A race in loading
  the name database wrote `[PERSON-NAME-REDACTED]` for 6 to 7 of 24 copies of one name at exit 0; it
  is gone, and a database that cannot load is an error instead of that placeholder. A synthetic IP
  address can now be anywhere in RFC 1918 (`10.`, `172.16-31.`) when `192.168.0.0/16` is used up, and
  a local part shorter than four characters gets four. When a type has no unused fake left the file is
  refused (`files_not_redacted`, exit 3 with `--fail-on-incomplete`) instead of reusing one.
  `simple` and `format_preserving` output is byte-identical.
  ([#886](https://github.com/awslabs/ferret-scan/issues/886))
