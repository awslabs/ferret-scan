### 🐛 Bug Fixes

- **redaction (legacy .doc/.xls/.ppt, format_preserving):** every occurrence of a reported value is
  now overwritten, overlapping ones included. The overwrite resumed after the bytes it had just
  written, so an occurrence starting inside the previous one was skipped; `simple`'s mask destroyed
  it anyway, but the format-preserving rendering keeps the value's last characters, and the skipped
  occurrence could be left exactly as it was while the file was reported as redacted. On the public
  `poi--PPT95.ppt` a 9-digit value reported as SSN, stored in a repeating binary pattern, survived
  18 times in the `format_preserving` copy; it now survives 0 times, and the `simple` copy is
  byte-identical to before ([#916](https://github.com/awslabs/ferret-scan/issues/916)).
