### 🐛 Bug Fixes

- **redaction (audio, video, legacy Office):** `--redaction-strategy simple` now writes a same-length
  `*` mask of every value in `.mp3 .wav .flac .m4a .mp4 .m4v .mov .3gp .3g2 .doc .xls .ppt`, as its
  documentation promises ("nothing from the original value is preserved"). It used to write the
  `format_preserving` rendering, byte-identical to it: on all twelve extensions, 36 of 36 values kept
  a card's last four digits, an email's first character and domain, or a phone's last four, at exit
  0. `format_preserving` output is unchanged. **`synthetic` is now refused** on audio and video files
  with findings, and on a legacy Office file embedded in a `.docx`/`.xlsx`/`.pptx` (with its
  container): no output is written, the run names the file under `redaction incomplete` with the
  strategies it takes, it counts in `files_not_redacted`, and `--fail-on-incomplete` exits 3. It used
  to be written as a same-length `*` mask at exit 0 while the audit log and
  `RedactFileResult.Strategy` said `synthetic`. A top-level `.doc`/`.xls`/`.ppt` is still written with
  that mask under `synthetic`. The image redactor now declares all three strategies, which it always
  handled identically. ([#863](https://github.com/awslabs/ferret-scan/issues/863))
