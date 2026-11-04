### 🐛 Bug Fixes

- **redaction (audit log):** `--redaction-audit-log` now records what the run did, and its JSON
  changes for any parser of it. `ferret_version` (both levels) is the build's version instead of the
  literal `v1.0.0`. `redaction_summary.strategy` and each entry's `strategy` are names
  (`"format_preserving"`) instead of integers, and the summary's is set: it was `0` (which reads as
  `simple`) in every document. `processing_time`, always `0`, is replaced by `processing_time_ms`.
  An entry's `confidence` is the finding's detection confidence / 100 for every redactor: text files
  (and SVG and RTF) logged their placement score instead, `0.0095` for findings the report scored 15,
  61 and 100; that score is now `placement.score`, beside `placement.method`. Entries carry the
  finding's `line`. Image metadata removals are listed in `metadata_redactions`, one per EXIF field,
  instead of as `IMAGE_METADATA` content redactions at `0.01`, and an embedded part's redactions name
  it (`target_type: embedded_media`, `target_path: word/media/image1.jpeg`). The never-written
  `redaction_config` field is gone. Findings and redacted files are unchanged.
  ([#865](https://github.com/awslabs/ferret-scan/issues/865))
