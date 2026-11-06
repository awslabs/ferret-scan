### 🐛 Bug Fixes

- **redaction (audit log):** audio, video and legacy Office entries in `--redaction-audit-log` now
  record what was written. Two findings sharing bytes in one tag (an email inside the comment it was
  reported in) are written as one `*` mask, and both entries now record that mask: they recorded
  each value's own rendering, `j*******@example.com` and `c***************@example.com`, 0 of 2 in
  the file. Where a `*` mask was written instead of a `format_preserving` rendering that keeps part
  of the value, the entry's `strategy` is the new audit-only `mask` and a new `requested_strategy`
  field names the strategy asked for; it said `format_preserving`. A value stored only as UTF-16 in
  a legacy Office file is recorded at the width written. These entries now carry the finding's
  `line`, as every other redactor's do. Redacted files are unchanged.
  ([#865](https://github.com/awslabs/ferret-scan/issues/865))
