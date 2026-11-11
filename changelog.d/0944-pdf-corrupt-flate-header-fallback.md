### 🐛 Bug Fixes

- **PDF text extraction**: a PDF whose cross-reference stream or object stream has a corrupt 2-byte
  zlib header is now read instead of skipped. The extractor rewrites each invalid FlateDecode header
  in an in-memory copy (same length, so offsets hold) and retries; the issue's synthetic
  `xref_bad.pdf` and `objstm_bad.pdf` went from 0 findings and "PDF library panic ... zlib: invalid
  header" to the same EMAIL finding as the intact file. Where the stream body is damaged too, the
  disclosure now names the unreadable part ("cross-reference section unreadable", "document catalog
  or page tree unreadable") instead of "PDF library panic".
  [#944](https://github.com/awslabs/ferret-scan/issues/944)
