### ⚡ Performance

- **redaction (Office documents):** redacting a `.docx`, `.xlsx` or `.pptx` no longer searches the
  document's whole extracted text once per distinct reported value, twice (to find where the value
  lives, and again to find which parts still hold it). Both questions are now answered for every
  value in one pass, so the cost grows with the document instead of with values times document size
  ([#1054](https://github.com/awslabs/ferret-scan/issues/1054)). On a synthetic file with one distinct
  email per finding the redaction step took 0.73 s at 8,000 values and 2.41 s at 16,000 (3.3x per
  doubling); it now takes 0.22 s and 0.44 s (2.0x). The redacted copies and the audit log are
  byte-identical to the previous release's.
