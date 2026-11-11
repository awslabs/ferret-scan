### 🐛 Bug Fixes

- **redaction (card tracks):** `format_preserving` and `synthetic` no longer keep a Track 1's
  cardholder name (11 of the issue's 11 Track 1 files kept it; now 0), and `synthetic` no longer
  writes a Luhn-valid PAN into a frame: over 10 synthetic runs of the issue's 40 files, re-scanning
  the copies reported 24 card findings on v2.6.0 and 0 now. Synthetic also redacts the 11 files with a
  labelled security code, which it refused before (`files_not_redacted` 11 to 0)
  ([#905](https://github.com/awslabs/ferret-scan/issues/905)).
