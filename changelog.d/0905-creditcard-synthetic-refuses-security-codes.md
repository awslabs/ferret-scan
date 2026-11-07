### ⚠️ Breaking Changes

- **creditcard (track data and security codes):** with `--redaction-strategy synthetic`, a file or
  `--stdin` input holding a labelled security code is now refused instead of written with the code
  in cleartext: the synthetic card generator keeps a value's first four digits, so it writes a
  three- or four-digit code back unchanged and the output check refuses the result (a file is listed
  as not redacted and `--stdin` exits 1; `pkg/redact` still returns the code unchanged). A frame
  under `synthetic` keeps its Track 1 name and gets random digits after its first four, which on 300
  measured Track 2s left a Luhn-valid PAN in 33. `--pre-commit-mode` now blocks a commit holding a
  Track 1, a Track 2 or a tag 57 value, which score 100 HIGH (a bare Track 2 PAN is 75 MEDIUM and
  did not); a labelled code takes its card's score, and one with no card within three lines is 40
  LOW and does not block. A rule that suppresses a Track 2 PAN still suppresses it; the Track 2
  frame on the same line is a new finding
  ([#905](https://github.com/awslabs/ferret-scan/issues/905)).
