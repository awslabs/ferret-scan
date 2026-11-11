### ⚠️ Breaking Changes

- **creditcard (types):** a whole card track (Track 1, Track 2, EMV tag 57) is now reported as
  `CARD_TRACK_DATA` and a labelled card security code as `CARD_SECURITY_CODE`, instead of the PAN's
  brand type (`VISA`, ...) and `CREDIT_CARD` with `metadata.card_frame`
  ([#905](https://github.com/awslabs/ferret-scan/issues/905)). `--checks CREDIT_CARD` still reports
  both, `card_frame` is unchanged and `card_type` still names the brand; a frame finding no longer
  carries `vendor`. The `simple` strategy writes `[CARD_TRACK_DATA-REDACTED]` and
  `[CARD_SECURITY_CODE-REDACTED]` for them instead of `[CREDIT-CARD-REDACTED]`. A suppression rule
  written in v2.6.0 for a frame or code finding hashes the old type and stops matching (38 of the
  issue's 118 findings): regenerate it. Brand findings for the PAN itself are unchanged.
