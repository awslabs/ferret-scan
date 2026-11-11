### 🚀 Features

- **pkg/scan**: `RedactFile` on a format that refuses the requested strategy (synthetic on legacy
  `.doc`/`.xls`/`.ppt`, audio or video) now returns an error for which
  `errors.Is(err, scan.ErrStrategyNotSupported)` is true, so a library caller can pick another
  strategy without matching the message. Every other failure leaves it false (a cancelled scan is
  `ErrIncomplete` only), and the message text is byte-identical to v2.6.0's.
  ([#863](https://github.com/awslabs/ferret-scan/issues/863))
