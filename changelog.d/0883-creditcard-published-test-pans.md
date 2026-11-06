### 🐛 Bug Fixes

- **creditcard (published test numbers):** the card numbers payment processors publish for their
  sandboxes are reported at LOW 15 with `not_test: false` instead of scoring like real cards. An
  exact-value list, `internal/validators/creditcard/published_test_pans.go`, holds the 492
  Luhn-valid values the testing pages of Adyen, Authorize.net, Braintree, Checkout.com, Square and
  Stripe print, each block citing its page and the date it was read; a listed value is capped,
  never dropped, and publishes `confidence_ceiling: 15` so no document adjustment lifts it. Measured
  over the 492 values: on `Card number:` lines 386 scored 100 HIGH and none do now, in JSON fixtures
  453 HIGH became 0 and in CSV rows 457 became 0, while a same-BIN random control for each value
  keeps its score. Findings are still reported and redacted (redacted output byte-identical) with
  unchanged current-format suppression hashes; a legacy rule that hashed the old confidence stops
  matching, and its finding reappears at LOW. `--profile precommit` now passes a fixture that holds
  only published numbers and still blocks one that also holds a real-shaped card. The same
  published ceiling now holds test-pattern literals and repeating shapes, which a CSV export lifted
  from 15 to 35 ([#883](https://github.com/awslabs/ferret-scan/issues/883)).
