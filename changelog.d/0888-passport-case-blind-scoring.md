### 🐛 Bug Fixes

- **passport (scoring):** a passport number containing a letter now gets the same passport-keyword
  boost as a 9-digit one ([#888](https://github.com/awslabs/ferret-scan/issues/888)). The proximity
  boost searched for the original-case value in the lower-cased line, so `GK123456` or `C12345678`
  never earned it, and the same-line keyword boost searched for `passport` in the original-case line,
  so `Passport` and `PASSPORT` earned less than `passport`. On 15 sentence pairs that differ only in
  the number, the letter-bearing value's `context_impact` was 10 to 20 points below its 9-digit
  twin's in 10 and the value was not reported at all in 4 (`She showed passport GK123456 at the
  border.` among them), so it stayed in cleartext under `--enable-redaction`; now all 15 match their
  twin and all are reported. Upgrade notes: confidence only rises, never falls, and the reported
  text, line and type are unchanged, so current (v2) suppression rules keep matching; legacy v1
  rules, which hash the confidence, stop matching a finding whose confidence moved. IDs already
  reported beside a passport label rise as well, some into HIGH: measured, `passport kiosk K12345678
  offline` 87.5 to 100, `passport office ticket INC482071 closed` 87.5 to 97.5, `Customer Passport
  100000001 on booking` 85 to 92.5. The negative-keyword check stays case-sensitive on purpose.
