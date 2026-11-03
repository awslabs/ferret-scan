### 🐛 Bug Fixes

- **otp (uppercase word as base32):** an English word of 16+ letters written in capitals on a line
  that names OTP or MFA is no longer reported as an `OTP_SECRET`
  ([#838](https://github.com/awslabs/ferret-scan/issues/838)). #800 applied its word-shape test to
  the lowercase base32 pass only, and the uppercase pass matches `A-Z` directly and emitted without
  it, so `otp_secret = RESPONSIBILITIES` scored 85 MEDIUM and `mfa_totp_secret = RESPONSIBILITIES`
  95 HIGH while the lowercase spelling of the same line reported nothing. Measured on main with
  `--show-match`: those two lines, the five #800 words in capitals on #800's lines (70–95) and an
  all-caps `TOTP SECRET KEY: ADMINISTRATIVELY DISABLED …` (95) gave 8 findings; now none. The test is
  now case-neutral and both passes apply it, so a digit-free value is reported in capitals exactly
  when it is reported in lowercase. A secret with a digit is never tested and scores as before (a
  generated 32-character one: 95 and 100 on the issue's lines, in either case). The cost is #800's,
  now in the uppercase pass too: about 0.7% of random 16-character secrets, 0.2% at 20 and under
  0.01% at 32 are digit-free and shaped like a word.
