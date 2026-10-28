### 🐛 Bug Fixes

- **secrets (line pre-check, `session`):** `session=` with an 8- to 11-byte value on a line under
  20 bytes is scanned again. `session` is a stem the keyword patterns are compiled from, but the
  pre-check in front of them (`containsSecretIndicators`) admitted keyword lines through a hand
  list with no word for it, and its generic fall-through admits a line with `=` or `:` only from
  20 bytes, so `session=Ab3dEf7h` reported nothing while `token=Ab3dEf7h` reported 100. The
  pre-check now admits every stem beside an `=` or `:` at any length, through `lineHasKeywordStem`,
  the matcher derived from the stem lists, so a stem cannot be left without an admit; a new guard
  test checks a minimal assignment for every stem. Measured on main vs this branch: the issue's
  four lines of 16 to 19 bytes, nothing to `API_KEY_OR_SECRET` 100, the same as `token=`; the 20-
  and 21-byte lines unchanged at 100; generated npm lockfiles of 4,000 to 16,000 packages, 0
  findings on both and SECRETS CPU within noise
  ([#815](https://github.com/awslabs/ferret-scan/issues/815)).
