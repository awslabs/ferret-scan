### 🐛 Bug Fixes

- **secrets (CSV, TSV and FixedWidth documents):** the context analyzer's document adjustment is
  applied to a secrets finding once, by the document bridge, as it is for every other validator,
  instead of twice ([#879](https://github.com/awslabs/ferret-scan/issues/879)). The validator added
  `tabular_boost` (+20) and `test_data_penalty` (−30) to its own score and the bridge added them
  again, so a secrets finding in a tabular document got +40 while its metadata recorded +20:
  `token = getToken()` scored 75 in a key=value file and 100 as a TSV cell. It now scores 80 (75,
  less the Configuration +15 a TSV does not get, plus one +20), and `original_confidence` plus
  `confidence_adjustment` is the reported score. The validator still judges its reporting threshold
  on the score the bridge reports, so no finding appears or disappears; deleting the validator's
  adjustment alone would have dropped every keyword match it scores exactly 60, such as
  `password = summer2024` in a TSV cell, and left it unredacted. A secrets finding in a tabular
  document drops by up to 20 (not one at 100 or held at 55 by the M24 cap, which still reports at
  75), and one in a document whose prose names five of the analyzer's eight test-data phrases rises
  by up to 30. Measured on main vs this branch with `--checks SECRETS`: the Go standard library
  (11,328 files), the Go module cache (14,328) and this repository (2,131) report the same 14,487
  findings, three of them at a lower score, all in Go test files typed CSV (75 → 70, 85 → 65 twice);
  the 39 values main reports in planted TSV and CSV cells are all reported and redacted, 11 of them
  (10 weak passwords and `getToken()`) at 80 instead of 100. Legacy v1 suppression rules hash
  confidence and stop matching a finding
  whose score moved; rules written by `--generate-suppressions` today do not. Golden corpus and
  `make score` unchanged.
