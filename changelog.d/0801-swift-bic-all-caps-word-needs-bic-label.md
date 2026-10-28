### 🐛 Bug Fixes

- **bankaccount (all-caps word as SWIFT/BIC):** an all-caps English word whose 5th and 6th letters
  spell a country code (`CUSTOMER`, `BUSINESS`, `MITIGATIONS`) is no longer reported as `SWIFT_BIC`
  on a line that only talks about banking. `scanSWIFT` waived its all-letter word gate whenever any
  positive keyword was on the line (`bank`, `bank account`, `wire`, `deposit`), then added the
  keyword boost on top, so each word scored 100 HIGH. An all-letter candidate now needs a label
  that names the code (`swift`, `bic` or `iban`); a candidate with a digit (`CHASUS33`) keeps the
  old rule. Measured with the 9,283 English words of 8 or 11 letters that pass the SWIFT structure
  check, one per line beside `bank`: 9,283 HIGH on main, 0 on the branch; 115 real all-letter BICs
  labelled `SWIFT:`, `BIC:` or `IBAN` report unchanged. Trade-off: an all-letter BIC whose line
  names only the bank (`Deutsche Bank DEUTDEFF`) is no longer reported
  ([#801](https://github.com/awslabs/ferret-scan/issues/801)).
