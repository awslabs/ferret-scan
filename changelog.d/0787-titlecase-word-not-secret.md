### 🐛 Bug Fixes

- **secrets (a capitalised word after `password:` / `session:`):** an unquoted value that is a
  single word in sentence case, `Checklist` or `Required`, is no longer reported as
  `API_KEY_OR_SECRET`. The prose veto in `plausibleUnquotedSecret` rejected a short all-lowercase
  word (`token: creating`) but not the same word with a capital, and prose capitalises the word after
  a colon: `Onboarding session: Checklist review` reported `Checklist` at MEDIUM 85, and at HIGH 100
  in a document whose first lines are a tab-separated table (+20), where `--pre-commit-mode` blocked
  the commit. A value of one upper-case letter followed only by lower-case letters, under 16
  characters, is now rejected like its lower-case spelling. Stated cost, the same as the lower-case
  rule's: a short sentence-case alphabetic password under an unquoted key is not reported, and as a
  URI password it is kept at LOW (at most 55) instead of being scored. Still reported: the same
  word quoted (`password: "Checklist"`), with a digit or a symbol, in CamelCase, in capitals, and
  from 16 characters (`Correcthorsebatterystaple`). Measured on main vs this branch: the issue's
  prose files, 1 MEDIUM (plain), 2 HIGH (under a tab header) and 3 MEDIUM (a policy document) to
  nothing; the issue's control file, the real password still reported at the same confidence and
  the word beside it no longer reported; `postgres://app:Clustering@...`, HIGH 100 to LOW 55
  ([#787](https://github.com/awslabs/ferret-scan/issues/787)).
