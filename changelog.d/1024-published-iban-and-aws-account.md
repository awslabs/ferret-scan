### 🐛 Bug Fixes

- **bankaccount, cloudresources:** ⚠ two published example values now read LOW. The IBAN the SWIFT
  IBAN registry gives as Germany's example (`DE89 3704 0044 0532 0130 00`, any spelling) read `IBAN`
  100 HIGH and is now held at LOW 15, as the GB example has been since #971. An `AWS_ARN` whose
  account is `123456789012`, the account the AWS IAM User Guide uses in its ARN examples
  (`arn:aws:iam::123456789012:role/MyRole`, any service or partition), read 95 HIGH and is now held at
  15. Both are still reported, so still redacted, and the ceiling is published so a document cannot
  lift it. Any other IBAN, and an ARN with any other account (one digit away included), keeps its
  score; so does a real account that happens to be `123456789012`, which is the cost of the hold.
  The `PHONE` finding on the IBAN's digit run is the phone check's and is unchanged.
  ([#1024](https://github.com/awslabs/ferret-scan/issues/1024),
  [#1027](https://github.com/awslabs/ferret-scan/issues/1027))
