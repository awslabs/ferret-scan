### 🐛 Bug Fixes

- **bankaccount (cloud account id as US account):** a 12-digit cloud account id on a line that
  names it (`AWS account`, `account id`, `payer`, `management account`, `org id`,
  `subscription id`, `project number`, `project id`, `tenant`) is no longer reported as
  `US_BANK_ACCOUNT` above LOW. A bare account number has no checksum, so any banking word on the
  line (`deposit`, or the AWS product words `savings` and `transit`) admitted the run, the `account`
  proximity boost lifted it to 85 MEDIUM, and the document bridge's +20 tabular boost to 100 HIGH
  in a CSV row. Such a run is now capped at 55 and the cap is published as `confidence_ceiling`, so
  the bridge cannot lift it; it is still reported and still redacted. Measured: the issue's line
  85 MEDIUM on main, 55 LOW on the branch; a CSV row of the same shape 100 HIGH on main, 55 LOW on
  the branch; `Account number: 210987654321` beside `routing` or `bank` stays 100 HIGH
  ([#805](https://github.com/awslabs/ferret-scan/issues/805)).
