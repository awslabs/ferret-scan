### 🐛 Bug Fixes

- **phone:** an ISO 6709 point string (the QuickTime `©xyz` / XMP GPS form, `+4012.22-07500.25/`,
  `+40.7128-074.0060+000.125/`) and a decimal written after `00` (`00125.37`, `00074.56695-7`) are no
  longer reported as phone numbers. On the issue's lines `PHONE` reported 8 findings (3 HIGH at 95, 5
  LOW at 15) and now reports none; the numbers nearest the rule (the German `+49-911/1234567`, the EPP
  `+1.7035550123`, dotted and `00` forms) keep their findings and scores.
  ([#938](https://github.com/awslabs/ferret-scan/issues/938))
