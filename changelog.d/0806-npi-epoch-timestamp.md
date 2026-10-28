### 🐛 Bug Fixes

- **medicalid (Unix timestamp read as an NPI):** a 10-digit Unix timestamp whose own label or unit
  names it as a time is no longer reported as an NPI
  ([#806](https://github.com/awslabs/ferret-scan/issues/806)). One epoch in ten passes the CMS
  NPI-Luhn check by chance, and `evaluateNPI` admitted every Luhn-valid 1- or 2-led run at base 80
  plus line context, so `NPI reconciliation ran at 1751328000 epoch seconds.` reported NPI 90 HIGH.
  Now a candidate between 1000000000 and 2000000000 (2001-09-09 to 2033-05-18) is dropped when the
  token right before it names a time (`at`, `ts`, `timestamp`, `epoch`, `date`, `created_at`, the
  JWT `iat`/`nbf`/`exp`, or `created`/`updated`/`modified` and units written as a field name) or the
  word right after it is a time unit (`s`, `ms`, `seconds`, `epoch`, `unix`), and no NPI label is
  attached: `NPI: 1751328000`, `npi=1751328000` and `NPI 1234567893 seconds` keep their score and
  the TM-11 floor. Measured main vs branch: 19 timestamp shapes went from NPI 90–100 to no finding,
  22 real-NPI controls (1- and 2-led, labelled and not, ending in `00`, time words elsewhere on the
  line) report at the same score, and no existing golden snapshot or `make score` count moved.
