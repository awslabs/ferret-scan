### 🚀 Features

- **driverslicense (GB DVLA, Ontario, Quebec):** `DRIVERS_LICENSE` reports a Great Britain DVLA
  driver number (`GB_DVLA`: 16 characters, or 18 with the issue number, contiguous or in 5/6/5
  groups) and Ontario and Quebec licences written with hyphens (`CA_ON` `A1234-12345-12345`, `CA_QC`
  `A1234-123456-12`). Each gave no finding of any type on main, under any label, so the number
  stayed in cleartext under `--enable-redaction`; a DVLA number encodes the holder's surname,
  birth date and sex. A GB value must also pass the DVLA layout (birth month 01-12 or 51-62, day
  01-31, surname letters then 9-padding, initials), and an Ontario or Quebec value must not be one
  segment of a longer hyphenated token. On main, 0 of 12 GB display variants were reported; now 12
  of 12 (95, or 85 with the label on the line above); 500 GB-shaped values with an impossible month
  or day stay unreported. The issue's onboarding record now redacts 4 of its 5 licence numbers
  (main: 1); the fifth is an India number, which stays out of scope with the other jurisdictions
  listed in `docs/validators-new.md`. Contiguous Ontario and Quebec numbers keep their US format
  names (`NJ_1L14D`, `FL_MI_1L12D`), and a file with no finding before may report one now
  ([#861](https://github.com/awslabs/ferret-scan/issues/861)).
