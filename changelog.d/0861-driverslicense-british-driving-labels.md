### 🐛 Bug Fixes

- **driverslicense (British and `driving` labels):** a licence label spelled the British way or with
  `driving` is found and scored like its US twin. The three hand-written label lists had drifted
  apart; one generated vocabulary of the 24 {driver, drivers, driver's, driving} x {license,
  licence} x {"", number, no} spellings now feeds all three. On a 50-file case matrix (one label
  per file, `D1234567` as the value), 10 keys that gave no finding on main (`drivingLicence:`,
  `DrivingLicenceNo:`, `driversLicence:`, `driverLicence:`, a JSON and a YAML key, ...) report at 95,
  and `Driving licence:`, `Driving license:`, `Driving licence #:`, `driving_licence:` and
  `Driving Licence No.` (75 on main) and `Licence No.` (65) score 95, like `Driver's licence:` and
  `License No.`; US spellings keep their scores and their supporting-keyword lists. A line that
  moves from 75 or 65 to 95 (also `Driving licence issued: 20190714`, like `Driver's licence
  issued:`) stops matching a legacy v1 suppression rule, which hashes the confidence; v2 rules are
  unaffected, and a file with no finding before may report one now. The per-line keyword gate now
  lowercases each line once instead of once per keyword: `--checks DRIVERS_LICENSE` on 15.4 MB of
  public text costs 0.85x main's CPU (median of 7 interleaved runs)
  ([#861](https://github.com/awslabs/ferret-scan/issues/861)).
