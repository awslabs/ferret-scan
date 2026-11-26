### 📚 Documentation

- **national ID (rule text):** the SARIF `fullDescription` and the GitLab remediation text of the
  NATIONAL_ID family now name the Mexican RFC beside the other five numbers, and no longer say each
  one identifies one person, because an RFC can identify a company
  ([#884](https://github.com/awslabs/ferret-scan/issues/884)). ⚠ The SARIF `fullDescription` of the
  five NATIONAL_ID family rules (`AR_CUIL`, `BR_CPF`, `CA_SIN`, `CL_RUT`, `MX_CURP`) and the GitLab SAST
  remediation text change; the SARIF `help` text does not; no finding, score or exit code changes.
- **web (`--debug`):** `docs/configuration.md` and `docs/user-guides/README-WebUI.md` state that under
  `--web` only the `--debug` flag turns on the server's debug log; a `debug:` key in a config file or
  profile does not ([#1072](https://github.com/awslabs/ferret-scan/issues/1072)).
- **README:** the pre-commit snippet pins `rev: v2.6.2`.
