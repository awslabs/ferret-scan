### 📚 Documentation

- **sarif, gitlab-sast (rule copy):** an `ITIN` finding's SARIF rule and GitLab vulnerability now
  read "Individual Taxpayer Identification Number Detected" and describe the IRS number, instead of
  the "Social Security Number Detected" copy it inherited from `SSN`
  ([#884](https://github.com/awslabs/ferret-scan/issues/884)). The `MEDICAL_ID` copy, which all seven
  medical sub-types use, names UK NHS and Scottish CHI numbers beside the US identifiers and the UK
  GDPR beside HIPAA ([#859](https://github.com/awslabs/ferret-scan/issues/859)). The
  `DRIVERS_LICENSE` help says that a finding's `format` names the shape it matched, not the
  jurisdiction that issued it: `NY_GA_9D` is New York or Georgia, and a contiguous Ontario or Quebec
  number reports as `NJ_1L14D` or `FL_MI_1L12D`
  ([#861](https://github.com/awslabs/ferret-scan/issues/861)). `docs/checks.md` is regenerated from
  the same copy. Rule text only: no finding, type, confidence or suppression hash changes.
