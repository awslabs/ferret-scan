**ferret-scan** finds sensitive data before it leaks and redacts it in place: PII, secrets and
intellectual-property markers in files, directories and streams, with context-aware confidence
scoring and format-preserving redaction. It is one static Go binary with no runtime dependencies.
No data leaves your host.

This image is built `FROM scratch`, contains only that binary, and runs as a non-root user
(`ferret`, uid 1000). Platforms: `linux/amd64`, `linux/arm64`.

**Tags.** Each release publishes `X.Y.Z` and `X.Y`; `latest` is the newest release; `main` is the
development build of the default branch. Pin a version tag in CI.

**What it detects.** Twenty validators: credit cards (Luhn-validated, 8 brands), secrets and API
keys, SSN/ITIN, bank accounts and IBANs, OTP secrets, dates of birth, street addresses, driver's
licenses, medical identifiers, email, phone, IP addresses, national IDs, passports (incl. MRZ), VINs,
person names, cloud resource identifiers, IP/confidentiality markers, social media handles, and file
metadata (EXIF, document properties). What each one catches, and how confidence is scored:
https://github.com/awslabs/ferret-scan#what-it-detects

**Output formats.** `text`, `json`, `csv`, `yaml`, `junit`, `gitlab-sast`, `sarif`.

**The GitHub repository is the reference for everything on this page.**

- Source and README: https://github.com/awslabs/ferret-scan
- Documentation index: https://github.com/awslabs/ferret-scan/blob/main/docs/README.md
- Container guide (Docker and Finch): https://github.com/awslabs/ferret-scan/blob/main/docs/user-guides/README-Docker.md
- Changelog: https://github.com/awslabs/ferret-scan/blob/main/CHANGELOG.md
- Issues: https://github.com/awslabs/ferret-scan/issues
- Other ways to install (`pip install ferret-scan`, Homebrew, release binaries for macOS, Linux and
  Windows): https://github.com/awslabs/ferret-scan#install

Apache-2.0. An awslabs open-source project.
