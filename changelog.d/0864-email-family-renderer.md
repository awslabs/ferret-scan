### 🐛 Bug Fixes

- **redaction (email, social media):** every one of the 24 types the email validator reports
  (`EMAIL`, the provider types such as `OUTLOOK` or `GITHUB`, the sector types such as `GOVERNMENT`)
  is now redacted as an email in every strategy: `simple` writes `[EMAIL-REDACTED]` instead of a
  provider- or sector-named placeholder (`[SALESFORCE-REDACTED]`), `format_preserving` keeps the
  first character and the domain (`z****@outlook.com`) instead of an all-`*` mask, and `synthetic`
  writes a random address at `example.com` instead of a random string with no `@`. Measured on a
  24-line fixture with one address per type, the email rendering reached 3 of 24 lines in each
  strategy; it now reaches 24 of 24, so `format_preserving` now shows the domain of 21 more types,
  and re-scanning `synthetic` output finds 24 `example.com` addresses instead of 3. Social media
  platform types (`LINKEDIN`, `GITHUB`, …) now get `synthetic`'s fake profile URL instead of a
  random string, and `simple` writes `[SOCIAL-MEDIA-REDACTED]` instead of naming the platform; an
  address at `github.com` stays an email. Secrets keep their typed `simple` markers, which the
  README now shows. ([#864](https://github.com/awslabs/ferret-scan/issues/864))
