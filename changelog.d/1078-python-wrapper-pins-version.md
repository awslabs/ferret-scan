### 🐛 Bug Fixes

- **python-package:** the `ferret-scan` pip wrapper now downloads the GitHub release that matches
  the installed package version (`releases/tags/v<version>`) instead of `releases/latest`, so
  `pip install ferret-scan==2.6.1` runs the 2.6.1 binary, and checksums are verified against that
  same release. A version that is not a plain `X.Y.Z` (`0.0.0`, a dev or pre-release build) falls
  back to the latest release with one notice on stderr; a plain version with no matching tag exits
  non-zero naming the tag. ⚠ A pinned pip version now runs that version's binary, and the binary is
  cached as `ferret-scan-<version>-<os>-<arch>`, so the first run after upgrading downloads again;
  the old unversioned cached file is ignored. (#1078)
