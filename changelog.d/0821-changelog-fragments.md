### 🔨 Internal

- **changelog (fragments):** a release note is now a file of its own under `changelog.d/`, rendered
  into this file when the release tag is pushed, instead of an edit under `## [Unreleased]`, where
  every two open pull requests conflicted ([#821](https://github.com/awslabs/ferret-scan/issues/821));
  the entries already there moved into fragments byte for byte. Name one `NNNN-slug.md` and follow
  `changelog.d/README.md`; the `CHANGELOG` check requires and validates it.
