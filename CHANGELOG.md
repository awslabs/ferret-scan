# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<a name="v1.5.0"></a>
## [v1.5.0] - 2026-02-18

### 🐛 Bug Fixes

- **redaction:** fix synthetic strategy silently skipping SECRETS, PASSPORT, SOCIAL_MEDIA, and INTELLECTUAL_PROPERTY — added type-aware generators for all four types
- **redaction:** fix synthetic person name generation producing random character strings — now draws from embedded name databases (~5200 first names, ~2100 last names)
- **redaction:** fix PDF and Office redactors using their own duplicate replacement logic instead of the shared implementation

### 📦 Code Refactoring

- **redaction:** extract ~600 lines of duplicated replacement generation code into shared package `internal/redactors/replacement` — each redactor's `generateReplacement()` is now a one-liner
- reduce duplication across scanner, suppress count fix, exponential retry backoff, 47 new tests

### 🚀 Features

- **person-name:** expand name database coverage with 53 unambiguous names from South Asian, West African, Eastern European, Middle Eastern, Japanese, and Italian backgrounds

### 📚 Documentation

- add `docs/user-guides/README-Redaction.md` — comprehensive guide covering all three strategies, validator×strategy support table, document type support, synthetic token formats, and config reference

### 🛠 Build System

- remove pre-built platform binaries from repository and git history (repo size: ~200MB → 2.2MB)
- simplify `.gitignore` to ignore entire `bin/` directory
- remove platform dispatcher shell script — `make build` outputs directly to `bin/ferret-scan`
- fix git-chglog `repository_url` pointing to internal CodeCommit instead of GitHub

### Pull Requests

- Merge pull request [#38](https://github.com/awslabs/ferret-scan/issues/38) from awslabs/refactor/code-quality-improvements
- Merge pull request [#37](https://github.com/awslabs/ferret-scan/issues/37) from awslabs/dev/fabio-dev

<a name="v1.4.0"></a>
## [v1.4.0] - 2026-01-13

### 🚀 Features

- add `--exclude` flag for file and directory exclusion with glob pattern support

### Pull Requests

- Merge pull request [#36](https://github.com/awslabs/ferret-scan/issues/36) from awslabs/dev/fabio-dev
