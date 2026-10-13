# Release Process

This document describes the Go-native release process for Ferret Scan using GoReleaser.

> **CHANGELOG.md is hand-maintained.** It is not generated. Add your entry, as prose, under
> `## [Unreleased]` in the same PR that makes the change — a PR that changes what a release ships
> fails the `CHANGELOG` check without one (see [CONTRIBUTING.md](../CONTRIBUTING.md#changelog-entries)). `git-chglog` was removed on 2026-09-09: it was
> configured to rewrite the whole file from commit subjects with no `[Unreleased]` section, so running
> it replaced ~43,000 words of measurements and reasoning with one-line subjects. Nothing generates
> this file, and nothing should.

## Overview

We use a **Go-native release pipeline** that eliminates NPM dependencies:

- **GoReleaser** - Cross-platform builds and GitHub/GitLab releases
- **GitLab CI** - Automated pipeline with Go-only dependencies

## Release Types

### 1. Automated Releases (Recommended)

#### Tag-based Releases
Create a git tag to trigger a full release:

```bash
# Create and push a tag
git tag v1.2.3
git push origin v1.2.3

# GitLab CI will automatically:
# 1. Build binaries for all platforms
# 2. Generate release notes from commit subjects (GoReleaser; CHANGELOG.md is not touched)
# 3. Create GitLab release with assets
# 4. Build and push container images
```

#### Semantic Versioning
Use conventional commit messages for automatic version bumping:

```bash
# Patch version (v1.2.3 -> v1.2.4)
git commit -m "fix: resolve memory leak in scanner"

# Minor version (v1.2.3 -> v1.3.0)
git commit -m "feat: add new validator for API keys"

# Major version (v1.2.3 -> v2.0.0)
git commit -m "feat!: redesign configuration format

BREAKING CHANGE: Configuration file format has changed"
```

### 2. Manual Release Creation

Use the GitLab CI manual job to create releases:

1. Go to GitLab CI/CD → Pipelines
2. Find your main branch pipeline
3. Click the manual "create-release-tag" job
4. This will analyze commits and create an appropriate version tag

### 3. Snapshot Builds

Test releases without creating tags:

```bash
# Local snapshot build
make release-snapshot

# This creates builds in ./dist/ without releasing
```

## Tools Installation

### Automatic Installation
```bash
# Install GoReleaser
./scripts/install-release-tools.sh
```

### Manual Installation
```bash
# Install GoReleaser
go install github.com/goreleaser/goreleaser@latest
```

## Configuration Files

### GoReleaser (`.goreleaser.yml`)
- **Builds**: CLI and web binaries for multiple platforms
- **Archives**: Compressed releases with documentation
- **GitLab integration**: Automated releases and container images
- **Checksums**: Security verification files


## Makefile Commands

```bash
# Test GoReleaser configuration
make release-test

# Build snapshot (no release)
make release-snapshot

# Cut [Unreleased] into a version heading in CHANGELOG.md (normally done by
# changelog-promote.yml when the tag is pushed)
make promote-changelog TAG=v1.2.3

# Check Go version consistency
make check-go-version
```

## GitLab CI Pipeline

### Stages
1. **cache-cleanup** - Manage Go module cache
2. **build** - Compile and test
3. **security** - Security scanning
4. **release** - GoReleaser builds and releases

### Jobs
- **goreleaser-release** - Main release job (automatic on tags)
- **create-release-tag** - Manual version tagging (manual trigger)

### Artifacts
- **Binaries** - Cross-platform executables
- **Archives** - Compressed releases
- **Checksums** - Security verification
- **Container images** - Docker images (if configured)

## Release Workflow

### For Maintainers

1. **Development**
   ```bash
   # Use conventional commits
   git commit -m "feat: add new feature"
   git commit -m "fix: resolve bug"
   ```

2. **Pre-release Testing**
   ```bash
   # Test locally
   make release-snapshot
   make release-test
   ```

3. **Create Release**
   ```bash
   # Option A: Manual tag
   git tag v1.2.3
   git push origin v1.2.3

   # Option B: Use GitLab CI manual job
   # Go to GitLab → Pipelines → Manual "create-release-tag"
   ```

4. **Verify Release**
   - Check GitLab releases page
   - Verify all platforms built successfully
   - Test download and installation

### For Contributors

Contributors don't need to worry about releases - just use conventional commit messages:

```bash
# Good commit messages
git commit -m "feat: add support for new file format"
git commit -m "fix: handle edge case in parser"
git commit -m "docs: update installation guide"

# These will be automatically categorized in releases
```

## Troubleshooting

### GoReleaser Issues

```bash
# Validate configuration
goreleaser check

# Test build without releasing
goreleaser build --snapshot --clean

# Debug with verbose output
goreleaser release --debug
```

### CHANGELOG.md

There is no tool to run by hand. Pushing a release tag runs `.github/workflows/changelog-promote.yml`,
which renames `## [Unreleased]` to `## [<tag>] - <date>` and inserts a fresh empty `[Unreleased]` above
it (`scripts/promote-changelog.sh`). An empty `[Unreleased]` is a no-op — and if the tag's range
contains `fix`, `feat` or `perf` commits, the run says so with a warning, because that is a release
whose notes are missing.

Entries are required at PR time, where the author still knows what changed: the `CHANGELOG` check
(`.github/workflows/changelog-check.yml`, `internal/tools/changelogcheck`) fails a PR that changes
what a release ships without an entry under `[Unreleased]`, unless it carries the `no-changelog`
label. Its `after-merge` job runs again on the push to main and fails if a release promoted while
the PR was open moved the entry into the released section. The check reports; whether it blocks a
merge is the branch-protection setting for required status checks. If an entry is missing from a
release anyway, add it under that release's heading in a follow-up PR.

### CI/CD Issues

1. **Missing tools**: Run `./scripts/install-release-tools.sh`
2. **Permission errors**: Check `GITLAB_TOKEN` permissions
3. **Build failures**: Verify Go version consistency with `make check-go-version`

## Migration from semantic-release

This project has migrated from semantic-release to GoReleaser:

### Benefits
- ✅ **No NPM dependencies** - Pure Go ecosystem
- ✅ **Faster builds** - No Node.js setup overhead
- ✅ **Better Go integration** - Native cross-compilation
- ✅ **Smaller cache footprint** - Only Go modules
- ✅ **Industry standard** - GoReleaser is the Go standard

### What Changed
- **Removed**: `package.json`, `.releaserc.js`, NPM cache
- **Added**: `.goreleaser.yml`, Go-native tools
- **Updated**: GitLab CI uses Go-only pipeline
- **Maintained**: Same conventional commit workflow

The release process remains the same for developers - commit with conventional messages and releases happen automatically.
