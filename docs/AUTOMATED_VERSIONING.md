# Automated Versioning and Releases

This document explains the automated versioning and release system for Ferret Scan.

## Overview

The project uses **GoReleaser** with **GitLab CI** for automated versioning and releases, replacing the previous NPM-based semantic-release system. This provides a Go-native solution that's more appropriate for a Go project.

## How It Works

### Automatic Version Bumping

The system automatically creates new version tags based on conventional commit messages:

- **Major version bump** (`1.0.0` → `2.0.0`):
  - `BREAKING CHANGE:` in commit message
  - `feat!:`, `fix!:`, `perf!:` (with exclamation mark)

- **Minor version bump** (`1.0.0` → `1.1.0`):
  - `feat:` commits (new features)

- **Patch version bump** (`1.0.0` → `1.0.1`):
  - `fix:` commits (bug fixes)
  - `perf:` commits (performance improvements)
  - `refactor:` commits (code refactoring)

### Release Process

1. **Commit to main/master** with conventional commit messages
2. **GitLab CI automatically**:
   - Analyzes commits since last tag
   - Determines appropriate version bump
   - Creates and pushes new version tag
   - Triggers GoReleaser build
3. **GoReleaser automatically**:
   - Builds binaries for Linux and macOS (amd64 and arm64)
   - Generates changelog from commit messages
   - Creates GitLab release with binaries attached
   - Updates Docker images (if configured)

## Configuration Files

### `.gitlab-ci.yml`
- **auto-version-tag**: Analyzes commits and creates version tags
- **goreleaser-release**: Builds and publishes releases
- **manual-release-tag**: Manual release creation (fallback)

### `.goreleaser.yml`
- Defines build targets (Linux, macOS)
- Configures binary names and build flags
- Sets up GitLab releases and changelog generation
- Excludes Windows builds (as requested)

## Manual Operations

### Initialize Versioning
If no tags exist in the repository:
```bash
./scripts/init-version.sh
```

### Create Manual Release
```bash
# Auto-determine version bump
./scripts/create-release.sh

# Specify exact version
./scripts/create-release.sh v1.2.3
```

### Check Version Status
```bash
./scripts/version-helper.sh status
```

### Manual Tag Creation (GitLab CI)
You can manually trigger a release in GitLab CI:
1. Go to CI/CD → Pipelines
2. Run pipeline on main/master branch
3. Manually trigger the `manual-release-tag` job

## Version Format

- **Format**: `vMAJOR.MINOR.PATCH` (e.g., `v1.2.3`)
- **Starting version**: `v0.1.0`
- **Pre-release handling**: Automatically strips suffixes like `-beta`

## Conventional Commit Format (Required for Auto-Versioning)

### Commit Message Structure
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Version Bump Types

#### Patch Version Bump (0.1.0 → 0.1.1)
Use for bug fixes, performance improvements, and refactoring:
```bash
git commit -m "fix: resolve memory leak in credit card scanner"
git commit -m "fix: handle edge case in passport validation"
git commit -m "perf: optimize regex matching performance by 40%"
git commit -m "perf: reduce memory usage in large file processing"
git commit -m "refactor: simplify validator interface implementation"
git commit -m "refactor: extract common validation logic"
```

#### Minor Version Bump (0.1.0 → 0.2.0)
Use for new features and enhancements:
```bash
git commit -m "feat: add passport number validator"
git commit -m "feat: support custom regex patterns in configuration"
git commit -m "feat: add web interface for scan results"
git commit -m "feat: implement batch file processing"
```

#### Major Version Bump (0.1.0 → 1.0.0)
Use for breaking changes:
```bash
# Method 1: Use exclamation mark
git commit -m "feat!: change validator API interface"
git commit -m "fix!: remove deprecated ValidateFile method"

# Method 2: Use BREAKING CHANGE footer
git commit -m "feat: add new validation engine

BREAKING CHANGE: The old ValidateFile method has been removed.
Use the new Validate method instead."
```

#### No Version Bump
These commit types won't trigger releases:
```bash
git commit -m "docs: update README with new examples"
git commit -m "chore: update Go dependencies"
git commit -m "style: fix code formatting"
git commit -m "ci: update GitLab CI configuration"
git commit -m "test: add unit tests for SSN validator"
```

### Complete Examples with Context

```bash
# Adding a new validator (minor bump)
git commit -m "feat: add driver license validator

- Supports US and Canadian formats
- Includes confidence scoring
- Added comprehensive test coverage"

# Fixing a critical bug (patch bump)
git commit -m "fix: prevent false positives in credit card detection

The regex was too broad and matching account numbers.
Now uses Luhn algorithm for validation."

# Breaking API change (major bump)
git commit -m "refactor!: standardize validator interface

BREAKING CHANGE: All validators now implement the new
ValidatorV2 interface. The old Validate() method has been
replaced with ValidateContent() and ValidateFile() methods."
```

### Quick Reference Card

| Commit Prefix      | Version Bump | Use For                  |
| ------------------ | ------------ | ------------------------ |
| `fix:`             | Patch        | Bug fixes                |
| `perf:`            | Patch        | Performance improvements |
| `refactor:`        | Patch        | Code refactoring         |
| `feat:`            | Minor        | New features             |
| `feat!:`           | Major        | Breaking new features    |
| `fix!:`            | Major        | Breaking bug fixes       |
| `BREAKING CHANGE:` | Major        | Any breaking change      |
| `docs:`            | None         | Documentation only       |
| `chore:`           | None         | Maintenance tasks        |
| `style:`           | None         | Code formatting          |
| `ci:`              | None         | CI/CD changes            |
| `test:`            | None         | Test additions/changes   |

## Disabling Automatic Versioning

Set the GitLab CI variable `AUTO_VERSION_ENABLED` to `"false"` to disable automatic version tagging while keeping manual options available.

## Benefits Over NPM Semantic-Release

1. **Go-native tooling**: No Node.js dependencies
2. **Smaller CI footprint**: Reduced memory and storage usage
3. **Better Go integration**: Native Go build flags and versioning
4. **Simpler configuration**: Single `.goreleaser.yml` file
5. **GitLab-optimized**: Built specifically for GitLab CI/CD

## Troubleshooting

### No Version Tags Created
- Check that commits follow conventional commit format
- Verify `AUTO_VERSION_ENABLED` is set to `"true"`
- Ensure you're pushing to main/master branch

### Build Failures
- Check GoReleaser configuration with `goreleaser check`
- Verify Go version consistency across project files
- Review GitLab CI logs for specific error messages

### Manual Recovery
If automatic versioning fails, you can always create tags manually:
```bash
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

## Migration Notes

This system replaces the previous NPM-based semantic-release setup:
- ✅ Removed `package.json` and NPM dependencies
- ✅ Replaced semantic-release with GoReleaser
- ✅ Updated GitLab CI configuration
- ✅ Added Go-native version management scripts
- ✅ Maintained conventional commit compatibility
