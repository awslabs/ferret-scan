# Semantic Release Setup

This document explains how semantic-release is configured for automated versioning and releases in the Ferret Scan project.

## Overview

Semantic-release automatically determines the next version number, generates release notes, and publishes releases based on commit messages following the [Conventional Commits](https://conventionalcommits.org/) specification.

## Commit Message Format

Use the following format for commit messages:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: A new feature (triggers minor version bump)
- **fix**: A bug fix (triggers patch version bump)
- **perf**: A performance improvement (triggers patch version bump)
- **revert**: Reverts a previous commit (triggers patch version bump)
- **docs**: Documentation changes (triggers patch version bump for README scope)
- **style**: Code style changes (no release)
- **refactor**: Code refactoring (triggers patch version bump)
- **test**: Test changes (no release)
- **build**: Build system changes (triggers patch version bump)
- **ci**: CI/CD changes (no release)

### Examples

```bash
# Feature (minor version bump)
git commit -m "feat: add social media validator for LinkedIn profiles"

# Bug fix (patch version bump)
git commit -m "fix: resolve memory leak in PDF processing"

# Breaking change (major version bump)
git commit -m "feat!: redesign configuration file structure

BREAKING CHANGE: Configuration file format has changed. See migration guide."

# No release
git commit -m "ci: update GitLab CI configuration"
git commit -m "test: add unit tests for credit card validator"
```

## Release Process

### Automatic Releases

Releases are automatically triggered when commits are pushed to:

- **main/master branch**: Creates stable releases (1.0.0, 1.1.0, 1.1.1, etc.)
- **develop branch**: Creates pre-releases (1.1.0-beta.1, 1.1.0-beta.2, etc.)

### Manual Release

To trigger a release manually:

1. Ensure your commits follow the conventional format
2. Push to the main/master branch
3. The GitLab CI pipeline will automatically run semantic-release

## Configuration Files

### package.json
Contains semantic-release dependencies and basic configuration.

### .releaserc.js
Main semantic-release configuration with:
- Commit analysis rules
- Release note generation
- Changelog management
- Version injection into Go files
- GitLab release creation

### scripts/update-version.sh
Script to update version information in Go source files.

## Version Information

Version information is embedded in the Go binary through:

- **internal/version/version.go**: Contains version constants
- **Build-time injection**: Git commit, build date, and version are injected during compilation
- **--version flag**: Users can check version with `ferret-scan --version`

## GitLab CI Integration

The semantic-release job:

1. Analyzes commits since the last release
2. Determines the next version number
3. Updates version in Go source files
4. Builds the release binary with version information
5. Generates changelog
6. Creates GitLab release with binary assets
7. Commits version updates back to the repository

## Troubleshooting

### No Release Created

- Check that commit messages follow conventional format
- Ensure commits contain releasable changes (feat, fix, etc.)
- Verify the branch is main/master or develop

### Version Not Updated

- Check that the update-version.sh script has execute permissions
- Verify the internal/version/version.go file exists
- Check GitLab CI logs for script execution errors

### GitLab Release Failed

- Ensure CI_JOB_TOKEN has sufficient permissions
- Check that the repository URL in package.json is correct
- Verify binary artifacts are created successfully

## Best Practices

1. **Use descriptive commit messages**: Help others understand what changed
2. **Group related changes**: Use a single commit for related changes
3. **Test before committing**: Ensure your changes work as expected
4. **Use scopes**: Add scopes to provide more context (e.g., `feat(validator): add new pattern`)
5. **Document breaking changes**: Always include BREAKING CHANGE footer for major version bumps

## Migration from Manual Versioning

If migrating from manual versioning:

1. Ensure the last manual version is tagged in Git
2. Update package.json version to match the last release
3. Start using conventional commits for all new changes
4. The next release will be automatically determined based on commits since the last tag
