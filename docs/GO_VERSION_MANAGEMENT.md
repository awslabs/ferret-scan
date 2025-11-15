# Go Version Management

This document explains how Go version consistency is maintained across the Ferret Scan project.

## Overview

Maintaining consistent Go versions across development, CI/CD, and deployment environments is crucial for:
- **Reproducible builds** - Same results across different environments
- **Dependency compatibility** - Avoiding version-specific issues
- **Team consistency** - All developers using the same toolchain
- **CI/CD reliability** - Preventing environment-specific failures

## Version Sources

### Primary Source: `.go-version`
```
1.24.1
```
This file contains the **exact** Go version used across the project.

### Derived Versions

| File | Version Format | Purpose |
|------|----------------|---------|
| `go.mod` | `1.24` | Go module compatibility (major.minor) |
| `.gitlab-ci.yml` | `1.24.1` | CI/CD Docker images |
| `Dockerfile` | `1.24.1-alpine` | Container builds |
| Local development | `1.24.1` | Developer environments |

## Synchronization Tools

### 1. Automatic Sync Script
```bash
# Sync all files to match .go-version
./scripts/sync-versions.sh
```

### 2. Makefile Targets
```bash
# Check version consistency
make check-go-version

# Sync versions and update files
make sync-go-version
```

### 3. Pre-commit Hooks
Version consistency is automatically checked before commits:
```bash
# Install pre-commit hooks
pre-commit install

# Manual check
pre-commit run go-version-check --all-files
```

## Updating Go Version

### Step 1: Update Primary Source
```bash
echo "1.25.1" > .go-version
```

### Step 2: Sync All Files
```bash
./scripts/sync-versions.sh
```

### Step 3: Verify Changes
```bash
git diff
make check-go-version
```

### Step 4: Test Build
```bash
make build
make test
```

### Step 5: Commit Changes
```bash
git add .go-version go.mod .gitlab-ci.yml
git commit -m "chore: update Go version to 1.25.1"
```

## CI/CD Integration

### GitLab CI Variables
```yaml
variables:
  GO_VERSION: "1.24.1"
  GO_DOCKER_IMAGE: "golang:1.24.1-alpine"
```

### Usage in Jobs
```yaml
build:
  image: $GO_DOCKER_IMAGE
  script:
    - go version  # Outputs: go version go1.24.1 linux/amd64
```

## Local Development

### Version Managers
We recommend using a Go version manager:

#### Option 1: g (Simple)
```bash
# Install g
curl -sSL https://git.io/g-install | sh -s

# Use project version
g install $(cat .go-version)
g use $(cat .go-version)
```

#### Option 2: gvm (Feature-rich)
```bash
# Install gvm
bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)

# Use project version
gvm install go$(cat .go-version)
gvm use go$(cat .go-version) --default
```

### Manual Installation
Download from [golang.org/dl](https://golang.org/dl/) and install the exact version specified in `.go-version`.

## Troubleshooting

### Version Mismatch Errors
```bash
# Check current versions
./scripts/go-version.sh check

# Fix mismatches
./scripts/sync-versions.sh
```

### CI/CD Failures
1. Check if `.gitlab-ci.yml` uses `$GO_DOCKER_IMAGE` variable
2. Verify `GO_VERSION` variable matches `.go-version`
3. Ensure Docker image exists for the specified version

### Build Issues
```bash
# Clean and rebuild
make clean
go clean -modcache
make build
```

## Best Practices

### ✅ Do
- Always update `.go-version` first
- Run sync script after version changes
- Test builds after version updates
- Use version variables in CI/CD
- Check version consistency in pre-commit hooks

### ❌ Don't
- Hardcode Go versions in multiple places
- Skip testing after version updates
- Use different versions in different environments
- Ignore version mismatch warnings

## File Locations

```
.
├── .go-version                 # Primary version source
├── go.mod                      # Go module version (major.minor)
├── .gitlab-ci.yml             # CI/CD version variables
├── Dockerfile                  # Container Go version (if exists)
├── scripts/
│   ├── go-version.sh          # Version checking utility
│   └── sync-versions.sh       # Comprehensive sync script
├── .pre-commit-config.yaml    # Pre-commit version checks
└── docs/
    └── GO_VERSION_MANAGEMENT.md  # This document
```

## Integration with Semantic Release

When using semantic-release, version updates should be part of the release process:

```javascript
// .releaserc.js or package.json
{
  "plugins": [
    "@semantic-release/commit-analyzer",
    "@semantic-release/release-notes-generator",
    [
      "@semantic-release/exec",
      {
        "prepareCmd": "./scripts/sync-versions.sh"
      }
    ]
  ]
}
```

This ensures Go version consistency is maintained during automated releases.
