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
1.26.4
```
This file contains the **exact** Go version used across the project.

### Derived Versions

| File | Version Format | Purpose |
|------|----------------|---------|
| `go.mod` | `1.26` | Go module compatibility (major.minor) |
| `.gitlab-ci.yml` | `1.26.4` | CI/CD Docker images (`GO_VERSION`, `GO_DOCKER_IMAGE`) |
| `Dockerfile` | `1.26.4-alpine` + `@sha256:…` | Container builds (tag **and** digest — see below) |
| GitHub workflows | `go-version-file: .go-version` | No literal pin — they read `.go-version` directly |
| Local development | `1.26.4` | Developer environments |

> **Dockerfile digest (TM-10).** The builder image is digest-pinned for
> supply-chain integrity: the `@sha256:…` is what actually determines the
> pulled image; the tag is informational. The sync tool resolves and rewrites
> the digest for the new tag, so you never edit it by hand. GitHub Actions use
> `go-version-file: .go-version`, so there is no literal version to keep in
> sync there — `check` asserts no workflow has reintroduced a hardcoded pin.

## Synchronization Tools

`.go-version` is the single source of truth. One script — `scripts/go-version.sh`
— both propagates it and validates consistency.

### 1. Makefile Targets (preferred)

```bash
# Cross-validate every pin against .go-version (used by CI + pre-commit)
make check-go-version

# Propagate .go-version to go.mod, Dockerfile (tag + digest), .gitlab-ci.yml
make sync-go-version
```

### 2. The script directly

```bash
./scripts/go-version.sh check   # validate; non-zero exit on any drift
./scripts/go-version.sh all     # sync all pins (alias: sync)
```

Resolving the Dockerfile digest needs network access plus one of `crane`,
`docker`, or `curl`+`jq`. Offline, `sync` updates the tag and warns that the
digest must be set manually (`crane digest <registry>/golang:<ver>-alpine`),
and `check` validates the tag but only warns on an unverifiable digest.

### 3. Pre-commit Hook
The `go-version-check` hook runs `go-version-check` on any commit touching
`.go-version`, `go.mod`, `.gitlab-ci.yml`, or `Dockerfile`, so drift is caught
before it lands:
```bash
pre-commit install
pre-commit run go-version-check --all-files   # manual check
```

## Updating Go Version

### Step 1: Update Primary Source
```bash
echo "1.26.4" > .go-version
```

### Step 2: Sync All Files
```bash
make sync-go-version
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
git commit -m "chore: update Go version to 1.26.4"
```

## CI/CD Integration

### GitLab CI Variables
```yaml
variables:
  GO_VERSION: "1.26.4"
  GO_DOCKER_IMAGE: "golang:1.26.4-alpine"
```

### Usage in Jobs
```yaml
build:
  image: $GO_DOCKER_IMAGE
  script:
    - go version  # Outputs: go version go1.26.4 linux/amd64
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
make check-go-version

# Fix mismatches
make sync-go-version
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
├── Dockerfile                  # Container Go version: tag + @sha256 digest
├── scripts/
│   └── go-version.sh          # Single sync + check tool (.go-version -> all pins)
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
        "prepareCmd": "./scripts/go-version.sh all"
      }
    ]
  ]
}
```

This ensures Go version consistency is maintained during automated releases.
