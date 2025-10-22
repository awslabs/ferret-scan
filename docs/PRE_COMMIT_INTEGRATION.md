# Ferret Scan Pre-commit Integration Guide

This guide explains how to integrate Ferret Scan directly into your Git workflow using pre-commit hooks to automatically scan for sensitive data before commits.

## Quick Start

### 1. Install Pre-commit

```bash
# Install pre-commit
pip install pre-commit

# Verify installation
pre-commit --version
```

### 2. Direct Binary Integration (Recommended)

First, build the ferret-scan binary:
```bash
make build
# This creates bin/ferret-scan
```

Create a `.pre-commit-config.yaml` file in your repository:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode
        language: system
        files: \.(txt|py|js|ts|go|java|json|yaml|yml|env|conf)$
        pass_filenames: true
```

**Alternative: Build from source (if binary not available):**
```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: go run cmd/main.go --config ferret.yaml --pre-commit-mode
        language: system
        files: \.(txt|py|js|ts|go|java|json|yaml|yml|env|conf)$
        pass_filenames: true
```

### 3. Python Package Integration

If you prefer using the Python package:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ferret-scan --config ferret.yaml --pre-commit-mode
        language: python
        files: \.(txt|py|js|ts|go|java|json|yaml|yml|env|conf)$
        pass_filenames: true
```

### 4. Install and Test

```bash
# Build the binary (if using direct binary integration)
make build

# Install the hooks
pre-commit install

# Test on all files
pre-commit run --all-files

# Test on specific files
pre-commit run --files sensitive-file.py
```

## Pre-commit Mode Features

When `--pre-commit-mode` is enabled, Ferret Scan automatically:

- **Enables quiet mode** - Reduces verbose output for cleaner pre-commit logs
- **Disables colors** - Ensures compatibility with all terminal environments  
- **Uses appropriate exit codes** - Returns 1 to block commits when high confidence findings are detected
- **Optimizes performance** - Uses efficient batch processing for multiple files
- **Respects file filtering** - Only processes files passed by pre-commit's file filtering

## Environment Detection

Ferret Scan automatically detects pre-commit environments by checking for:

- `PRE_COMMIT` environment variable
- `_PRE_COMMIT_RUNNING` environment variable  
- `PRE_COMMIT_HOME` environment variable

When detected, it automatically enables pre-commit optimizations even without the `--pre-commit-mode` flag.

## Configuration Options

### Basic Configuration

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
        args:
          - --confidence
          - high,medium
          - --checks
          - CREDIT_CARD,SECRETS,SSN
```

### Advanced Configuration with Environment Variables

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan - Custom
        entry: ./bin/ferret-scan --pre-commit-mode
        language: system
        files: \.(py|js|ts|go|java|json|yaml|yml)$
        exclude: (test_|_test\.|spec_|_spec\.|\.md$)
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_BATCH_SIZE: "25"
          FERRET_PRECOMMIT_EXIT_ON: "high"
          FERRET_PRECOMMIT_EXIT_ON_FIRST: "false"
```

### Environment Variables

| Variable | Options | Default | Description |
|----------|---------|---------|-------------|
| `FERRET_PRECOMMIT_BATCH_SIZE` | Number (1-100) | `50` | Files processed per batch |
| `FERRET_PRECOMMIT_EXIT_ON` | `high`, `medium`, `low`, `none` | `high` | When to block commits |
| `FERRET_PRECOMMIT_EXIT_ON_FIRST` | `true`, `false` | `false` | Exit on first finding |

## Team Configurations

### Security-Critical Projects

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-strict
        name: Ferret Scan - High Security
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high,medium --verbose
        language: system
        files: \.(py|js|ts|go|java|json|yaml|yml|env|conf)$
        exclude: (test_|_test\.|spec_|_spec\.)
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "medium"
```

### Development Teams (Advisory Mode)

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-advisory
        name: Ferret Scan - Advisory
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high,medium,low
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "none"  # Never block commits
```

### Balanced Approach

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-balanced
        name: Ferret Scan - Balanced
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high,medium
        language: system
        files: \.(py|js|ts|go|java|json|yaml|yml)$
        exclude: (test_|_test\.|docs/|README)
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "high"
```

## Configuration Requirements

**Important:** For ferret-scan to properly detect intellectual property (IP) and other sensitive data, you need a configuration file. The configuration file defines detection patterns, confidence levels, and validation rules.

### Required Configuration File

Create a `ferret.yaml` configuration file in your project root:

```bash
# Copy the example configuration
cp examples/ferret.yaml ferret.yaml

# Or download from the repository
curl -O https://raw.githubusercontent.com/your-org/ferret-scan/main/examples/ferret.yaml

# Commit the config file to your repository
git add ferret.yaml
git commit -m "Add ferret-scan configuration"
```

The configuration file includes:
- **IP detection patterns** - Internal URLs, cloud infrastructure, corporate networks
- **Validation rules** - Confidence scoring and pattern matching
- **Check types** - CREDIT_CARD, SECRETS, SSN, EMAIL, PHONE, IP_ADDRESS, INTELLECTUAL_PROPERTY
- **Preprocessor settings** - Document text extraction and metadata analysis

**Important for CI/CD:** The `ferret.yaml` file must be committed to your repository and available in the working directory where ferret-scan runs. All CI/CD examples above assume this file exists in the project root.

## Configuration Profiles

Create a `ferret.yaml` configuration file for team-wide settings:

```yaml
defaults:
  confidence_levels: "high,medium"
  checks: "CREDIT_CARD,SECRETS,SSN,EMAIL"

profiles:
  precommit:
    description: "Pre-commit optimized profile"
    confidence_levels: "high"
    checks: "CREDIT_CARD,SECRETS,SSN"
    quiet: true
    no_color: true
```

Reference the profile in your pre-commit config:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ./bin/ferret-scan --pre-commit-mode --profile precommit
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
```

## Multiple Hook Strategy

Use different configurations for different file types:

```yaml
repos:
  - repo: local
    hooks:
      # Strict scanning for configuration files
      - id: ferret-scan-config
        name: Ferret Scan - Config Files
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --checks SECRETS,EMAIL
        language: system
        files: \.(env|conf|config|ini|yaml|yml)$
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "medium"
      
      # Standard scanning for source code
      - id: ferret-scan-source
        name: Ferret Scan - Source Code
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "high"
```

## Suppression Management

Ferret Scan supports a sophisticated suppression system for handling false positives:

### Quick Suppression Setup

```bash
# Generate suppressions for existing code
./bin/ferret-scan --file . --recursive --generate-suppressions

# Review and enable legitimate suppressions
vim .ferret-scan-suppressions.yaml

# Keep suppressions local (recommended)
echo ".ferret-scan-suppressions.yaml" >> .gitignore
```

### Suppression File Example

```yaml
version: "1.0"
rules:
  - id: "SUP-00000001"
    hash: "d7cba2ce6b8361659c919a5dffc28886cb490a9e8f63aa04437207b701297282"
    reason: "Test credit card number in documentation"
    enabled: true
    created_at: "2024-01-15T10:30:00Z"
    metadata:
      finding_type: "CREDIT_CARD"
      filename: "README.md"
      line_number: "42"
```

### Using Suppressions with Pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --show-suppressed
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
```

## Performance Optimization

### File Filtering

Use specific file patterns to improve performance:

```yaml
# Good: Specific file types
files: \.(py|js|ts|go|java)$

# Better: Exclude unnecessary files
files: \.(py|js|ts|go|java)$
exclude: (test_|_test\.|spec_|_spec\.|node_modules/|\.git/)

# Best: Focus on critical files only
files: \.(py|js|ts|go)$
exclude: (test_|_test\.|docs/|examples/|\.md$)
```

### Batch Processing

Optimize batch size for your repository:

```yaml
env:
  FERRET_PRECOMMIT_BATCH_SIZE: "25"  # Smaller batches for large repos
  # or
  FERRET_PRECOMMIT_BATCH_SIZE: "100" # Larger batches for small repos
```

### Check Selection

Use specific checks instead of scanning everything:

```yaml
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --checks CREDIT_CARD,SECRETS,SSN
```

## Troubleshooting

### Common Issues

**1. "Binary not found" or "Command failed"**
```bash
# Build the ferret-scan binary (recommended)
make build

# Then use the binary in your config:
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode

# Or use go run as fallback:
entry: go run cmd/main.go --pre-commit-mode
```

**2. "Too many false positives"**
```bash
# Use suppressions (recommended)
./bin/ferret-scan --file . --recursive --generate-suppressions

# Or adjust confidence levels
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high
```

**3. "Scans are too slow"**
```bash
# Reduce file scope
files: \.(py|js|go)$  # Only critical file types

# Increase batch size
env:
  FERRET_PRECOMMIT_BATCH_SIZE: "100"

# Use specific checks
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --checks CREDIT_CARD,SECRETS
```

**4. "Different results between local and CI"**
```bash
# Ensure consistent configuration
# Use the same ferret.yaml file in both environments

# Check file paths and content
# Suppressions use exact hashes - any difference breaks matching
```

### Debug Mode

Enable debug output for troubleshooting:

```yaml
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --debug --verbose
```

### Testing Configuration

```bash
# Test without committing
pre-commit run ferret-scan --all-files

# Test on specific files
pre-commit run ferret-scan --files suspicious-file.py

# Bypass for legitimate commits
git commit --no-verify -m "Bypass scan for test data"
```

## Docker Integration

Ferret Scan provides excellent Docker support for containerized environments and CI/CD pipelines.

### Docker Pre-commit Integration

You can use the Docker container in pre-commit hooks:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-docker
        name: Ferret Scan - Docker
        entry: docker run --rm -v $(pwd):/data -v $(pwd)/ferret.yaml:/ferret.yaml ferret-scan:latest --config /ferret.yaml --pre-commit-mode
        language: system
        files: \.(py|js|ts|go|java|json|yaml|yml)$
        pass_filenames: true
        args: ["/data"]
```

### Using Finch (Docker Alternative)

For environments using Finch instead of Docker:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-finch
        name: Ferret Scan - Finch
        entry: finch run --rm -v $(pwd):/data -v $(pwd)/ferret.yaml:/ferret.yaml ferret-scan:latest --config /ferret.yaml --pre-commit-mode
        language: system
        files: \.(py|js|ts|go|java|json|yaml|yml)$
        pass_filenames: true
        args: ["/data"]
```

### Building the Docker Image

```bash
# Build the image
docker build -t ferret-scan .
# or with Finch
finch build -t ferret-scan .

# Test the image
docker run --rm ferret-scan --version
# or with Finch
finch run --rm ferret-scan --version
```

### Docker Container Features

- **Ultra-minimal size**: ~5-10MB using scratch base image
- **Security**: Runs as non-root user (ferret:1000)
- **Flexibility**: Supports both CLI and web modes
- **Performance**: Static binary with no runtime dependencies

### Docker Usage Examples

```bash
# CLI mode - scan files
docker run --rm -v $(pwd):/data ferret-scan --file /data --recursive

# Pre-commit mode
docker run --rm -v $(pwd):/data ferret-scan --pre-commit-mode /data/file.py

# Web UI mode
docker run --rm -p 8080:8080 ferret-scan --web --port 8080

# With configuration file
docker run --rm -v $(pwd):/data -v $(pwd)/ferret.yaml:/ferret.yaml ferret-scan --config /ferret.yaml --file /data
```

## CI/CD Integration

### GitLab CI/CD

Add Ferret Scan to your `.gitlab-ci.yml`:

```yaml
ferret-scan:
  stage: security
  image: ferret-scan:latest
  script:
    - ferret-scan --config ferret.yaml --file . --recursive --format gitlab-sast --output ferret-sast-report.json
  artifacts:
    reports:
      sast: ferret-sast-report.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitHub Actions

Add to your `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  ferret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Ferret Scan
        run: |
          docker run --rm -v ${{ github.workspace }}:/data \
            ferret-scan:latest --config /data/ferret.yaml --file /data --recursive \
            --format json --output /data/results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: ferret-scan-results
          path: results.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    docker.image('ferret-scan:latest').inside('-v ${WORKSPACE}:/data') {
                        sh 'ferret-scan --config /data/ferret.yaml --file /data --recursive --format json --output /data/results.json'
                    }
                }
                archiveArtifacts artifacts: 'results.json', fingerprint: true
            }
        }
    }
}
```

### Azure DevOps

Add to your `azure-pipelines.yml`:

```yaml
- task: Docker@2
  displayName: 'Run Ferret Scan'
  inputs:
    command: 'run'
    arguments: '--rm -v $(Build.SourcesDirectory):/data ferret-scan:latest --config /data/ferret.yaml --file /data --recursive --format json --output /data/results.json'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'results.json'
    artifactName: 'ferret-scan-results'
```

### Pre-commit in CI/CD

Many CI/CD systems can run pre-commit hooks directly:

```yaml
# GitLab CI example
pre-commit-scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install pre-commit
    - docker pull ferret-scan:latest
  script:
    - pre-commit run ferret-scan --all-files
```

## Integration Examples

### With Other Security Tools

```yaml
repos:
  # Ferret Scan for comprehensive sensitive data detection
  - repo: local
    hooks:
      - id: ferret-scan
        name: Ferret Scan
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true

  # Additional security tools
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        exclude: \.ferret-scan-suppressions\.yaml$

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: check-added-large-files
      - id: check-merge-conflict
```

### CI/CD Integration

For GitHub Actions, GitLab CI, or other CI systems:

```yaml
repos:
  - repo: local
    hooks:
      - id: ferret-scan-ci
        name: Ferret Scan - CI
        entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --format junit --output ferret-results.xml
        language: system
        files: \.(py|js|ts|go|java)$
        pass_filenames: true
        env:
          FERRET_PRECOMMIT_EXIT_ON: "high"
```

## Best Practices

### 1. Start Gradually
- Begin with advisory mode (`FERRET_PRECOMMIT_EXIT_ON: "none"`)
- Let the team learn what sensitive data looks like
- Gradually increase strictness

### 2. Use Appropriate Scope
- Focus on files that could contain real sensitive data
- Exclude test files, documentation, and generated code
- Use specific file patterns for better performance

### 3. Team Alignment
- Create a shared `ferret.yaml` configuration file
- Document your configuration choices in README
- Train team on using `--no-verify` when appropriate
- Set up suppressions for known false positives

### 4. Performance Optimization
- Use specific file patterns instead of scanning everything
- Adjust batch size based on repository size
- Consider using specific check types instead of "all"

### 5. Suppression Strategy
- Keep suppressions local to each developer (recommended)
- Or use shared suppressions for team consistency
- Regular review of suppressions to ensure they're still valid
- Use expiration dates for temporary suppressions

## Migration from Old Systems

If you're migrating from wrapper scripts or other pre-commit integrations:

### Remove Old Files
```bash
# Remove old wrapper scripts
rm -f scripts/enhanced-pre-commit-wrapper.sh
rm -f scripts/setup-pre-commit.sh

# Remove old configuration files
rm -f .pre-commit-config-advisory.yaml
```

### Update Configuration
Replace old wrapper-based configurations with direct integration:

```yaml
# OLD (remove this)
entry: scripts/enhanced-pre-commit-wrapper.sh
env:
  FERRET_CONFIDENCE: "high"
  FERRET_FAIL_ON: "high"

# NEW (use this)
entry: ./bin/ferret-scan --config ferret.yaml --pre-commit-mode --confidence high
env:
  FERRET_PRECOMMIT_EXIT_ON: "high"
```

### Test Migration
```bash
# Test the new configuration
pre-commit run ferret-scan --all-files

# Compare results with old system to ensure consistency
```

## Support

For additional help:
- Run `./bin/ferret-scan --help` for all command-line options
- Check `ferret.yaml` configuration examples
- See `docs/suppression-system.md` for detailed suppression documentation
- Use `--debug --verbose` flags for detailed troubleshooting
- Review the integration test examples in `tests/integration/precommit_*_test.go`