# GitLab Security Scanner Setup Guide

[← Back to GitLab Integration](../GITLAB_INTEGRATION.md) | [← Back to Documentation Index](../README.md)

This guide provides step-by-step instructions for setting up Ferret Scan as a GitLab security scanner with complete Security Dashboard integration.

## Prerequisites

- GitLab Ultimate or GitLab.com Premium/Ultimate
- Project with CI/CD pipelines enabled
- Ferret Scan binary or container image available

## Quick Setup (5 Minutes)

### Step 1: Update GitLab CI Configuration

Add the Ferret SAST job to your `.gitlab-ci.yml`:

```yaml
stages:
  - build
  - test
  - security
  - deploy

# Build Ferret Scan (if building from source)
build:ferret:
  stage: build
  image: golang:1.21
  script:
    - make build
  artifacts:
    paths:
      - bin/ferret-scan
    expire_in: 1 hour

# Ferret Scan Security Scanner
ferret-sast:
  stage: security
  image: golang:1.21  # or use ferret-scan container image
  dependencies:
    - build:ferret
  script:
    - echo "Running Ferret Scan security analysis..."
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --confidence all --output gl-sast-report.json --no-color --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - gl-sast-report.json
    expire_in: 1 week
  allow_failure: true
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### Step 2: Enable Security Features

1. Go to **Project Settings** → **General** → **Visibility, project features, permissions**
2. Enable **Security and Compliance**
3. Save changes

### Step 3: Test the Integration

1. Create a test file with sensitive data:
   ```bash
   echo "Credit Card: 4111-1111-1111-1111" > test-sensitive.txt
   git add test-sensitive.txt
   git commit -m "Add test file for security scanning"
   git push
   ```

2. Check the pipeline results in **CI/CD** → **Pipelines**
3. View security findings in **Security & Compliance** → **Vulnerability Report**

## Detailed Setup Options

### Option 1: Using Pre-built Container

```yaml
ferret-sast:
  stage: security
  image: registry.gitlab.com/your-group/ferret-scan:latest
  script:
    - ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Option 2: Using System Installation

```yaml
ferret-sast:
  stage: security
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y wget
    - wget -O ferret-scan https://github.com/your-org/ferret-scan/releases/latest/download/ferret-scan-linux-amd64
    - chmod +x ferret-scan
  script:
    - ./ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json --quiet
```

### Option 3: Building from Source

```yaml
variables:
  GO_VERSION: "1.21"

build:ferret:
  stage: build
  image: golang:${GO_VERSION}
  script:
    - go version
    - make build
  artifacts:
    paths:
      - bin/ferret-scan
    expire_in: 1 hour

ferret-sast:
  stage: security
  image: golang:${GO_VERSION}
  dependencies:
    - build:ferret
  script:
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json --quiet
```

## Advanced Configuration

### Custom Scan Configuration

Create a `.ferret-scan.yaml` configuration file:

```yaml
# .ferret-scan.yaml
defaults:
  format: "gitlab-sast"
  confidence_levels: "high,medium"
  checks: "CREDIT_CARD,SSN,SECRETS,EMAIL"
  recursive: true
  no_color: true
  quiet: true

profiles:
  security-audit:
    description: "Security audit profile for GitLab CI"
    confidence_levels: "high"
    checks: "CREDIT_CARD,SSN,SECRETS"
    verbose: false
```

Update your GitLab CI job:

```yaml
ferret-sast:
  stage: security
  script:
    - ./bin/ferret-scan --config .ferret-scan.yaml --profile security-audit --output gl-sast-report.json
```

### Conditional Scanning

Scan only specific file types or directories:

```yaml
ferret-sast:
  stage: security
  script:
    # Scan only source code files
    - ./bin/ferret-scan --file "src/" --recursive --format gitlab-sast --output gl-sast-report.json

    # Or scan specific file patterns
    - find . -name "*.py" -o -name "*.js" -o -name "*.java" | xargs ./bin/ferret-scan --format gitlab-sast --output gl-sast-report.json
```

### Multi-Environment Scanning

```yaml
.ferret-scan-template: &ferret-scan
  stage: security
  script:
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json --quiet
  artifacts:
    reports:
      sast: gl-sast-report.json

ferret-sast:development:
  <<: *ferret-scan
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"

ferret-sast:production:
  <<: *ferret-scan
  script:
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --confidence high --output gl-sast-report.json --quiet
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## Security Dashboard Configuration

### Viewing Results

1. **Project Level**: Go to **Security & Compliance** → **Vulnerability Report**
2. **Merge Request Level**: Security widget appears automatically in MR interface
3. **Pipeline Level**: View security tab in pipeline details

### Managing Vulnerabilities

**Dismissing Findings:**
1. Click on a vulnerability in the Security Dashboard
2. Select **Dismiss vulnerability**
3. Choose dismissal reason:
   - False positive
   - Acceptable risk
   - Used in tests
   - Not applicable

**Creating Issues:**
1. Click **Create issue** from vulnerability details
2. Issue is automatically populated with vulnerability information
3. Assign to team members for remediation

### Security Policies

Create security approval rules:

```yaml
# .gitlab/security-policies/scan-execution-policy.yml
scan_execution_policy:
  - name: Ferret Scan Policy
    description: Run Ferret Scan on all merge requests
    enabled: true
    rules:
      - type: pipeline
        branches:
          - main
          - develop
    actions:
      - scan: sast
```

## Troubleshooting

### Common Issues

#### 1. Security Reports Not Appearing

**Problem**: GitLab doesn't show security findings

**Solutions**:
- Verify GitLab Ultimate/Premium license
- Check that `artifacts.reports.sast` points to correct file
- Ensure JSON output is valid GitLab security report format
- Verify Security & Compliance features are enabled

#### 2. Pipeline Fails with Permission Errors

**Problem**: `ferret-scan` command not found or permission denied

**Solutions**:
```yaml
before_script:
  - chmod +x ./bin/ferret-scan  # Make binary executable
  - ls -la ./bin/ferret-scan    # Verify file exists
```

#### 3. Large Repository Timeouts

**Problem**: Scan times out on large repositories

**Solutions**:
```yaml
ferret-sast:
  timeout: 30m  # Increase timeout
  script:
    # Scan only specific directories
    - ./bin/ferret-scan --file "src/" --recursive --format gitlab-sast --output gl-sast-report.json
```

#### 4. Too Many False Positives

**Problem**: Security dashboard shows many false positives

**Solutions**:
1. Use suppression files:
   ```yaml
   script:
     - ./bin/ferret-scan --file . --suppression-file .ferret-suppressions.yaml --format gitlab-sast --output gl-sast-report.json
   ```

2. Adjust confidence levels:
   ```yaml
   script:
     - ./bin/ferret-scan --file . --confidence high --format gitlab-sast --output gl-sast-report.json
   ```

#### 5. Invalid Security Report Format

**Problem**: GitLab rejects the security report

**Solutions**:
- Verify output file is valid JSON
- Check GitLab security report schema compliance
- Enable debug mode to see detailed error messages:
  ```yaml
  script:
    - ./bin/ferret-scan --file . --format gitlab-sast --debug --output gl-sast-report.json
  ```

### Validation Commands

Test your setup locally:

```bash
# Generate report locally
./ferret-scan --file . --recursive --format gitlab-sast --output test-report.json

# Validate JSON format
cat test-report.json | jq .

# Check report structure
jq '.version, .vulnerabilities | length, .scan.status' test-report.json
```

### Getting Help

- **GitLab Documentation**: [Security Reports](https://docs.gitlab.com/ee/user/application_security/)
- **Ferret Scan Issues**: [GitHub Issues](https://github.com/your-org/ferret-scan/issues)
- **GitLab Support**: Available with GitLab Ultimate subscription

## Best Practices

### 1. Performance Optimization

```yaml
ferret-sast:
  stage: security
  cache:
    key: ferret-scan-cache
    paths:
      - .ferret-cache/
  script:
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json --quiet
```

### 2. Selective Scanning

```yaml
# Only scan on merge requests and main branch
ferret-sast:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_TAG
```

### 3. Parallel Scanning

```yaml
# Split scanning across multiple jobs for large repositories
ferret-sast:source:
  extends: .ferret-template
  script:
    - ./bin/ferret-scan --file "src/" --recursive --format gitlab-sast --output gl-sast-source.json

ferret-sast:config:
  extends: .ferret-template
  script:
    - ./bin/ferret-scan --file "config/" --recursive --format gitlab-sast --output gl-sast-config.json
```

### 4. Integration with Other Security Tools

```yaml
security:
  stage: security
  parallel:
    matrix:
      - SECURITY_TOOL: [ferret-scan, semgrep, bandit]
  script:
    - case $SECURITY_TOOL in
        ferret-scan) ./bin/ferret-scan --format gitlab-sast --output ${SECURITY_TOOL}-report.json ;;
        semgrep) semgrep --config=auto --gitlab-sast --output=${SECURITY_TOOL}-report.json ;;
        bandit) bandit -r . -f json -o ${SECURITY_TOOL}-report.json ;;
      esac
  artifacts:
    reports:
      sast: ${SECURITY_TOOL}-report.json
```

This setup provides comprehensive sensitive data detection integrated directly into your GitLab security workflow.
