# GitLab Integration Guide

[← Back to Documentation Index](README.md)

This guide covers how to integrate Ferret Scan with GitLab Ultimate, including CI/CD pipelines, security scanning, and GitLab Duo features.

## Quick Start

1. **Add the pipeline configuration**:
   ```bash
   # The .gitlab-ci.yml file is already included in the repository
   git add .gitlab-ci.yml
   git commit -m "Add GitLab CI/CD pipeline"
   git push
   ```

2. **Enable GitLab Ultimate features**:
   - Go to Project Settings → General → Visibility, project features, permissions
   - Enable: Security and Compliance, Container Registry, Pages
   - Configure merge request approvals if desired

3. **Create your first merge request**:
   - The pipeline will automatically run tests, security scans, and quality checks
   - View results in the merge request widgets

## GitLab Security Scanner Integration

Ferret Scan integrates natively with GitLab as a security scanner, providing sensitive data detection results directly in GitLab's Security Dashboard and merge request widgets.

### GitLab SAST Report Format

Ferret Scan generates GitLab-compatible security reports using the `--format gitlab-sast` option:

```bash
# Generate GitLab Security Report
ferret-scan --file . --recursive --format gitlab-sast --output gl-sast-report.json
```

**Key Features:**
- **Schema Compliance**: Follows GitLab Security Report schema v15.0.4
- **Vulnerability Mapping**: Maps Ferret findings to GitLab vulnerability format
- **Confidence Levels**: High→Critical, Medium→High, Low→Medium severity mapping
- **Location Information**: Precise file paths and line numbers
- **Sanitized Output**: Sensitive data is never exposed in vulnerability descriptions

### Security Dashboard Integration

Once configured, Ferret Scan findings appear in:

1. **Project Security Dashboard**: View all sensitive data vulnerabilities
2. **Merge Request Widgets**: See new findings introduced in MRs
3. **Vulnerability Management**: Dismiss, track, and manage findings
4. **Security Policies**: Set approval rules based on security findings

### Example GitLab Security Report Output

```json
{
  "version": "15.0.4",
  "vulnerabilities": [
    {
      "id": "ferret-a1b2c3d4",
      "category": "sast",
      "name": "Credit Card Number Detected",
      "message": "Potential credit card number found",
      "description": "A pattern matching credit card format was detected in this location",
      "severity": "Critical",
      "confidence": "High",
      "location": {
        "file": "src/payment.js",
        "start_line": 42,
        "end_line": 42
      }
    }
  ],
  "scan": {
    "analyzer": {
      "id": "ferret-scan",
      "name": "Ferret Scan",
      "version": "v0.4.1"
    },
    "type": "sast",
    "status": "success"
  }
}
```

## GitLab Ultimate Features

### Security Dashboard
Access comprehensive security insights:
- **Vulnerability Report**: View all security findings across the project including Ferret Scan results
- **Dependency List**: Track all dependencies and their licenses
- **Security Policies**: Set up security approval rules for sensitive data findings

### Merge Request Security Widget
Each merge request shows:
- **Security Scanning Results**: New sensitive data vulnerabilities introduced
- **Ferret Scan Findings**: Dedicated section for sensitive data detection
- **License Compliance**: License compatibility status
- **Dependency Changes**: New or updated dependencies

### Code Quality Integration
- **Code Quality Reports**: Integrated with golangci-lint
- **Coverage Visualization**: Built-in coverage tracking
- **Performance Impact**: Track performance changes

## CI/CD Pipeline Stages

### 1. Build Stage
```yaml
build:
  stage: build
  script:
    - make build
  artifacts:
    paths:
      - bin/ferret-scan
```

### 2. Test Stage
```yaml
test:unit:
  stage: test
  script:
    - make test-unit
  artifacts:
    reports:
      junit: junit-report.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```

### 3. Security Stage
```yaml
# Ferret Scan as GitLab Security Scanner
ferret-sast:
  stage: security
  image: $GO_DOCKER_IMAGE
  dependencies:
    - build
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

# Additional GitLab security templates (optional)
include:
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
```

### 4. Quality Stage
```yaml
code_quality:
  stage: quality
  script:
    - golangci-lint run --out-format code-climate > gl-code-quality-report.json
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

## GitLab Container Registry

### Automatic Docker Builds
The pipeline automatically builds and pushes Docker images:

```yaml
docker:build:
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

### Using the Container Registry
```bash
# Pull the latest image
docker pull registry.gitlab.com/your-group/ferret-scan:latest

# Run security scan
docker run --rm -v $(pwd):/workspace \
  registry.gitlab.com/your-group/ferret-scan:latest \
  --file /workspace --recursive --format json
```

## GitLab Pages Integration

### Coverage Reports
Coverage reports are automatically deployed to GitLab Pages:
- **URL**: `https://your-group.gitlab.io/ferret-scan/coverage.html`
- **Updates**: Automatically updated on main branch pushes

### Documentation Hosting
Project documentation is also hosted on GitLab Pages:
- **URL**: `https://your-group.gitlab.io/ferret-scan/`
- **Content**: All markdown files from the `docs/` directory

## GitLab Duo AI Features

<!-- GENAI_DISABLED: Code Suggestions
GitLab Duo provides AI-powered assistance:
- **Code Completion**: Intelligent code suggestions while editing
- **Test Generation**: AI-assisted test case creation
-->
- **Code Explanation**: AI explanations of complex code sections

<!-- GENAI_DISABLED: Security Insights
- **Vulnerability Explanations**: AI-powered explanations of security findings
- **Remediation Suggestions**: AI-suggested fixes for security issues
- **Risk Assessment**: AI-powered risk analysis
-->

<!-- GENAI_DISABLED: Code Review Assistance
- **Review Summaries**: AI-generated merge request summaries
- **Code Quality Suggestions**: AI-powered code improvement suggestions
- **Documentation Generation**: AI-assisted documentation creation
-->

## Merge Request Workflow

### Automatic Checks
When creating a merge request:

1. **Pipeline Triggers**: Automatically runs full test suite
2. **Security Scanning**: SAST, secret detection, dependency scanning
3. **Code Quality**: Linting and quality analysis
4. **Coverage Analysis**: Coverage diff from target branch

### Merge Request Widgets
GitLab displays widgets showing:
- **Test Results**: ✅ 45 tests passed, ❌ 2 tests failed
- **Coverage**: 📊 Coverage increased by 2.3%
- **Security**: 🔒 No new vulnerabilities found
- **Code Quality**: 📈 Code quality improved

### Approval Rules
Configure approval requirements:
```yaml
# In .gitlab-ci.yml or project settings
approval_rules:
  - name: "Security Review"
    rule_type: "security"
    approvals_required: 1
  - name: "Coverage Gate"
    rule_type: "coverage"
    coverage_threshold: 80
```

## Environment-Specific Deployments

### Staging Environment
```yaml
deploy:staging:
  stage: deploy
  script:
    - docker run --rm -v $(pwd):/workspace ferret-scan:$CI_COMMIT_SHA --file /workspace/staging-data
  environment:
    name: staging
    url: https://staging.example.com
  rules:
    - if: $CI_COMMIT_BRANCH == "develop"
```

### Production Environment
```yaml
deploy:production:
  stage: deploy
  script:
    - docker run --rm -v $(pwd):/workspace ferret-scan:$CI_COMMIT_SHA --file /workspace/production-data
  environment:
    name: production
    url: https://production.example.com
  rules:
    - if: $CI_COMMIT_TAG
  when: manual
```

## Monitoring and Alerting

### Pipeline Notifications
Configure notifications in Project Settings → Integrations:
- **Slack Integration**: Pipeline status updates
- **Email Notifications**: Failure alerts
- **Webhook Integration**: Custom integrations

### Security Monitoring
- **Security Dashboard**: Monitor security trends
- **Vulnerability Alerts**: Automatic notifications for new vulnerabilities
- **Compliance Reports**: Regular compliance status reports

## Best Practices

### Branch Protection
Configure branch protection rules:
- **Require merge request**: Prevent direct pushes to main
- **Require pipeline success**: Block merges on test failures
- **Require approvals**: Require code review approvals

### Security Configuration
```yaml
# Exclude test data from security scans
security:sast:
  variables:
    SAST_EXCLUDED_PATHS: "tests/, testdata/, mocks/"

security:secret-detection:
  variables:
    SECRET_DETECTION_EXCLUDED_PATHS: "tests/testdata/"
```

### Performance Optimization
```yaml
# Cache Go modules for faster builds
cache:
  key: "${CI_JOB_NAME}-${CI_COMMIT_REF_SLUG}"
  paths:
    - .cache/go-build/
    - .cache/go-mod/
    - .go/pkg/mod/
```

## Troubleshooting

For comprehensive troubleshooting information, see the **[GitLab Integration Troubleshooting Guide](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md)**.

### Common Issues

#### Pipeline Fails on First Run
- **Cause**: Missing GitLab Ultimate features
- **Solution**: Enable Security and Compliance features in project settings

#### Security Scans Report False Positives
- **Cause**: Test data triggering security alerts
- **Solution**: Add exclusions to security scan configuration

#### Coverage Reports Not Showing
- **Cause**: Incorrect coverage format
- **Solution**: Verify coverage regex pattern in pipeline configuration

#### Docker Build Failures
- **Cause**: Docker-in-Docker not properly configured
- **Solution**: Ensure `docker:dind` service is enabled

### Getting Support
- **GitLab Documentation**: https://docs.gitlab.com/
- **GitLab Support**: Available with GitLab Ultimate
- **Community Forum**: https://forum.gitlab.com/
- **GitLab Duo**: Ask AI assistant for help

## Additional Resources

### Setup and Configuration
- **[GitLab Security Scanner Setup Guide](deployment/GITLAB_SECURITY_SCANNER_SETUP.md)** - Complete step-by-step setup instructions
- **[GitLab Integration Troubleshooting](troubleshooting/GITLAB_INTEGRATION_TROUBLESHOOTING.md)** - Common issues and solutions

### Related Documentation
- **[Architecture Diagram](architecture-diagram.md)** - Technical architecture including GitLab SAST formatter
- **[Configuration Guide](configuration.md)** - YAML configuration for GitLab integration
- **[CI/CD Setup Guide](deployment/GITLAB_CI_SETUP.md)** - General GitLab CI/CD configuration

This integration provides a comprehensive development workflow with automated testing, security scanning, and quality assurance using GitLab Ultimate's advanced features.
