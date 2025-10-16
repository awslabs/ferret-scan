# GitLab CI/CD Setup for Ferret Scan

[← Back to Documentation Index](../README.md)

This document explains how to set up and use the GitLab CI/CD pipeline for Ferret Scan, optimized for GitLab Ultimate with GitLab Duo.

## Pipeline Overview

The GitLab CI/CD pipeline includes the following stages:

1. **Build**: Compile the application and create artifacts
2. **Test**: Run unit tests, integration tests, and race detection
3. **Security**: SAST, Secret Detection, Dependency Scanning, License Scanning
4. **Quality**: Code quality analysis and coverage reporting
5. **Benchmark**: Performance benchmarks (main branch only)
6. **Deploy**: Docker builds, GitLab Pages, and releases

## GitLab Ultimate Features Used

### Security Scanning
- **SAST (Static Application Security Testing)**: Automatic code vulnerability detection
- **Secret Detection**: Prevents secrets from being committed
- **Dependency Scanning**: Identifies vulnerable dependencies
- **License Scanning**: Ensures license compliance

### Code Quality
- **Code Quality Reports**: Integrated with merge requests
- **Coverage Visualization**: Built-in coverage tracking and visualization
- **Test Reports**: JUnit XML integration for test result visualization

### Container Registry
- **Docker Image Storage**: Automatic image builds and storage
- **Vulnerability Scanning**: Container image security scanning

### GitLab Pages
- **Coverage Reports**: Automated deployment of HTML coverage reports
- **Documentation**: Automatic documentation hosting

## Pipeline Configuration

### Environment Variables

The pipeline uses these environment variables (automatically set):

```yaml
variables:
  FERRET_TEST_MODE: "true"          # Enable AWS mocking
  AWS_ACCESS_KEY_ID: "test-key"     # Mock AWS credentials
  AWS_SECRET_ACCESS_KEY: "test-secret"
  AWS_REGION: "us-east-1"
```

### Caching

Go modules and build cache are cached between jobs for faster execution:

```yaml
cache:
  key: "${CI_JOB_NAME}-${CI_COMMIT_REF_SLUG}"
  paths:
    - .cache/go-build/
    - .cache/go-mod/
    - .go/pkg/mod/
```

## Job Details

### Build Jobs

#### `build`
- Compiles the application
- Creates binary artifacts
- Runs on all branches and merge requests

#### `docker:build`
- Builds Docker image
- Tests Docker functionality
- Pushes to GitLab Container Registry (main branch/tags only)

### Test Jobs

#### `test:unit`
- Fast unit tests with no external dependencies
- Generates JUnit XML reports
- Produces coverage reports
- Runs on all merge requests and main branch

#### `test:integration`
- Integration tests with mocked AWS services
- Tests complete workflows
- Generates separate JUnit reports

#### `test:race`
- Race condition detection
- Allowed to fail (warning only)

#### Multi-version Testing
- `test:go-1.21`, `test:go-1.22`, `test:go-1.23`
- Ensures compatibility across Go versions

### Security Jobs

#### `security:sast`
- Static Application Security Testing
- Excludes test directories from scanning
- Automatic vulnerability detection

#### `security:secret-detection`
- Prevents secrets in code
- Excludes test data directories

#### `security:dependency-scanning`
- Scans Go modules for vulnerabilities
- Provides security advisories

#### `license_scanning`
- Ensures license compliance
- Tracks open source dependencies

### Quality Jobs

#### `code_quality`
- Runs golangci-lint
- Generates Code Climate reports
- Integrates with merge request discussions

#### `coverage`
- Detailed coverage analysis
- GitLab Ultimate coverage visualization
- Coverage badges and trends

### Performance Jobs

#### `benchmark`
- Performance benchmarks
- Runs on main branch and tags only
- Tracks performance regressions

### Deployment Jobs

#### `pages`
- Deploys coverage reports to GitLab Pages
- Hosts documentation
- Available at `https://your-group.gitlab.io/ferret-scan`

#### `release`
- Creates release artifacts for tagged versions
- Builds versioned binaries
- Long-term artifact storage

## Merge Request Integration

### Automatic Checks
When you create a merge request, the pipeline automatically:

1. **Builds** the application
2. **Runs tests** (unit and integration)
3. **Performs security scans**
4. **Analyzes code quality**
5. **Generates coverage reports**

### Merge Request Widgets
GitLab Ultimate provides widgets showing:
- **Test Results**: Pass/fail status with details
- **Coverage Changes**: Coverage diff from target branch
- **Security Findings**: New vulnerabilities introduced
- **Code Quality**: New issues or improvements
- **License Compliance**: License compatibility

### Approval Rules
You can configure approval rules based on:
- Security scan results
- Coverage thresholds
- Code quality gates

## Branch Protection

### Main Branch
- Requires successful pipeline
- Requires merge request approval
- Runs full test suite including benchmarks
- Builds and pushes Docker images

### Feature Branches
- Runs core tests and security scans
- Provides fast feedback
- Blocks merge on test failures

## Monitoring and Alerts

### Pipeline Notifications
Configure notifications for:
- Pipeline failures
- Security vulnerabilities
- Coverage drops
- Performance regressions

### GitLab Duo Integration
GitLab Duo can help with:
- **Code Suggestions**: AI-powered code completion
- **Vulnerability Explanations**: AI explanations of security findings
- **Test Generation**: AI-assisted test creation
- **Code Review**: AI-powered code review suggestions

## Local Development

### Running Tests Locally
```bash
# Set up test environment
export FERRET_TEST_MODE=true

# Run the same tests as CI
make test-unit
make test-integration
make test-race

# Generate coverage like CI
make test-coverage
```

### Pre-commit Testing
```bash
# Run quick validation before pushing
./scripts/run-tests.sh -t unit -v

# Run full test suite
./scripts/run-tests.sh
```

## Troubleshooting

### Common Issues

#### Pipeline Fails on Dependencies
```bash
# Clear Go module cache
rm -rf .cache/go-mod/
git push --force-with-lease
```

#### Security Scan False Positives
Add to `.gitlab-ci.yml`:
```yaml
security:sast:
  variables:
    SAST_EXCLUDED_PATHS: "tests/, testdata/, specific-file.go"
```

#### Coverage Not Updating
Ensure coverage format is correct:
```yaml
coverage: '/total:\s+\(statements\)\s+(\d+\.\d+)%/'
```

#### Docker Build Failures
Check Docker service availability:
```yaml
services:
  - docker:24-dind
```

### Getting Help

1. **Pipeline Logs**: Check detailed logs in GitLab CI/CD → Pipelines
2. **Security Dashboard**: View security findings in GitLab Ultimate
3. **Coverage Reports**: Access via GitLab Pages or merge request widgets
4. **GitLab Duo**: Ask AI assistant for help with pipeline issues

## Best Practices

### Performance Optimization
- Use caching for Go modules and build artifacts
- Run expensive jobs only on main branch
- Parallelize independent jobs

### Security
- Exclude test data from security scans
- Use GitLab Ultimate security features
- Review security findings before merging

### Quality Gates
- Set coverage thresholds
- Require code quality improvements
- Use approval rules for sensitive changes

### Monitoring
- Set up pipeline failure notifications
- Monitor coverage trends
- Track performance benchmarks

This GitLab CI/CD setup provides comprehensive testing, security scanning, and quality assurance while leveraging GitLab Ultimate's advanced features for better development workflows.
