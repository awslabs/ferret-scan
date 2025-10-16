# GitLab Integration Troubleshooting Guide

[← Back to GitLab Integration](../GITLAB_INTEGRATION.md) | [← Back to Documentation Index](../README.md)

This guide helps resolve common issues when integrating Ferret Scan with GitLab as a security scanner.

## Quick Diagnostics

### Check Integration Status

Run these commands to verify your GitLab integration:

```bash
# 1. Test GitLab SAST format generation
./ferret-scan --file . --format gitlab-sast --output test-report.json

# 2. Validate JSON structure
cat test-report.json | jq .

# 3. Check required fields
jq '.version, .vulnerabilities, .scan' test-report.json

# 4. Verify schema compliance
jq '.scan.analyzer.id, .scan.type, .scan.status' test-report.json
```

### Verify GitLab Configuration

```bash
# Check GitLab CI configuration
grep -A 10 -B 5 "ferret-sast" .gitlab-ci.yml

# Verify artifacts configuration
grep -A 5 "artifacts:" .gitlab-ci.yml | grep -A 3 "reports:"
```

## Common Issues and Solutions

### 1. Security Reports Not Appearing in GitLab

#### Symptoms
- Pipeline succeeds but no security findings in Security Dashboard
- Merge request security widget is empty
- "No vulnerabilities found" message despite known issues

#### Root Causes and Solutions

**A. GitLab License Issues**
```bash
# Check if GitLab Ultimate/Premium features are available
# Go to Project Settings → General → Visibility, project features, permissions
# Ensure "Security and Compliance" is enabled
```

**B. Incorrect Artifact Configuration**
```yaml
# ❌ Wrong - missing reports section
artifacts:
  paths:
    - gl-sast-report.json

# ✅ Correct - includes reports.sast
artifacts:
  reports:
    sast: gl-sast-report.json
  paths:
    - gl-sast-report.json
```

**C. Invalid JSON Format**
```bash
# Debug: Check if JSON is valid
./ferret-scan --file . --format gitlab-sast --output debug-report.json
cat debug-report.json | jq . || echo "Invalid JSON"

# Common JSON issues:
# - Missing closing braces
# - Trailing commas
# - Invalid escape sequences
```

**D. Schema Validation Errors**
```bash
# Verify required GitLab security report fields
jq 'has("version") and has("vulnerabilities") and has("scan")' test-report.json

# Check scan object structure
jq '.scan | has("analyzer") and has("type") and has("status")' test-report.json
```

### 2. Pipeline Failures

#### Symptoms
- `ferret-scan: command not found`
- Permission denied errors
- Pipeline timeout

#### Solutions

**A. Binary Not Found**
```yaml
# ❌ Problem: Binary not available
ferret-sast:
  script:
    - ferret-scan --format gitlab-sast --output report.json

# ✅ Solution: Ensure binary is available
ferret-sast:
  dependencies:
    - build  # Job that creates the binary
  script:
    - ls -la bin/ferret-scan  # Verify binary exists
    - ./bin/ferret-scan --format gitlab-sast --output report.json
```

**B. Permission Issues**
```yaml
# ✅ Solution: Make binary executable
ferret-sast:
  before_script:
    - chmod +x ./bin/ferret-scan
  script:
    - ./bin/ferret-scan --format gitlab-sast --output report.json
```

**C. Timeout Issues**
```yaml
# ✅ Solution: Increase timeout and optimize scanning
ferret-sast:
  timeout: 30m  # Increase from default 1h
  script:
    # Scan only relevant directories
    - ./bin/ferret-scan --file "src/" --recursive --format gitlab-sast --output report.json
    # Or use higher confidence levels to reduce processing
    - ./bin/ferret-scan --file . --confidence high --format gitlab-sast --output report.json
```

### 3. Too Many False Positives

#### Symptoms
- Security Dashboard flooded with false positives
- Legitimate test data flagged as vulnerabilities
- Development/staging data causing alerts

#### Solutions

**A. Use Suppression Files**
```yaml
# Create .ferret-suppressions.yaml
suppressions:
  - id: "test-data-credit-cards"
    pattern: "test-credit-card-data.txt"
    reason: "Test data file"
    enabled: true

# Update GitLab CI
ferret-sast:
  script:
    - ./bin/ferret-scan --suppression-file .ferret-suppressions.yaml --format gitlab-sast --output report.json
```

**B. Adjust Confidence Levels**
```yaml
# Only report high confidence findings
ferret-sast:
  script:
    - ./bin/ferret-scan --confidence high --format gitlab-sast --output report.json
```

**C. Exclude Test Directories**
```yaml
# Scan only production code
ferret-sast:
  script:
    - ./bin/ferret-scan --file "src/" --recursive --format gitlab-sast --output report.json
    # Avoid scanning test/, testdata/, mock/ directories
```

### 4. Missing Vulnerability Details

#### Symptoms
- Vulnerabilities appear but lack details
- Missing file locations or line numbers
- Generic vulnerability descriptions

#### Solutions

**A. Enable Verbose Output for Debugging**
```bash
# Debug locally with verbose output
./ferret-scan --file . --format gitlab-sast --verbose --debug --output debug-report.json
```

**B. Check File Processing**
```yaml
# Ensure preprocessors are enabled for document scanning
ferret-sast:
  script:
    - ./bin/ferret-scan --enable-preprocessors --format gitlab-sast --output report.json
```

**C. Verify Content Extraction**
```bash
# Test preprocessing separately
./ferret-scan --file problematic-file.pdf --preprocess-only --verbose
```

### 5. Performance Issues

#### Symptoms
- Very slow pipeline execution
- High memory usage
- Pipeline runner resource exhaustion

#### Solutions

**A. Optimize Scanning Scope**
```yaml
# Scan specific file types only
ferret-sast:
  script:
    - find . -name "*.py" -o -name "*.js" -o -name "*.java" | head -1000 | xargs ./bin/ferret-scan --format gitlab-sast --output report.json
```

**B. Use Parallel Processing**
```yaml
# Split large repositories across multiple jobs
ferret-sast:source:
  script:
    - ./bin/ferret-scan --file "src/" --format gitlab-sast --output source-report.json
  artifacts:
    reports:
      sast: source-report.json

ferret-sast:config:
  script:
    - ./bin/ferret-scan --file "config/" --format gitlab-sast --output config-report.json
  artifacts:
    reports:
      sast: config-report.json
```

**C. Resource Optimization**
```yaml
ferret-sast:
  variables:
    # Limit memory usage
    GOMAXPROCS: "2"
  script:
    - ./bin/ferret-scan --file . --format gitlab-sast --quiet --output report.json
```

### 6. Schema Validation Failures

#### Symptoms
- GitLab rejects security report
- "Invalid security report format" errors
- Missing required fields warnings

#### Solutions

**A. Validate Report Structure**
```bash
# Check required top-level fields
jq 'keys' test-report.json
# Should include: ["scan", "version", "vulnerabilities"]

# Validate vulnerability structure
jq '.vulnerabilities[0] | keys' test-report.json
# Should include: ["category", "confidence", "description", "id", "location", "message", "name", "severity"]
```

**B. Fix Common Schema Issues**
```bash
# Check version format
jq '.version' test-report.json
# Should be: "15.0.4"

# Verify scan type
jq '.scan.type' test-report.json
# Should be: "sast"

# Check analyzer information
jq '.scan.analyzer' test-report.json
# Should include id, name, version
```

**C. Debug Schema Compliance**
```yaml
# Add validation step to pipeline
ferret-sast:
  script:
    - ./bin/ferret-scan --format gitlab-sast --output report.json
    - echo "Validating report structure..."
    - jq '.version, .scan.type, (.vulnerabilities | length)' report.json
  artifacts:
    reports:
      sast: report.json
    paths:
      - report.json  # Keep for debugging
```

## Advanced Troubleshooting

### Debug Mode Analysis

Enable comprehensive debugging:

```yaml
ferret-sast:
  variables:
    FERRET_DEBUG: "1"
  script:
    - ./bin/ferret-scan --debug --format gitlab-sast --output report.json 2>&1 | tee debug.log
  artifacts:
    reports:
      sast: report.json
    paths:
      - debug.log
      - report.json
```

### Local Testing Workflow

Test integration locally before pushing:

```bash
# 1. Generate report locally
./ferret-scan --file . --format gitlab-sast --output local-test.json

# 2. Validate JSON structure
cat local-test.json | jq . > /dev/null && echo "Valid JSON" || echo "Invalid JSON"

# 3. Check GitLab schema compliance
jq '.version, .scan.type, .scan.status, (.vulnerabilities | length)' local-test.json

# 4. Simulate GitLab artifact processing
mkdir -p artifacts/reports
cp local-test.json artifacts/reports/sast.json

# 5. Test with different confidence levels
for level in high medium low; do
  echo "Testing confidence level: $level"
  ./ferret-scan --confidence $level --format gitlab-sast --output test-$level.json
  echo "Vulnerabilities found: $(jq '.vulnerabilities | length' test-$level.json)"
done
```

### Integration Testing

Create a comprehensive test suite:

```yaml
# .gitlab-ci.yml test job
test:ferret-integration:
  stage: test
  script:
    # Test basic functionality
    - ./bin/ferret-scan --version
    
    # Test GitLab format generation
    - echo "Test data: 4111-1111-1111-1111" > test-file.txt
    - ./bin/ferret-scan --file test-file.txt --format gitlab-sast --output test-report.json
    
    # Validate report structure
    - jq '.version, .scan.type, (.vulnerabilities | length)' test-report.json
    
    # Test with different options
    - ./bin/ferret-scan --file test-file.txt --confidence high --format gitlab-sast --output high-conf-report.json
    
    # Cleanup
    - rm test-file.txt
  artifacts:
    paths:
      - "*-report.json"
    expire_in: 1 hour
```

## Getting Help

### Diagnostic Information to Collect

When reporting issues, include:

1. **Ferret Scan Version**:
   ```bash
   ./ferret-scan --version
   ```

2. **GitLab Version and License**:
   - Go to Admin Area → Overview → GitLab and system information

3. **Pipeline Configuration**:
   ```bash
   grep -A 20 "ferret-sast" .gitlab-ci.yml
   ```

4. **Sample Report Output**:
   ```bash
   ./ferret-scan --file . --format gitlab-sast --output sample.json
   head -50 sample.json
   ```

5. **Error Messages**:
   - Full pipeline logs
   - GitLab error messages
   - Debug output if available

### Support Channels

- **GitLab Documentation**: [Security Reports](https://docs.gitlab.com/ee/user/application_security/)
- **Ferret Scan Issues**: [GitHub Repository](https://github.com/your-org/ferret-scan/issues)
- **GitLab Support**: Available with GitLab Ultimate subscription
- **Community Forum**: [GitLab Community](https://forum.gitlab.com/)

### Useful GitLab API Endpoints

Test GitLab integration programmatically:

```bash
# Get project vulnerabilities
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/vulnerabilities"

# Get security reports for specific pipeline
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/pipelines/$PIPELINE_ID/security_report_summary"
```

This troubleshooting guide should help resolve most common GitLab integration issues. For complex problems, enable debug mode and collect comprehensive diagnostic information before seeking support.