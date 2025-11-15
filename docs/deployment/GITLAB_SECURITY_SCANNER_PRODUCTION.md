# GitLab Security Scanner Production Deployment Guide

This guide provides instructions for deploying Ferret Scan as a GitLab Security Scanner in production environments.

## Overview

Ferret Scan integrates with GitLab's Security Dashboard as a SAST (Static Application Security Testing) scanner, providing sensitive data detection capabilities that appear directly in GitLab's security reports and merge request widgets.

## Prerequisites

- GitLab project with CI/CD enabled
- Ferret Scan binary built and available in your CI pipeline
- Alpine Linux compatible environment (or adjust image as needed)

## Production Configuration

### GitLab CI Job Configuration

Add the following job to your `.gitlab-ci.yml` file:

```yaml
# Ferret Scan SAST integration for GitLab Security Dashboard
ferret-sast:
  stage: security
  image: alpine:latest
  dependencies:
    - build
  before_script:
    - apk add --no-cache jq
    - chmod +x bin/ferret-scan
  script:
    - echo "Running Ferret Scan security analysis..."
    - ./bin/ferret-scan --file . --recursive --format gitlab-sast --output ferret-sast-report.json --confidence high,medium --no-color --quiet
    - |
      if [ -f "ferret-sast-report.json" ]; then
        VULN_COUNT=$(jq '.vulnerabilities | length' ferret-sast-report.json)
        echo "Ferret Scan completed: $VULN_COUNT findings detected"
      else
        echo "Error: Ferret SAST report not generated" && exit 1
      fi
  artifacts:
    reports:
      sast: ferret-sast-report.json
    expire_in: 1 week
  allow_failure: true
```

### Configuration Options

#### Confidence Levels
The production configuration uses `--confidence high,medium` to balance detection quality with noise reduction:

- **`high,medium`** (Recommended): Focuses on high-quality findings with minimal false positives
- **`high`**: Only highest confidence findings (very conservative)
- **`all`**: All confidence levels including low (may produce more noise)

#### File Scanning
- **`--file . --recursive`**: Scans all files in the repository recursively
- **`--format gitlab-sast`**: Generates GitLab-compatible security reports
- **`--no-color --quiet`**: Optimized for CI environments

#### Error Handling
- **`allow_failure: true`**: Allows pipeline to continue even if security issues are found
- **Essential validation**: Ensures report generation and provides clear error messages

## Integration Points

### GitLab Security Dashboard
Once deployed, Ferret Scan findings will appear in:

1. **Project Security Dashboard**: Navigate to Security & Compliance → Vulnerability Report
2. **Pipeline Security Tab**: View findings for specific pipeline runs
3. **Merge Request Widgets**: Security findings displayed in MR discussions
4. **Security Policies**: Can be used with GitLab security policies and approval rules

### Vulnerability Management
- **Dismissal**: Findings can be dismissed through GitLab's interface
- **Issue Creation**: Convert findings to GitLab issues for tracking
- **Status Tracking**: GitLab tracks vulnerability status across commits
- **Reporting**: Export and analyze findings through GitLab's reporting features

## Configuration Options

### Confidence Levels
The production configuration uses `--confidence high,medium` to balance detection quality with noise reduction:

- **`high,medium`** (Recommended): Focuses on high-quality findings with minimal false positives
- **`high`**: Only highest confidence findings (very conservative)
- **`all`**: All confidence levels including low (may produce more noise)

### File Scanning
- **`--file . --recursive`**: Scans all files in the repository recursively
- **`--format gitlab-sast`**: Generates GitLab-compatible security reports
- **`--no-color --quiet`**: Optimized for CI environments

### Error Handling
- **`allow_failure: true`**: Allows pipeline to continue even if security issues are found
- **Essential validation**: Ensures report generation and provides clear error messages

## Performance Characteristics

### Resource Usage
- **Execution Time**: ~30-35 seconds for typical repositories
- **Memory**: Minimal (Alpine Linux base image)
- **CPU**: Efficient scanning with parallel processing
- **Storage**: Reports expire after 1 week by default

### Scalability
- **Repository Size**: Handles large repositories efficiently
- **File Types**: Supports 50+ file formats
- **Concurrent Scans**: Can run alongside other security scanners

## Monitoring and Troubleshooting

### Success Indicators
- Pipeline job completes successfully
- Security report appears in GitLab Security Dashboard
- Findings are properly categorized and actionable
- No schema validation errors in pipeline logs

### Common Issues

#### Schema Validation Errors
If you see timestamp format errors:
```
[Schema] property '/scan/start_time' does not match pattern
```
Ensure you're using the latest version of Ferret Scan with GitLab schema compliance fixes.

#### Missing Findings
If no findings appear in the Security Dashboard:
- Check that the `ferret-sast-report.json` artifact is generated
- Verify the report format matches GitLab's SAST schema
- Ensure the `artifacts.reports.sast` configuration is correct

#### Performance Issues
If scans take too long:
- Consider adjusting confidence levels to reduce processing
- Use file type filters if scanning unnecessary files
- Check repository size and file count

### Debugging
For troubleshooting, temporarily add debug output:
```yaml
script:
  - echo "Running Ferret Scan security analysis..."
  - ./bin/ferret-scan --file . --recursive --format gitlab-sast --output ferret-sast-report.json --confidence high,medium --no-color
  # Remove --quiet flag and add sample output for debugging
  - |
    if [ -f "ferret-sast-report.json" ]; then
      VULN_COUNT=$(jq '.vulnerabilities | length' ferret-sast-report.json)
      echo "Ferret Scan completed: $VULN_COUNT findings detected"
      echo "Sample findings:"
      jq -r '.vulnerabilities[:3] | .[] | "- \(.severity): \(.name) in \(.location.file):\(.location.start_line)"' ferret-sast-report.json || echo "No findings to display"
    else
      echo "Error: Ferret SAST report not generated" && exit 1
    fi
```

## Security Considerations

### Data Privacy
- Ferret Scan processes files locally in the CI environment
- No data is sent to external services
- Reports contain sanitized descriptions (actual sensitive data is redacted)

### Access Control
- Security reports follow GitLab's permission model
- Only users with appropriate access can view vulnerability details
- Reports are stored according to GitLab's data retention policies

### Compliance
- Reports follow GitLab's security report schema standards
- Compatible with GitLab security policies and compliance frameworks
- Supports audit trails through GitLab's vulnerability tracking

## Best Practices

### CI/CD Integration
1. **Stage Placement**: Run in `security` stage after build completion
2. **Dependencies**: Ensure Ferret Scan binary is available from build stage
3. **Failure Handling**: Use `allow_failure: true` to prevent blocking deployments
4. **Artifact Management**: Set appropriate expiration times for reports

### Finding Management
1. **Regular Review**: Establish process for reviewing and triaging findings
2. **False Positive Handling**: Use GitLab's dismissal feature for false positives
3. **Issue Tracking**: Convert actionable findings to GitLab issues
4. **Trend Analysis**: Monitor finding trends over time

### Performance Optimization
1. **Confidence Tuning**: Adjust confidence levels based on your needs
2. **File Filtering**: Exclude unnecessary file types if needed
3. **Parallel Execution**: Can run alongside other security scanners
4. **Resource Limits**: Set appropriate resource limits for large repositories

## Support and Maintenance

### Updates
- Monitor Ferret Scan releases for security and feature updates
- Test updates in non-production environments first
- Update GitLab CI configuration as needed for new features

### Documentation
- Keep internal documentation updated with any customizations
- Document any project-specific configuration decisions
- Maintain runbooks for common troubleshooting scenarios

### Contact
- **Developers**: Andrea Di Fabio (adifabio@), Lee Myers (mlmyers@)
- **Slack Channel**: [ferret-scan-interest](https://amazon.enterprise.slack.com/archives/C09AXRBD90B)
- **Issues**: Report issues through the project's issue tracker

---

This production deployment guide ensures reliable, efficient, and secure integration of Ferret Scan with GitLab's Security Dashboard.
