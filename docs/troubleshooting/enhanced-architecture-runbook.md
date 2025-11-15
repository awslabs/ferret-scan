# Enhanced Architecture Troubleshooting Runbook

This runbook provides step-by-step procedures for troubleshooting common issues with the enhanced metadata processing architecture.

## Table of Contents

1. [Quick Health Check](#quick-health-check)
2. [Content Routing Issues](#content-routing-issues)
3. [Dual-Path Validation Problems](#dual-path-validation-problems)
4. [Performance Degradation](#performance-degradation)
5. [Memory Issues](#memory-issues)
6. [Accuracy Degradation](#accuracy-degradation)
7. [Fallback Mode Activation](#fallback-mode-activation)
8. [Monitoring and Alerting Issues](#monitoring-and-alerting-issues)

## Quick Health Check

### Symptoms
- System appears unresponsive
- Unexpected errors during processing
- Performance issues

### Diagnostic Steps

1. **Check Overall System Health**
   ```bash
   # Basic functionality test
   ferret-scan --version

   # Test with a simple file
   echo "test content" > test.txt
   ferret-scan test.txt
   ```

2. **Check Health Endpoints** (if web interface is running)
   ```bash
   curl -f http://localhost:8080/health
   ```

3. **Check Process Status**
   ```bash
   # Check if ferret-scan processes are running
   ps aux | grep ferret-scan

   # Check system resources
   top -p $(pgrep ferret-scan)
   ```

### Resolution Steps

1. **If basic functionality fails:**
   - Verify ferret-scan binary is accessible
   - Check file permissions
   - Verify dependencies are installed

2. **If health check fails:**
   - Check logs for error messages
   - Verify configuration files
   - Restart the service if necessary

## Content Routing Issues

### Symptoms
- Files not being processed correctly
- Content separation failures
- Unexpected routing decisions

### Diagnostic Steps

1. **Enable Debug Logging**
   ```bash
   ferret-scan --debug --file your-file.pdf
   ```

2. **Check Routing Decision Logs**
   Look for log entries with `component: "debug_logger"` and `operation: "routing_decision"`

3. **Verify Preprocessor Detection**
   ```bash
   # Check if preprocessors are working
   ferret-scan --list-preprocessors
   ```

### Common Issues and Solutions

#### Issue: Content Not Being Separated
**Symptoms:** All content goes to document path, no metadata extraction

**Diagnosis:**
```bash
# Check preprocessor output
ferret-scan --debug --preprocessor-only your-file.pdf
```

**Solutions:**
1. Verify file format is supported
2. Check if metadata preprocessors are enabled
3. Ensure file is not corrupted
4. Check file permissions

#### Issue: Incorrect Routing Decisions
**Symptoms:** Content routed to wrong validation path

**Diagnosis:**
- Check routing decision logs for reasoning
- Verify preprocessor type identification
- Check content separation results

**Solutions:**
1. Update preprocessor type detection logic
2. Adjust routing decision criteria
3. Check for file format edge cases

## Dual-Path Validation Problems

### Symptoms
- Validation results inconsistent
- One path not processing files
- Cross-path correlation issues

### Diagnostic Steps

1. **Check Path-Specific Metrics**
   ```bash
   # Look for validation outcome logs
   grep "validation_outcome" ferret-scan.log
   ```

2. **Verify Both Paths Are Active**
   ```bash
   # Check for both document and metadata path activity
   grep -E "(document|metadata)_path" ferret-scan.log
   ```

3. **Test Each Path Individually**
   ```bash
   # Force document path only
   ferret-scan --document-path-only your-file.txt

   # Force metadata path only
   ferret-scan --metadata-path-only your-file.pdf
   ```

### Common Issues and Solutions

#### Issue: Document Path Not Processing
**Symptoms:** No document validation results

**Diagnosis:**
- Check if document body content is being separated
- Verify document validators are enabled
- Check for document path errors

**Solutions:**
1. Verify content separation is working
2. Check document validator configuration
3. Ensure document validators are not disabled

#### Issue: Metadata Path Not Processing
**Symptoms:** No metadata validation results

**Diagnosis:**
- Check if metadata is being extracted
- Verify metadata validators are enabled
- Check preprocessor functionality

**Solutions:**
1. Verify metadata extraction is working
2. Check metadata validator configuration
3. Ensure preprocessors are functioning correctly

## Performance Degradation

### Symptoms
- Slow processing times
- High CPU/memory usage
- Timeouts during processing

### Diagnostic Steps

1. **Check Performance Metrics**
   ```bash
   # Look for performance metric logs
   grep "performance_metrics" ferret-scan.log
   ```

2. **Monitor Resource Usage**
   ```bash
   # Monitor during processing
   top -p $(pgrep ferret-scan)

   # Check memory usage
   ps -o pid,vsz,rss,comm -p $(pgrep ferret-scan)
   ```

3. **Profile Processing Time**
   ```bash
   # Time a typical operation
   time ferret-scan your-file.pdf
   ```

### Common Issues and Solutions

#### Issue: Slow Content Routing
**Symptoms:** High routing times in logs

**Diagnosis:**
- Check routing time metrics
- Look for routing decision complexity
- Check for large file processing

**Solutions:**
1. Optimize content separation algorithms
2. Implement content size limits
3. Add caching for repeated operations

#### Issue: Slow Validation Processing
**Symptoms:** High validation times in logs

**Diagnosis:**
- Check validation path metrics
- Identify slow validators
- Look for resource contention

**Solutions:**
1. Optimize validator algorithms
2. Implement parallel processing
3. Add validation timeouts

## Memory Issues

### Symptoms
- Out of memory errors
- Memory usage alerts
- System becoming unresponsive

### Diagnostic Steps

1. **Check Memory Usage Patterns**
   ```bash
   # Monitor memory over time
   while true; do
     ps -o pid,vsz,rss,comm -p $(pgrep ferret-scan)
     sleep 5
   done
   ```

2. **Check for Memory Leaks**
   ```bash
   # Look for increasing memory usage
   grep "memory_usage" ferret-scan.log | tail -20
   ```

3. **Analyze Large File Processing**
   ```bash
   # Test with different file sizes
   ferret-scan small-file.txt
   ferret-scan large-file.pdf
   ```

### Common Issues and Solutions

#### Issue: Memory Leaks
**Symptoms:** Continuously increasing memory usage

**Diagnosis:**
- Monitor memory usage over time
- Check for unreleased resources
- Look for goroutine leaks

**Solutions:**
1. Implement proper resource cleanup
2. Add memory usage monitoring
3. Set memory limits for processing

#### Issue: Large File Processing
**Symptoms:** Memory spikes with large files

**Diagnosis:**
- Test with files of different sizes
- Check memory usage during processing
- Look for streaming vs. loading patterns

**Solutions:**
1. Implement streaming processing
2. Add file size limits
3. Use memory-efficient algorithms

## Accuracy Degradation

### Symptoms
- Accuracy degradation alerts
- Confidence score drops
- Inconsistent validation results

### Diagnostic Steps

1. **Check Accuracy Metrics**
   ```bash
   # Look for accuracy degradation alerts
   grep "accuracy_degradation" ferret-scan.log
   ```

2. **Compare with Baseline**
   ```bash
   # Check baseline metrics
   grep "baseline_updated" ferret-scan.log | tail -5
   ```

3. **Test with Known Good Files**
   ```bash
   # Test with files that previously worked well
   ferret-scan known-good-file.pdf
   ```

### Common Issues and Solutions

#### Issue: Confidence Score Degradation
**Symptoms:** Lower confidence scores than baseline

**Diagnosis:**
- Check confidence score trends
- Look for context integration issues
- Verify validator calibration

**Solutions:**
1. Recalibrate confidence scoring
2. Update context analysis integration
3. Review validator rule changes

#### Issue: Match Count Variations
**Symptoms:** Unexpected changes in match counts

**Diagnosis:**
- Compare match counts with baseline
- Check for validator rule changes
- Look for content routing changes

**Solutions:**
1. Review recent validator updates
2. Check content routing decisions
3. Validate against known test cases

## Fallback Mode Activation

### Symptoms
- Fallback activation alerts
- Processing using legacy behavior
- Reduced functionality

### Diagnostic Steps

1. **Check Fallback Logs**
   ```bash
   # Look for fallback activation
   grep "fallback_activation" ferret-scan.log
   ```

2. **Identify Fallback Triggers**
   ```bash
   # Check what's causing fallbacks
   grep -A 5 -B 5 "fallback_activation" ferret-scan.log
   ```

3. **Test Enhanced Architecture Components**
   ```bash
   # Test content routing
   ferret-scan --test-routing your-file.pdf

   # Test dual-path validation
   ferret-scan --test-validation your-file.pdf
   ```

### Common Issues and Solutions

#### Issue: Frequent Fallback Activation
**Symptoms:** High fallback rate alerts

**Diagnosis:**
- Check fallback activation reasons
- Look for component failures
- Verify system stability

**Solutions:**
1. Fix underlying component issues
2. Improve error handling
3. Update fallback thresholds

## Monitoring and Alerting Issues

### Symptoms
- Missing alerts
- False positive alerts
- Monitoring system not responding

### Diagnostic Steps

1. **Check Monitoring System Status**
   ```bash
   # Verify monitoring is running
   grep "performance_monitor" ferret-scan.log | tail -10
   ```

2. **Test Alert Thresholds**
   ```bash
   # Check current alert configuration
   grep "alert_triggered" ferret-scan.log | tail -10
   ```

3. **Verify Metrics Collection**
   ```bash
   # Check if metrics are being collected
   grep "performance_report" ferret-scan.log | tail -5
   ```

### Common Issues and Solutions

#### Issue: Missing Performance Alerts
**Symptoms:** No alerts despite performance issues

**Diagnosis:**
- Check alert threshold configuration
- Verify monitoring system is running
- Look for alert suppression

**Solutions:**
1. Adjust alert thresholds
2. Restart monitoring system
3. Check alert configuration

#### Issue: False Positive Alerts
**Symptoms:** Too many unnecessary alerts

**Diagnosis:**
- Review alert frequency
- Check threshold appropriateness
- Look for baseline accuracy

**Solutions:**
1. Adjust alert thresholds
2. Implement alert cooldown periods
3. Update baseline metrics

## Emergency Procedures

### Complete System Failure
1. **Immediate Actions:**
   - Stop all ferret-scan processes
   - Check system resources
   - Review recent logs

2. **Recovery Steps:**
   - Restart with minimal configuration
   - Test with simple files
   - Gradually enable features

3. **Escalation:**
   - Contact system administrator
   - Prepare diagnostic information
   - Document the incident

### Data Loss Prevention
1. **Backup Current State:**
   - Save configuration files
   - Export current metrics
   - Preserve log files

2. **Recovery Verification:**
   - Test with known good files
   - Verify accuracy metrics
   - Check performance baselines

## Preventive Measures

### Regular Maintenance
- Update baseline metrics weekly
- Review alert thresholds monthly
- Perform health checks daily

### Monitoring Best Practices
- Set up automated health checks
- Monitor key performance indicators
- Maintain alert documentation

### Testing Procedures
- Test with diverse file types
- Validate against known results
- Perform regular performance benchmarks

## Contact Information

For additional support:
- System Administrator: [contact info]
- Development Team: [contact info]
- Emergency Contact: [contact info]

## Appendix

### Log File Locations
- Main log: `/var/log/ferret-scan/ferret-scan.log`
- Debug log: `/var/log/ferret-scan/debug.log`
- Performance log: `/var/log/ferret-scan/performance.log`

### Configuration Files
- Main config: `/etc/ferret-scan/config.yaml`
- Monitoring config: `/etc/ferret-scan/monitoring.yaml`
- Alert config: `/etc/ferret-scan/alerts.yaml`

### Useful Commands
```bash
# Check system status
ferret-scan --health-check

# Generate diagnostic report
ferret-scan --diagnostic-report

# Test specific components
ferret-scan --test-component content-router
ferret-scan --test-component dual-path-validator

# Performance benchmark
ferret-scan --benchmark test-files/
```
