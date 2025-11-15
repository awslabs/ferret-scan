# Enhanced Architecture Deployment Guide

## Overview

This document provides deployment procedures and monitoring guidelines for the enhanced metadata processing architecture. The enhanced architecture introduces intelligent content routing and dual-path validation while maintaining full backward compatibility.

## Pre-Deployment Checklist

### System Requirements
- [ ] Go 1.19 or later
- [ ] Sufficient memory for enhanced processing (recommended: 2GB+ available)
- [ ] Disk space for temporary processing files
- [ ] Network access for any external dependencies

### Compatibility Verification
- [ ] Run backward compatibility test suite: `go test ./tests/integration/backward_compatibility_test.go`
- [ ] Run architecture compatibility tests: `go test ./tests/integration/architecture_compatibility_test.go`
- [ ] Run CLI compatibility tests: `go test ./tests/integration/cli_compatibility_test.go`
- [ ] Verify all existing configuration files work unchanged
- [ ] Test with representative sample files from production

### Performance Baseline
- [ ] Establish performance baseline with current architecture
- [ ] Run performance tests: `go test ./tests/integration/architecture_compatibility_test.go -run TestArchitecturePerformanceCompatibility`
- [ ] Document current processing times for comparison

## Deployment Procedures

### 1. Staged Deployment (Recommended)

#### Phase 1: Development Environment
```bash
# Build enhanced version
go build -o ferret-scan-enhanced cmd/main.go

# Run comprehensive test suite
go test ./tests/integration/... -v

# Performance comparison
go test ./tests/integration/architecture_compatibility_test.go -run TestArchitecturePerformanceCompatibility -v
```

#### Phase 2: Staging Environment
```bash
# Deploy to staging
cp ferret-scan-enhanced /staging/bin/ferret-scan

# Run with production-like data
./ferret-scan --file /staging/test-data/*.pdf --format json --confidence high

# Monitor resource usage
top -p $(pgrep ferret-scan)
```

#### Phase 3: Production Deployment
```bash
# Backup current version
cp /production/bin/ferret-scan /production/bin/ferret-scan.backup

# Deploy enhanced version
cp ferret-scan-enhanced /production/bin/ferret-scan

# Verify deployment
./ferret-scan --help | grep -E "(format|confidence|checks)"
```

### 2. Blue-Green Deployment

#### Setup Blue-Green Environment
```bash
# Blue environment (current)
/production/blue/bin/ferret-scan

# Green environment (enhanced)
/production/green/bin/ferret-scan-enhanced

# Load balancer or symlink switch
ln -sf /production/green/bin/ferret-scan /production/current/ferret-scan
```

#### Validation Process
```bash
# Test both versions with same input
/production/blue/bin/ferret-scan --file test.pdf --format json > blue_results.json
/production/green/bin/ferret-scan --file test.pdf --format json > green_results.json

# Compare results (should be functionally equivalent)
diff -u blue_results.json green_results.json
```

### 3. Canary Deployment

#### Gradual Traffic Shift
```bash
# Route 10% of traffic to enhanced version
# (Implementation depends on your deployment infrastructure)

# Monitor metrics for both versions
# Gradually increase traffic: 10% -> 25% -> 50% -> 100%
```

## Monitoring and Alerting

### Key Metrics to Monitor

#### Performance Metrics
- **Processing Time**: Should not increase by more than 5%
- **Memory Usage**: Monitor for memory leaks or excessive consumption
- **CPU Usage**: Should remain within normal bounds
- **Throughput**: Files processed per minute

#### Functional Metrics
- **Match Count**: Total matches found should be consistent
- **Match Types**: Distribution of match types should be similar
- **Error Rate**: Should not increase
- **Success Rate**: File processing success rate

#### Architecture-Specific Metrics
- **Content Routing Success**: Percentage of successful content routing operations
- **Metadata Separation**: Accuracy of metadata vs document body separation
- **Validator Bridge Performance**: Performance of dual-path validation

### Monitoring Commands

#### Basic Health Check
```bash
# Test basic functionality
./ferret-scan --file sample.pdf --format json --confidence high

# Verify all validators are working
./ferret-scan --file test-data/mixed-content.txt --checks all --verbose
```

#### Performance Monitoring
```bash
# Monitor resource usage during processing
time ./ferret-scan --file large-document.pdf --format json

# Memory usage monitoring
valgrind --tool=massif ./ferret-scan --file test.pdf

# CPU profiling (if built with profiling support)
go tool pprof cpu.prof
```

#### Log Analysis
```bash
# Enable debug logging
export FERRET_DEBUG=1
./ferret-scan --file test.pdf --debug

# Monitor for errors
grep -i error /var/log/ferret-scan.log

# Monitor content routing
grep "content_router" /var/log/ferret-scan.log
```

### Alerting Thresholds

#### Critical Alerts
- Processing time increase > 20%
- Error rate > 5%
- Memory usage > 4GB per process
- Complete processing failures

#### Warning Alerts
- Processing time increase > 10%
- Error rate > 2%
- Memory usage > 2GB per process
- Content routing failures > 1%

## Rollback Procedures

### Immediate Rollback (Emergency)

#### Symptoms Requiring Immediate Rollback
- Processing failures > 10%
- Memory usage > 8GB per process
- Processing time increase > 50%
- Critical functionality broken

#### Rollback Steps
```bash
# 1. Stop current processes
pkill ferret-scan

# 2. Restore backup version
cp /production/bin/ferret-scan.backup /production/bin/ferret-scan

# 3. Verify rollback
./ferret-scan --help
./ferret-scan --file test.pdf --format json

# 4. Restart services
systemctl restart ferret-scan-service
```

### Planned Rollback

#### Preparation
```bash
# Verify backup version works
./ferret-scan.backup --file test.pdf --format json

# Document rollback reason
echo "Rollback reason: [REASON]" >> /var/log/deployment.log
```

#### Execution
```bash
# 1. Graceful shutdown
systemctl stop ferret-scan-service

# 2. Switch versions
mv /production/bin/ferret-scan /production/bin/ferret-scan.enhanced
mv /production/bin/ferret-scan.backup /production/bin/ferret-scan

# 3. Restart services
systemctl start ferret-scan-service

# 4. Verify functionality
./ferret-scan --file test.pdf --format json
```

### Rollback Verification

#### Functional Verification
```bash
# Test all major functionality
./ferret-scan --file test.pdf --format json --confidence high
./ferret-scan --file test.docx --format csv --checks all
./ferret-scan --file test.jpg --format yaml --verbose

# Test configuration compatibility
./ferret-scan --config production.yaml --file test.pdf
```

#### Performance Verification
```bash
# Verify performance is back to baseline
time ./ferret-scan --file large-document.pdf

# Check resource usage
top -p $(pgrep ferret-scan)
```

## Troubleshooting

### Common Issues

#### Content Routing Failures
**Symptoms**: Warnings about content routing failures in logs
**Solution**:
```bash
# Check for malformed content
./ferret-scan --file problematic.pdf --debug

# Verify preprocessors are working
./ferret-scan --file test.pdf --preprocess-only
```

#### Performance Degradation
**Symptoms**: Processing takes significantly longer
**Solution**:
```bash
# Check for memory issues
free -h
./ferret-scan --file test.pdf --debug

# Profile performance
go tool pprof cpu.prof
```

#### Validation Inconsistencies
**Symptoms**: Different results compared to previous version
**Solution**:
```bash
# Compare results in detail
./ferret-scan --file test.pdf --format json --verbose > new_results.json
./ferret-scan.backup --file test.pdf --format json --verbose > old_results.json
diff -u old_results.json new_results.json
```

### Debug Commands

#### Enable Detailed Logging
```bash
export FERRET_DEBUG=1
export FERRET_VERBOSE=1
./ferret-scan --file test.pdf --debug --verbose
```

#### Test Specific Components
```bash
# Test content router specifically
go test ./internal/router/content_router_test.go -v

# Test enhanced validator bridge
go test ./internal/validators/dual_path_bridge_test.go -v
```

#### Memory Analysis
```bash
# Check for memory leaks
valgrind --leak-check=full ./ferret-scan --file test.pdf

# Memory profiling
go tool pprof mem.prof
```

## Post-Deployment Validation

### Functional Validation Checklist
- [ ] All file types process correctly
- [ ] All output formats work
- [ ] All confidence levels work
- [ ] All validator types work
- [ ] Configuration files work unchanged
- [ ] Command-line flags work unchanged
- [ ] Performance is within acceptable bounds

### Long-term Monitoring
- [ ] Set up automated performance monitoring
- [ ] Configure alerting for key metrics
- [ ] Schedule regular compatibility tests
- [ ] Monitor user feedback and error reports
- [ ] Track resource usage trends

## Support and Escalation

### Level 1 Support
- Basic functionality issues
- Configuration problems
- Performance questions

### Level 2 Support
- Architecture-specific issues
- Content routing problems
- Complex debugging

### Level 3 Support (Development Team)
- Core architecture issues
- Performance optimization
- Bug fixes and patches

### Contact Information
- **Development Team**: [team-email]
- **Operations Team**: [ops-email]
- **Emergency Contact**: [emergency-contact]

## Documentation Updates

After successful deployment, update:
- [ ] User documentation
- [ ] API documentation
- [ ] Configuration examples
- [ ] Performance benchmarks
- [ ] Troubleshooting guides

## Conclusion

The enhanced metadata processing architecture maintains full backward compatibility while providing improved accuracy and performance. Following these deployment procedures ensures a smooth transition with minimal risk to production systems.

For questions or issues during deployment, refer to the troubleshooting section or contact the development team.
