# Content Routing and Validation Troubleshooting Guide

[← Back to Documentation Index](../README.md)

## Overview

This troubleshooting guide provides comprehensive solutions for issues related to the Content Router and dual-path validation system in Ferret Scan. It covers common problems, diagnostic procedures, and resolution strategies for the enhanced metadata processing architecture.

## Quick Diagnostic Commands

### Enable Debug Logging
```bash
# Enable comprehensive debug logging
ferret-scan --file document.pdf --debug

# Enable specific component debug logging
ferret-scan --file document.pdf --debug-content-routing
ferret-scan --file document.pdf --debug-metadata-validation
ferret-scan --file document.pdf --debug-context-analysis

# Enable performance profiling
ferret-scan --file document.pdf --profile-performance
```

### Fallback to Legacy Mode
```bash
# Force legacy validation for comparison
ferret-scan --file document.pdf --legacy-validation

# Disable enhanced features temporarily
ferret-scan --file document.pdf --disable-content-routing
```

### Validation Testing
```bash
# Test specific preprocessor types
ferret-scan --file image.jpg --checks METADATA --debug-metadata-validation
ferret-scan --file document.pdf --checks METADATA --debug-content-routing

# Compare enhanced vs legacy results
ferret-scan --file document.pdf --compare-validation-modes
```

## Content Router Issues

### Issue: Content Routing Fails with Parsing Errors

**Symptoms:**
- Error messages like "content router parsing failed"
- System falls back to legacy aggregation
- Missing metadata sections in validation results

**Common Causes:**
1. Malformed preprocessor output
2. Missing or incorrect section markers
3. Unexpected content format from preprocessors
4. Memory issues during content separation

**Diagnostic Steps:**

1. **Check Preprocessor Output Format:**
```bash
# Enable preprocessor debug logging
ferret-scan --file document.pdf --debug-preprocessors --preprocess-only

# Look for section markers in output
grep -n "---.*metadata.*---" preprocessor_output.txt
```

2. **Verify Section Markers:**
```bash
# Check for expected section markers
ferret-scan --file document.pdf --debug-content-routing 2>&1 | grep "section_marker"
```

3. **Examine Content Router Logs:**
```bash
# Look for content router specific errors
ferret-scan --file document.pdf --debug 2>&1 | grep "content_router"
```

**Solutions:**

1. **Fix Preprocessor Configuration:**
```yaml
# ferret.yaml - Ensure preprocessors are properly configured
preprocessors:
  image_metadata:
    enabled: true
    section_marker: "--- image_metadata ---"
  document_metadata:
    enabled: true
    section_marker: "--- document_metadata ---"
```

2. **Update Section Marker Patterns:**
```go
// If custom patterns are needed
contentRouter.ConfigureSectionPatterns(map[string]string{
    "image_metadata":    "--- image_metadata ---",
    "document_metadata": "--- document_metadata ---",
    "audio_metadata":    "--- audio_metadata ---",
    "video_metadata":    "--- video_metadata ---",
})
```

3. **Increase Memory Limits:**
```yaml
# ferret.yaml - Increase memory limits for large files
performance:
  max_memory_usage: "2GB"
  max_file_size: "500MB"
```

### Issue: Metadata Sections Not Properly Identified

**Symptoms:**
- Metadata content appears in document body validation
- Enhanced metadata validator receives no content
- Missing preprocessor type information in results

**Diagnostic Steps:**

1. **Check Section Identification:**
```bash
# Debug section identification process
ferret-scan --file document.pdf --debug-content-routing 2>&1 | grep "section_identified"
```

2. **Verify Preprocessor Output:**
```bash
# Check if preprocessors are generating section markers
ferret-scan --file document.pdf --preprocess-only | grep -A5 -B5 "metadata"
```

3. **Test Content Separation:**
```bash
# Test content separation logic
ferret-scan --file document.pdf --debug-content-routing --dry-run
```

**Solutions:**

1. **Update Preprocessor Configuration:**
```yaml
# Ensure preprocessors include proper section markers
preprocessors:
  metadata_extractor:
    include_section_markers: true
    marker_format: "--- {type}_metadata ---"
```

2. **Fix Section Pattern Matching:**
```go
// Update pattern matching logic if needed
func (cr *ContentRouter) identifyPreprocessorType(section ContentSection) string {
    patterns := map[string]string{
        "image_metadata":    `(?i)---\s*image_metadata\s*---`,
        "document_metadata": `(?i)---\s*document_metadata\s*---`,
        "audio_metadata":    `(?i)---\s*audio_metadata\s*---`,
        "video_metadata":    `(?i)---\s*video_metadata\s*---`,
    }

    for preprocessorType, pattern := range patterns {
        if matched, _ := regexp.MatchString(pattern, section.Header); matched {
            return preprocessorType
        }
    }

    return "unknown"
}
```

### Issue: Content Router Performance Degradation

**Symptoms:**
- Significantly increased processing time
- High memory usage during content routing
- System becomes unresponsive with large files

**Diagnostic Steps:**

1. **Profile Content Router Performance:**
```bash
# Enable performance profiling
ferret-scan --file large_document.pdf --profile-performance --debug-content-routing
```

2. **Monitor Memory Usage:**
```bash
# Monitor memory usage during processing
ferret-scan --file large_document.pdf --monitor-memory --debug
```

3. **Compare with Legacy Mode:**
```bash
# Compare processing times
time ferret-scan --file large_document.pdf --legacy-validation
time ferret-scan --file large_document.pdf
```

**Solutions:**

1. **Optimize Content Separation:**
```go
// Use streaming processing for large files
func (cr *ContentRouter) routeContentStreaming(content *ProcessedContent) (*RoutedContent, error) {
    // Process content in chunks to reduce memory usage
    const chunkSize = 1024 * 1024 // 1MB chunks

    // Implementation details...
}
```

2. **Implement Content Caching:**
```yaml
# ferret.yaml - Enable content caching
content_router:
  enable_caching: true
  cache_size: "100MB"
  cache_ttl: "1h"
```

3. **Adjust Worker Pool Size:**
```yaml
# ferret.yaml - Optimize worker pool configuration
parallel_processing:
  max_workers: 4  # Reduce for memory-constrained systems
  worker_memory_limit: "512MB"
```

## Metadata Validator Issues

### Issue: Metadata Validator Not Receiving Expected Content

**Symptoms:**
- Metadata validator processes no content
- Missing metadata-specific matches in results
- All validation goes through document validators

**Diagnostic Steps:**

1. **Check Metadata Routing:**
```bash
# Debug metadata routing
ferret-scan --file document.pdf --debug-metadata-validation 2>&1 | grep "metadata_content_received"
```

2. **Verify Content Router Output:**
```bash
# Check if content router is separating metadata
ferret-scan --file document.pdf --debug-content-routing 2>&1 | grep "metadata_sections"
```

3. **Test Metadata Validator Directly:**
```bash
# Test metadata validator with known metadata content
ferret-scan --test-metadata-validator --metadata-type image --content "GPSLatitude: 40.7128"
```

**Solutions:**

1. **Fix Content Router Configuration:**
```go
// Ensure content router is properly routing metadata
func (evb *EnhancedValidatorBridge) ProcessContent(content *ProcessedContent) ([]detector.Match, error) {
    routedContent, err := evb.contentRouter.RouteContent(content)
    if err != nil {
        evb.observer.LogError("content_routing_failed", err, map[string]interface{}{
            "file_path": content.OriginalPath,
        })
        return evb.processContentLegacy(content)
    }

    // Verify metadata content exists
    if len(routedContent.Metadata) == 0 {
        evb.observer.LogWarning("no_metadata_content",
            "No metadata content found for routing",
            map[string]interface{}{
                "file_path": content.OriginalPath,
            })
    }

    // Continue with processing...
}
```

2. **Update Metadata Validator Registration:**
```go
// Ensure metadata validator is properly registered
enhancedBridge := validators.NewEnhancedValidatorBridge(
    documentValidators,
    metadataValidator,  // Ensure this is not nil
    contentRouter,
    contextEngine,
    observer,
)
```

### Issue: Confidence Scores Different from Expected

**Symptoms:**
- Confidence scores are too low or too high
- Inconsistent confidence scoring across similar matches
- Preprocessor-specific boosts not applied

**Diagnostic Steps:**

1. **Debug Confidence Calculation:**
```bash
# Enable confidence scoring debug
ferret-scan --file document.pdf --debug-confidence-scoring
```

2. **Check Validation Rules:**
```bash
# Verify validation rules are loaded correctly
ferret-scan --file document.pdf --debug-metadata-validation 2>&1 | grep "validation_rules"
```

3. **Test Specific Preprocessor Types:**
```bash
# Test confidence scoring for specific types
ferret-scan --file image.jpg --debug-confidence-scoring --checks METADATA
ferret-scan --file audio.mp3 --debug-confidence-scoring --checks METADATA
```

**Solutions:**

1. **Update Validation Rules:**
```yaml
# ferret.yaml - Configure validation rules
metadata_validation:
  rules:
    image_metadata:
      confidence_boosts:
        gps: 0.6
        device: 0.4
        creator: 0.3
      field_weights:
        gpslatitude: 1.5
        camera_serial: 1.3
```

2. **Fix Confidence Calculation:**
```go
func (mv *EnhancedMetadataValidator) calculateEnhancedConfidence(
    baseConfidence float64,
    preprocessorType string,
    fieldType string,
    contextAnalysis *context.Analysis,
) float64 {
    // Debug logging
    mv.observer.LogDebug("confidence_calculation",
        "Calculating enhanced confidence",
        map[string]interface{}{
            "base_confidence":   baseConfidence,
            "preprocessor_type": preprocessorType,
            "field_type":       fieldType,
        })

    // Apply preprocessor-specific boost
    rules := mv.validationRules[preprocessorType]
    if rules == nil {
        mv.observer.LogWarning("missing_validation_rules",
            "No validation rules found for preprocessor type",
            map[string]interface{}{
                "preprocessor_type": preprocessorType,
            })
        return baseConfidence
    }

    boost := rules.ConfidenceBoosts[fieldType]
    enhancedConfidence := baseConfidence + (boost * 100)

    // Debug logging
    mv.observer.LogDebug("confidence_boost_applied",
        "Applied confidence boost",
        map[string]interface{}{
            "boost":               boost,
            "enhanced_confidence": enhancedConfidence,
        })

    return enhancedConfidence
}
```

### Issue: Preprocessor Type Detection Failures

**Symptoms:**
- All metadata treated as "unknown" type
- Generic validation rules applied instead of type-specific rules
- Missing source traceability in match metadata

**Diagnostic Steps:**

1. **Debug Preprocessor Type Detection:**
```bash
# Debug type detection process
ferret-scan --file document.pdf --debug-metadata-validation 2>&1 | grep "preprocessor_type"
```

2. **Check Metadata Content Structure:**
```bash
# Examine metadata content structure
ferret-scan --file document.pdf --debug-content-routing --preprocess-only
```

**Solutions:**

1. **Improve Type Detection Logic:**
```go
func (cr *ContentRouter) identifyPreprocessorType(section ContentSection) string {
    // Check explicit type markers first
    if section.Metadata != nil {
        if pType, exists := section.Metadata["preprocessor_type"]; exists {
            return pType.(string)
        }
    }

    // Check section headers
    headerLower := strings.ToLower(section.Header)
    switch {
    case strings.Contains(headerLower, "image") && strings.Contains(headerLower, "metadata"):
        return PreprocessorTypeImageMetadata
    case strings.Contains(headerLower, "document") && strings.Contains(headerLower, "metadata"):
        return PreprocessorTypeDocumentMetadata
    case strings.Contains(headerLower, "audio") && strings.Contains(headerLower, "metadata"):
        return PreprocessorTypeAudioMetadata
    case strings.Contains(headerLower, "video") && strings.Contains(headerLower, "metadata"):
        return PreprocessorTypeVideoMetadata
    }

    // Fallback to content analysis
    return cr.analyzeContentForType(section.Content)
}
```

2. **Update Preprocessor Output Format:**
```go
// Ensure preprocessors include type information
type PreprocessorOutput struct {
    Content          string
    PreprocessorType string
    SectionMarker    string
    Metadata         map[string]interface{}
}
```

## Context Analysis Integration Issues

### Issue: Context Analysis Engine Not Providing Expected Context

**Symptoms:**
- Missing domain or document type information
- Context-aware confidence adjustments not applied
- Generic validation behavior instead of context-specific

**Diagnostic Steps:**

1. **Debug Context Analysis:**
```bash
# Enable context analysis debug logging
ferret-scan --file document.pdf --debug-context-analysis
```

2. **Test Context Detection:**
```bash
# Test specific context detection
ferret-scan --file financial_document.pdf --debug-context-analysis 2>&1 | grep "domain_detected"
ferret-scan --file resume.pdf --debug-context-analysis 2>&1 | grep "document_type"
```

**Solutions:**

1. **Update Context Analysis Configuration:**
```yaml
# ferret.yaml - Configure context analysis
context_analysis:
  enabled: true
  domain_detection:
    enabled: true
    confidence_threshold: 0.7
  document_type_detection:
    enabled: true
    confidence_threshold: 0.8
```

2. **Fix Context Integration:**
```go
func (evb *EnhancedValidatorBridge) processWithContext(
    content *ProcessedContent,
) ([]detector.Match, error) {
    // Get context analysis
    contextAnalysis, err := evb.contextEngine.AnalyzeContent(
        content.CombinedContent,
        content.OriginalPath,
    )
    if err != nil {
        evb.observer.LogWarning("context_analysis_failed",
            "Context analysis failed, continuing without context",
            map[string]interface{}{
                "file_path": content.OriginalPath,
                "error":     err.Error(),
            })
        contextAnalysis = nil // Continue without context
    }

    // Apply context to validators
    for _, validator := range evb.documentValidators {
        if contextAware, ok := validator.(ContextAwareValidator); ok {
            contextAware.SetContextAnalysis(contextAnalysis)
        }
    }

    if contextAware, ok := evb.metadataValidator.(ContextAwareValidator); ok {
        contextAware.SetContextAnalysis(contextAnalysis)
    }

    // Continue with validation...
}
```

## Performance Issues

### Issue: Overall Processing Time Increased

**Symptoms:**
- Significantly longer processing times compared to legacy mode
- System becomes unresponsive with large files
- High CPU or memory usage

**Diagnostic Steps:**

1. **Profile Processing Performance:**
```bash
# Enable comprehensive performance profiling
ferret-scan --file document.pdf --profile-performance --debug

# Compare with legacy mode
time ferret-scan --file document.pdf --legacy-validation
time ferret-scan --file document.pdf
```

2. **Identify Performance Bottlenecks:**
```bash
# Profile specific components
ferret-scan --file document.pdf --profile-content-routing
ferret-scan --file document.pdf --profile-metadata-validation
ferret-scan --file document.pdf --profile-context-analysis
```

**Solutions:**

1. **Optimize Parallel Processing:**
```yaml
# ferret.yaml - Optimize parallel processing settings
parallel_processing:
  max_workers: 8  # Adjust based on CPU cores
  worker_memory_limit: "1GB"
  enable_adaptive_processing: true
```

2. **Implement Performance Caching:**
```go
// Add caching for expensive operations
type PerformanceCache struct {
    contextCache    map[string]*ContextAnalysis
    validationCache map[string][]detector.Match
    mutex          sync.RWMutex
}

func (pc *PerformanceCache) GetContextAnalysis(contentHash string) *ContextAnalysis {
    pc.mutex.RLock()
    defer pc.mutex.RUnlock()
    return pc.contextCache[contentHash]
}
```

3. **Optimize Memory Usage:**
```go
// Implement streaming processing for large files
func (cr *ContentRouter) routeContentStreaming(content *ProcessedContent) (*RoutedContent, error) {
    // Process content in chunks to reduce memory usage
    const maxChunkSize = 1024 * 1024 // 1MB chunks

    if len(content.CombinedContent) > maxChunkSize {
        return cr.routeContentInChunks(content, maxChunkSize)
    }

    return cr.routeContentStandard(content)
}
```

## Error Recovery and Fallback

### Issue: System Not Falling Back to Legacy Mode on Errors

**Symptoms:**
- Processing fails completely instead of falling back
- No error recovery mechanisms activated
- Missing fallback logging

**Solutions:**

1. **Implement Comprehensive Error Recovery:**
```go
func (evb *EnhancedValidatorBridge) ProcessContentWithRecovery(
    content *ProcessedContent,
) ([]detector.Match, error) {
    // Try enhanced processing first
    matches, err := evb.processContentEnhanced(content)
    if err == nil {
        return matches, nil
    }

    // Log fallback
    evb.observer.LogWarning("enhanced_processing_fallback",
        "Enhanced processing failed, falling back to legacy mode",
        map[string]interface{}{
            "file_path": content.OriginalPath,
            "error":     err.Error(),
        })

    // Fallback to legacy processing
    return evb.processContentLegacy(content)
}
```

2. **Add Circuit Breaker Pattern:**
```go
type CircuitBreaker struct {
    failureCount    int
    failureLimit    int
    resetTimeout    time.Duration
    lastFailureTime time.Time
    state          string // "closed", "open", "half-open"
    mutex          sync.Mutex
}

func (cb *CircuitBreaker) Execute(operation func() error) error {
    if cb.shouldSkip() {
        return errors.New("circuit breaker is open")
    }

    err := operation()
    cb.recordResult(err)
    return err
}
```

## Monitoring and Alerting

### Setting Up Monitoring

1. **Enable Comprehensive Logging:**
```yaml
# ferret.yaml - Configure logging
logging:
  level: "info"
  enable_structured_logging: true
  log_components:
    - content_router
    - metadata_validator
    - context_analysis
    - performance_metrics
```

2. **Configure Metrics Collection:**
```go
// Set up metrics collection
func (evb *EnhancedValidatorBridge) setupMetrics() {
    evb.observer.RegisterMetric("content_routing_time", "histogram")
    evb.observer.RegisterMetric("metadata_validation_time", "histogram")
    evb.observer.RegisterMetric("context_analysis_time", "histogram")
    evb.observer.RegisterMetric("validation_accuracy", "gauge")
    evb.observer.RegisterMetric("error_rate", "counter")
}
```

### Key Metrics to Monitor

- **Content Routing Success Rate**: Percentage of successful content routing operations
- **Metadata Validation Accuracy**: Accuracy of metadata-specific validation
- **Processing Time Distribution**: Distribution of processing times across components
- **Memory Usage Patterns**: Memory usage during content routing and validation
- **Error Rates**: Error rates by component and error type

### Alerting Thresholds

```yaml
# monitoring.yaml - Configure alerting thresholds
alerts:
  content_routing_failure_rate:
    threshold: 5%
    window: "5m"
  metadata_validation_accuracy:
    threshold: 85%
    window: "10m"
  processing_time_p95:
    threshold: "30s"
    window: "5m"
  memory_usage:
    threshold: "2GB"
    window: "1m"
```

## Common Log Messages and Solutions

### Content Router Logs

```
INFO  content_router: Successfully routed content (doc_body=1234 chars, metadata_sections=3)
```
✅ **Normal operation** - Content successfully separated

```
WARN  content_router_fallback: Falling back to legacy content aggregation (error=parsing_failed)
```
⚠️ **Action needed** - Check preprocessor output format

```
ERROR content_router: Failed to identify preprocessor type (section_header="unknown format")
```
❌ **Fix required** - Update section marker patterns

### Metadata Validator Logs

```
INFO  metadata_validator: Processing image_metadata (fields=5, confidence_boost=0.6)
```
✅ **Normal operation** - Metadata validation proceeding correctly

```
WARN  metadata_validator: No validation rules found for preprocessor type (type=unknown)
```
⚠️ **Action needed** - Configure validation rules for preprocessor type

```
ERROR metadata_validator: Validation failed for metadata content (error=pattern_compilation_failed)
```
❌ **Fix required** - Check regex pattern compilation

### Performance Logs

```
INFO  performance: Processing completed (time=1.2s, memory_peak=256MB)
```
✅ **Normal operation** - Performance within acceptable range

```
WARN  performance: Processing time exceeded threshold (time=45s, threshold=30s)
```
⚠️ **Action needed** - Investigate performance bottlenecks

```
ERROR performance: Memory usage exceeded limit (usage=3GB, limit=2GB)
```
❌ **Fix required** - Optimize memory usage or increase limits

---

*This troubleshooting guide covers the most common issues with the Content Router and dual-path validation system. For additional support, enable debug logging and examine the specific error messages and log entries.*
