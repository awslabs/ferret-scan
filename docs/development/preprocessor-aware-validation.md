# Preprocessor-Aware Validation Rules and Confidence Scoring

[← Back to Documentation Index](../README.md)

## Overview

The Preprocessor-Aware Validation system represents a significant enhancement to Ferret Scan's metadata validation capabilities. This system applies different validation rules and confidence scoring based on the source preprocessor type, enabling more targeted and accurate detection of sensitive information in metadata.

## Validation Rule Framework

### Rule Structure

Each preprocessor type has its own validation rule set that defines:

- **Sensitive Fields**: Metadata fields that should be validated for sensitive information
- **Confidence Boosts**: Additional confidence points based on field type and context
- **Pattern Overrides**: Custom regex patterns for specific metadata types
- **Field Weighting**: Importance weighting for different metadata fields

```go
type ValidationRule struct {
    SensitiveFields    []string                    // Fields to validate
    ConfidenceBoosts   map[string]float64         // Confidence adjustments
    PatternOverrides   map[string]*regexp.Regexp  // Custom patterns
    FieldWeights       map[string]float64         // Field importance
    ContextModifiers   map[string]float64         // Context-based adjustments
}
```

### Rule Application Process

1. **Preprocessor Type Detection**: Identify the source preprocessor from metadata context
2. **Rule Selection**: Select appropriate validation rules for the preprocessor type
3. **Field Filtering**: Only validate fields defined in the sensitive fields list
4. **Pattern Matching**: Apply standard or custom patterns to field values
5. **Confidence Calculation**: Calculate enhanced confidence using preprocessor-specific boosts
6. **Context Integration**: Apply context analysis adjustments to final confidence

## Preprocessor-Specific Validation Rules

### Image Metadata Validation

Image metadata contains highly sensitive location and device information that requires specialized validation.

#### Sensitive Fields

```go
ImageMetadataSensitiveFields = []string{
    // GPS and Location Data
    "gpslatitude", "gpslongitude", "gpsaltitude", "gpsdatestamp",
    "gpslatituderef", "gpslongituderef", "gpsaltituderef",
    "gpstimestamp", "gpsprocessingmethod", "gpsareainformation",
    
    // Device Information
    "camera_make", "camera_model", "camera_serial", "device_id",
    "lens_make", "lens_model", "lens_serial",
    "unique_camera_model", "camera_owner_name",
    
    // Creator and Copyright Information
    "artist", "creator", "copyright", "copyrightnotice",
    "imagedescription", "usercomment", "xp_author", "xp_comment",
    
    // Software and System Information
    "software", "processing_software", "host_computer",
    "camera_software_version", "firmware_version",
    
    // Personal Information in EXIF
    "owner_name", "camera_owner", "photographer",
    "contact_info", "email", "website",
}
```

#### Confidence Boosts

```go
ImageMetadataConfidenceBoosts = map[string]float64{
    "gps":           0.6,   // Very high confidence for GPS data
    "device":        0.4,   // High confidence for device info
    "creator":       0.3,   // Medium-high for creator info
    "copyright":     0.3,   // Medium-high for copyright
    "software":      0.2,   // Medium for software info
    "personal":      0.5,   // High for personal information
    "contact":       0.5,   // High for contact information
}
```

#### Validation Patterns

```go
ImageMetadataPatterns = map[string]*regexp.Regexp{
    "gps_coordinate": regexp.MustCompile(`^-?\d+\.\d+$`),
    "device_serial":  regexp.MustCompile(`^[A-Z0-9]{8,}$`),
    "email_in_exif":  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
    "phone_in_exif":  regexp.MustCompile(`[\+]?[1-9]?[\d\s\-\(\)]{10,}`),
}
```

### Document Metadata Validation

Document metadata often contains author information, comments, and revision history that may include sensitive personal data.

#### Sensitive Fields

```go
DocumentMetadataSensitiveFields = []string{
    // Author and Creator Information
    "author", "creator", "lastmodifiedby", "manager", "company",
    "dc:creator", "dc:publisher", "cp:lastmodifiedby",
    
    // Personal Comments and Descriptions
    "comments", "description", "keywords", "subject",
    "dc:description", "dc:subject", "cp:keywords",
    
    // Copyright and Ownership
    "copyright", "rights", "copyrightnotice",
    "dc:rights", "dc:rightsHolder",
    
    // Revision and History Information
    "revision_history", "change_tracking", "document_history",
    "last_saved_by", "created_by", "modified_by",
    
    // Template and Path Information
    "template", "template_path", "document_path",
    "hyperlink_base", "shared_doc_path",
    
    // Personal Information
    "personal_info", "contact_info", "email_address",
    "phone_number", "address", "organization",
}
```

#### Confidence Boosts

```go
DocumentMetadataConfidenceBoosts = map[string]float64{
    "manager":       0.4,   // High confidence for manager info
    "comments":      0.5,   // Very high for comments
    "author":        0.3,   // Medium-high for author info
    "personal":      0.5,   // High for personal information
    "contact":       0.4,   // High for contact information
    "revision":      0.2,   // Medium for revision info
    "copyright":     0.3,   // Medium-high for copyright
    "template":      0.1,   // Low for template info
}
```

### Audio Metadata Validation

Audio metadata contains artist identity, recording information, and contact details that require specialized validation.

#### Sensitive Fields

```go
AudioMetadataSensitiveFields = []string{
    // Artist and Performer Identity
    "artist", "performer", "composer", "conductor", "albumartist",
    "band", "ensemble", "orchestra", "choir",
    
    // ID3 Tag Fields (Personal Information)
    "tpe1", "tpe2", "tpe3", "tpe4",  // Performer fields
    "tcom", "tcon", "tcop",          // Composer, content, copyright
    "tpub", "town", "trsn",          // Publisher, owner, station
    
    // Recording and Production Information
    "publisher", "label", "record_label", "production_company",
    "studio", "recorded_at", "recording_location",
    "producer", "engineer", "mixer", "mastered_by",
    
    // Contact and Business Information
    "management", "booking", "agent", "contact",
    "website", "email", "phone", "address",
    "social_media", "facebook", "twitter", "instagram",
    
    // Copyright and Legal Information
    "copyright", "copyrightnotice", "rights", "license",
    "isrc", "publishing_rights", "mechanical_rights",
    
    // Personal Comments and Notes
    "comment", "description", "notes", "lyrics",
    "personal_notes", "session_notes",
}
```

#### Confidence Boosts

```go
AudioMetadataConfidenceBoosts = map[string]float64{
    "contact":       0.5,   // High confidence for contact info
    "management":    0.4,   // High for management info
    "artist":        0.3,   // Medium-high for artist info
    "personal":      0.5,   // High for personal information
    "social_media":  0.4,   // High for social media
    "recording":     0.2,   // Medium for recording info
    "copyright":     0.3,   // Medium-high for copyright
    "id3_personal":  0.4,   // High for ID3 personal fields
}
```

### Video Metadata Validation

Video metadata includes location data, device information, and production details that require targeted validation.

#### Sensitive Fields

```go
VideoMetadataSensitiveFields = []string{
    // GPS and Location Data
    "gpslatitude", "gpslongitude", "gpsaltitude", "xyz",
    "location", "recording_location", "gps_coordinates",
    "place", "venue", "address", "city", "country",
    
    // Device and Camera Information
    "camera_make", "camera_model", "recording_device", "device_serial",
    "camera_serial", "lens_make", "lens_model", "equipment_id",
    "camera_identifier", "device_manufacturer",
    
    // Creator and Production Information
    "recorded_by", "director", "producer", "cinematographer",
    "camera_operator", "sound_recordist", "editor",
    "production_company", "studio", "distributor",
    
    // Copyright and Legal Information
    "copyright", "copyrightnotice", "rights", "license",
    "production_copyright", "distribution_rights",
    
    // Personal Information and Comments
    "comment", "description", "notes", "keywords",
    "personal_notes", "production_notes", "scene_notes",
    
    // Technical and System Information
    "software", "encoding_software", "creation_tool",
    "host_computer", "operating_system", "user_account",
}
```

#### Confidence Boosts

```go
VideoMetadataConfidenceBoosts = map[string]float64{
    "gps":           0.6,   // Very high confidence for GPS data
    "location":      0.5,   // High for location info
    "device":        0.4,   // High for device info
    "creator":       0.3,   // Medium-high for creator info
    "personal":      0.5,   // High for personal information
    "production":    0.3,   // Medium-high for production info
    "copyright":     0.3,   // Medium-high for copyright
    "technical":     0.2,   // Medium for technical info
}
```

## Confidence Scoring Methodology

### Multi-Factor Confidence Calculation

The enhanced confidence scoring system uses multiple factors to calculate the final confidence score:

```go
func (v *EnhancedMetadataValidator) calculateEnhancedConfidence(
    baseConfidence float64,
    preprocessorType string,
    fieldType string,
    fieldValue string,
    contextAnalysis *context.Analysis,
) float64 {
    // Start with base pattern match confidence
    confidence := baseConfidence
    
    // Apply preprocessor-specific boost
    confidence += v.getPreprocessorBoost(preprocessorType, fieldType)
    
    // Apply field-specific weighting
    confidence *= v.getFieldWeight(preprocessorType, fieldType)
    
    // Apply context analysis adjustments
    confidence = v.applyContextAdjustments(confidence, contextAnalysis)
    
    // Apply value-specific adjustments
    confidence = v.applyValueAdjustments(confidence, fieldValue, fieldType)
    
    // Ensure confidence stays within valid range [0, 100]
    return math.Min(100.0, math.Max(0.0, confidence))
}
```

### Preprocessor-Specific Boost Calculation

```go
func (v *EnhancedMetadataValidator) getPreprocessorBoost(
    preprocessorType string,
    fieldType string,
) float64 {
    rules := v.validationRules[preprocessorType]
    if rules == nil {
        return 0.0
    }
    
    // Get base boost for field type
    boost := rules.ConfidenceBoosts[fieldType]
    
    // Apply preprocessor-specific multiplier
    multiplier := v.getPreprocessorMultiplier(preprocessorType)
    
    return boost * multiplier * 100 // Convert to percentage points
}
```

### Context Analysis Integration

The confidence scoring system integrates with the Context Analysis Engine to apply context-aware adjustments:

#### Domain-Specific Adjustments

```go
func (v *EnhancedMetadataValidator) applyDomainAdjustments(
    confidence float64,
    domain string,
) float64 {
    domainAdjustments := map[string]float64{
        "financial":    1.2,  // 20% increase for financial documents
        "healthcare":   1.3,  // 30% increase for healthcare documents
        "legal":        1.1,  // 10% increase for legal documents
        "personal":     1.4,  // 40% increase for personal documents
        "corporate":    1.1,  // 10% increase for corporate documents
        "government":   1.2,  // 20% increase for government documents
    }
    
    if adjustment, exists := domainAdjustments[domain]; exists {
        return confidence * adjustment
    }
    
    return confidence
}
```

#### Document Type Adjustments

```go
func (v *EnhancedMetadataValidator) applyDocumentTypeAdjustments(
    confidence float64,
    docType string,
) float64 {
    typeAdjustments := map[string]float64{
        "resume":       1.5,  // 50% increase for resumes
        "contract":     1.3,  // 30% increase for contracts
        "invoice":      1.2,  // 20% increase for invoices
        "report":       1.1,  // 10% increase for reports
        "presentation": 1.1,  // 10% increase for presentations
        "spreadsheet":  1.2,  // 20% increase for spreadsheets
    }
    
    if adjustment, exists := typeAdjustments[docType]; exists {
        return confidence * adjustment
    }
    
    return confidence
}
```

### Value-Specific Adjustments

The system applies additional confidence adjustments based on the actual field values:

#### Pattern Strength Analysis

```go
func (v *EnhancedMetadataValidator) analyzePatternStrength(
    fieldValue string,
    fieldType string,
) float64 {
    switch fieldType {
    case "gps":
        return v.analyzeGPSPrecision(fieldValue)
    case "email":
        return v.analyzeEmailValidity(fieldValue)
    case "phone":
        return v.analyzePhoneFormat(fieldValue)
    case "device":
        return v.analyzeDeviceIdentifier(fieldValue)
    default:
        return 1.0 // No adjustment
    }
}
```

#### GPS Precision Analysis

```go
func (v *EnhancedMetadataValidator) analyzeGPSPrecision(coordinate string) float64 {
    // Parse coordinate precision
    parts := strings.Split(coordinate, ".")
    if len(parts) != 2 {
        return 0.8 // Lower confidence for malformed coordinates
    }
    
    decimalPlaces := len(parts[1])
    
    // More decimal places = higher precision = higher confidence
    switch {
    case decimalPlaces >= 6:
        return 1.3 // Very high precision
    case decimalPlaces >= 4:
        return 1.2 // High precision
    case decimalPlaces >= 2:
        return 1.1 // Medium precision
    default:
        return 0.9 // Low precision
    }
}
```

### Historical Performance Integration

The system maintains historical performance data to calibrate confidence scores:

```go
type PerformanceMetrics struct {
    TruePositives  int
    FalsePositives int
    TrueNegatives  int
    FalseNegatives int
    Accuracy       float64
    Precision      float64
    Recall         float64
}

func (v *EnhancedMetadataValidator) applyHistoricalCalibration(
    confidence float64,
    preprocessorType string,
    fieldType string,
) float64 {
    metrics := v.getHistoricalMetrics(preprocessorType, fieldType)
    if metrics == nil {
        return confidence
    }
    
    // Adjust confidence based on historical accuracy
    calibrationFactor := metrics.Precision
    return confidence * calibrationFactor
}
```

## Validation Rule Configuration

### Dynamic Rule Updates

The validation rules can be updated dynamically without system restart:

```go
func (v *EnhancedMetadataValidator) UpdateValidationRules(
    preprocessorType string,
    rules ValidationRule,
) error {
    v.mutex.Lock()
    defer v.mutex.Unlock()
    
    // Validate rule structure
    if err := v.validateRuleStructure(rules); err != nil {
        return fmt.Errorf("invalid rule structure: %w", err)
    }
    
    // Update rules
    v.validationRules[preprocessorType] = rules
    
    // Log rule update
    v.observer.LogInfo("validation_rules_updated", 
        "Updated validation rules for preprocessor", 
        map[string]interface{}{
            "preprocessor_type": preprocessorType,
            "sensitive_fields":  len(rules.SensitiveFields),
            "confidence_boosts": len(rules.ConfidenceBoosts),
        })
    
    return nil
}
```

### Configuration File Format

Validation rules can be configured via YAML files:

```yaml
# metadata-validation-rules.yaml
validation_rules:
  image_metadata:
    sensitive_fields:
      - gpslatitude
      - gpslongitude
      - camera_make
      - camera_model
      - artist
      - creator
    confidence_boosts:
      gps: 0.6
      device: 0.4
      creator: 0.3
    field_weights:
      gpslatitude: 1.5
      gpslongitude: 1.5
      camera_serial: 1.3
    context_modifiers:
      personal_domain: 1.4
      corporate_domain: 1.1

  document_metadata:
    sensitive_fields:
      - author
      - lastmodifiedby
      - manager
      - comments
      - description
    confidence_boosts:
      manager: 0.4
      comments: 0.5
      author: 0.3
    field_weights:
      manager: 1.4
      comments: 1.5
      personal_info: 1.6
```

## Performance Optimization

### Rule Caching

The system caches compiled validation rules for performance:

```go
type RuleCache struct {
    compiledPatterns map[string]*regexp.Regexp
    fieldMappings    map[string][]string
    boostCalculator  map[string]func(float64) float64
    mutex           sync.RWMutex
}

func (rc *RuleCache) GetCompiledPattern(
    preprocessorType string,
    fieldType string,
) *regexp.Regexp {
    rc.mutex.RLock()
    defer rc.mutex.RUnlock()
    
    key := fmt.Sprintf("%s:%s", preprocessorType, fieldType)
    return rc.compiledPatterns[key]
}
```

### Parallel Field Validation

Multiple metadata fields are validated in parallel for performance:

```go
func (v *EnhancedMetadataValidator) validateFieldsParallel(
    metadataContent MetadataContent,
) ([]detector.Match, error) {
    fields := v.extractFields(metadataContent.Content)
    
    // Create worker pool for parallel validation
    numWorkers := min(len(fields), runtime.NumCPU())
    fieldChan := make(chan FieldValidationJob, len(fields))
    resultChan := make(chan detector.Match, len(fields))
    
    // Start workers
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go v.fieldValidationWorker(&wg, fieldChan, resultChan, metadataContent)
    }
    
    // Send jobs
    for fieldName, fieldValue := range fields {
        fieldChan <- FieldValidationJob{
            Name:  fieldName,
            Value: fieldValue,
        }
    }
    close(fieldChan)
    
    // Collect results
    go func() {
        wg.Wait()
        close(resultChan)
    }()
    
    var matches []detector.Match
    for match := range resultChan {
        matches = append(matches, match)
    }
    
    return matches, nil
}
```

## Testing and Validation

### Unit Testing Framework

The validation rules are thoroughly tested using a comprehensive unit testing framework:

```go
func TestImageMetadataValidation(t *testing.T) {
    validator := NewEnhancedMetadataValidator()
    
    testCases := []struct {
        name               string
        metadataContent    MetadataContent
        expectedMatches    int
        expectedTypes      []string
        minConfidence      float64
    }{
        {
            name: "gps_coordinates_high_precision",
            metadataContent: MetadataContent{
                Content:          "GPSLatitude: 40.712800\nGPSLongitude: -74.006000",
                PreprocessorType: "image_metadata",
                SourceFile:       "test.jpg",
            },
            expectedMatches: 2,
            expectedTypes:   []string{"GPS_COORDINATE", "GPS_COORDINATE"},
            minConfidence:   85.0,
        },
        // Additional test cases...
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            matches, err := validator.ValidateMetadataContent(tc.metadataContent)
            
            assert.NoError(t, err)
            assert.Len(t, matches, tc.expectedMatches)
            
            for i, match := range matches {
                assert.Equal(t, tc.expectedTypes[i], match.Type)
                assert.GreaterOrEqual(t, match.Confidence, tc.minConfidence)
                assert.Equal(t, tc.metadataContent.PreprocessorType, match.Metadata["source"])
            }
        })
    }
}
```

### Integration Testing

Integration tests verify the complete validation pipeline:

```go
func TestEndToEndMetadataValidation(t *testing.T) {
    // Test complete flow from file processing to validation results
    testFiles := []struct {
        filePath           string
        expectedMetadata   map[string]int  // preprocessor -> match count
        expectedConfidence map[string]float64
    }{
        {
            filePath: "testdata/image_with_gps.jpg",
            expectedMetadata: map[string]int{
                "image_metadata": 3,  // GPS + device info
            },
            expectedConfidence: map[string]float64{
                "GPS_COORDINATE": 85.0,
                "DEVICE_INFO":    75.0,
            },
        },
        // Additional test cases...
    }
    
    for _, tc := range testFiles {
        t.Run(tc.filePath, func(t *testing.T) {
            // Process file through complete pipeline
            results := processFileEndToEnd(tc.filePath)
            
            // Verify metadata-specific matches
            metadataMatches := filterMetadataMatches(results)
            
            for preprocessorType, expectedCount := range tc.expectedMetadata {
                actualMatches := filterByPreprocessor(metadataMatches, preprocessorType)
                assert.Len(t, actualMatches, expectedCount)
                
                for _, match := range actualMatches {
                    expectedConf := tc.expectedConfidence[match.Type]
                    assert.GreaterOrEqual(t, match.Confidence, expectedConf)
                }
            }
        })
    }
}
```

## Monitoring and Observability

### Metrics Collection

The system collects comprehensive metrics for monitoring validation performance:

```go
type ValidationMetrics struct {
    ProcessedFields     int64
    SuccessfulMatches   int64
    FailedValidations   int64
    AverageConfidence   float64
    ProcessingTime      time.Duration
    PreprocessorCounts  map[string]int64
    FieldTypeCounts     map[string]int64
}

func (v *EnhancedMetadataValidator) collectMetrics(
    preprocessorType string,
    fieldType string,
    confidence float64,
    processingTime time.Duration,
) {
    v.metrics.ProcessedFields++
    v.metrics.ProcessingTime += processingTime
    v.metrics.PreprocessorCounts[preprocessorType]++
    v.metrics.FieldTypeCounts[fieldType]++
    
    // Update average confidence
    v.updateAverageConfidence(confidence)
    
    // Log metrics periodically
    if v.metrics.ProcessedFields%1000 == 0 {
        v.logMetrics()
    }
}
```

### Performance Monitoring

Key performance indicators are tracked and monitored:

- **Validation Accuracy**: True positive rate by preprocessor type
- **Processing Speed**: Average validation time per field
- **Confidence Distribution**: Distribution of confidence scores
- **Error Rates**: Validation failure rates by preprocessor type
- **Resource Usage**: Memory and CPU usage during validation

### Alerting

The system provides alerting for validation issues:

```go
func (v *EnhancedMetadataValidator) checkAlertConditions() {
    // Check accuracy degradation
    if v.getCurrentAccuracy() < v.minAccuracyThreshold {
        v.sendAlert("ACCURACY_DEGRADATION", 
            "Validation accuracy below threshold")
    }
    
    // Check processing time increase
    if v.getAverageProcessingTime() > v.maxProcessingTime {
        v.sendAlert("PERFORMANCE_DEGRADATION", 
            "Validation processing time exceeded threshold")
    }
    
    // Check error rate increase
    if v.getErrorRate() > v.maxErrorRate {
        v.sendAlert("HIGH_ERROR_RATE", 
            "Validation error rate exceeded threshold")
    }
}
```

---

*This document describes the preprocessor-aware validation rules and confidence scoring methodology implemented in Ferret Scan's enhanced metadata validation system. For implementation details, see the source code in `internal/validators/metadata/` and related packages.*