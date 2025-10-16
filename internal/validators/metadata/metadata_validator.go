// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/router"
	"ferret-scan/internal/validators"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Import MetadataContent from router package to avoid duplication
// This ensures compatibility with the dual-path bridge system

// ValidationRule defines validation rules for specific preprocessor types
type ValidationRule struct {
	SensitiveFields  []string                  // Fields to focus validation on
	ConfidenceBoosts map[string]float64        // Confidence boosts for specific field types
	PatternOverrides map[string]*regexp.Regexp // Custom patterns for specific fields
}

// Preprocessor type constants
const (
	PreprocessorTypeImageMetadata    = "image_metadata"
	PreprocessorTypeDocumentMetadata = "document_metadata"
	PreprocessorTypeOfficeMetadata   = "office_metadata"
	PreprocessorTypeAudioMetadata    = "audio_metadata"
	PreprocessorTypeVideoMetadata    = "video_metadata"
	PreprocessorTypePlainText        = "plain_text"
	PreprocessorTypeDocumentText     = "document_text"
)

// Validator implements the detector.Validator and PreprocessorAwareValidator interfaces for metadata
type Validator struct {
	// Observability
	observer *observability.StandardObserver

	// Preprocessor-aware validation rules
	validationRules map[string]ValidationRule

	// Thread safety
	mu sync.RWMutex
}

// NewValidator creates a new metadata validator with preprocessor-aware validation rules
func NewValidator() *Validator {
	validator := &Validator{
		validationRules: make(map[string]ValidationRule),
	}

	// Initialize default validation rules for each preprocessor type
	validator.initializeDefaultValidationRules()

	return validator
}

// ValidateMetadataContent validates metadata content with preprocessor context
func (v *Validator) ValidateMetadataContent(content router.MetadataContent) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("metadata_validator", "validate_metadata_content", content.SourceFile)
		if v.observer.DebugObserver != nil {
			v.observer.DebugObserver.LogDetail("metadata_validator",
				fmt.Sprintf("Processing content from %s (type: %s), content length: %d",
					content.SourceFile, content.PreprocessorType, len(content.Content)))
			contentPreview := content.Content
			if len(contentPreview) > 200 {
				contentPreview = contentPreview[:200] + "..."
			}
			v.observer.DebugObserver.LogDetail("metadata_validator",
				fmt.Sprintf("Content preview: %s", contentPreview))
		}
	}

	// Get validation rules for this preprocessor type
	rules, exists := v.validationRules[content.PreprocessorType]
	if !exists {
		// Use default validation if no specific rules exist
		return v.ValidateContent(content.Content, content.SourceFile)
	}

	// Apply preprocessor-specific validation
	matches, err := v.validateWithPreprocessorRules(content, rules)
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, err
	}

	// Apply preprocessor-specific confidence boosts
	for i := range matches {
		v.applyPreprocessorConfidenceBoosts(&matches[i], content.PreprocessorType, rules.ConfidenceBoosts)

		// Add preprocessor context to metadata
		if matches[i].Metadata == nil {
			matches[i].Metadata = make(map[string]interface{})
		}
		matches[i].Metadata["source_preprocessor"] = content.PreprocessorType
		matches[i].Metadata["preprocessor_name"] = content.PreprocessorName
		matches[i].Metadata["source_file"] = content.SourceFile
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":       len(matches),
			"preprocessor_type": content.PreprocessorType,
		})
	}

	return matches, nil
}

// GetSupportedPreprocessors returns the list of supported preprocessor types
func (v *Validator) GetSupportedPreprocessors() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	preprocessors := make([]string, 0, len(v.validationRules))
	for preprocessorType := range v.validationRules {
		preprocessors = append(preprocessors, preprocessorType)
	}
	return preprocessors
}

// SetPreprocessorValidationRules sets custom validation rules for preprocessor types
func (v *Validator) SetPreprocessorValidationRules(rules map[string]validators.ValidationRule) {
	v.mu.Lock()
	defer v.mu.Unlock()

	for preprocessorType, rule := range rules {
		// Convert validators.ValidationRule to metadata.ValidationRule
		metadataRule := ValidationRule{
			SensitiveFields:  rule.SensitiveFields,
			ConfidenceBoosts: rule.ConfidenceBoosts,
			PatternOverrides: make(map[string]*regexp.Regexp),
		}

		// Convert string patterns to compiled regexps
		for key, pattern := range rule.PatternOverrides {
			if compiled, err := regexp.Compile(pattern); err == nil {
				metadataRule.PatternOverrides[key] = compiled
			}
		}

		v.validationRules[preprocessorType] = metadataRule
	}
}

// initializeDefaultValidationRules sets up the default validation rules for each preprocessor type
func (v *Validator) initializeDefaultValidationRules() {
	// Image metadata validation rules
	v.validationRules[PreprocessorTypeImageMetadata] = ValidationRule{
		SensitiveFields: []string{
			"gpslatitude", "gpslongitude", "gpsaltitude", "gpsdatestamp",
			"gps_coordinates", "coordinates", // Add consolidated GPS coordinates
			"camera_make", "camera_model", "camera_serial", "device_id",
			"artist", "creator", "copyright", "software", "usercomment",
			"exif_artist", "exif_creator", "exif_copyright",
		},
		ConfidenceBoosts: map[string]float64{
			"gps":     0.6, // High confidence for GPS data
			"device":  0.4, // Medium-high for device info
			"creator": 0.3, // Medium for creator info
		},
		PatternOverrides: make(map[string]*regexp.Regexp),
	}

	// Document metadata validation rules
	v.validationRules[PreprocessorTypeDocumentMetadata] = ValidationRule{
		SensitiveFields: []string{
			"author", "creator", "lastmodifiedby", "manager", "company",
			"comments", "description", "keywords", "subject",
			"copyright", "rights", "copyrightnotice",
		},
		ConfidenceBoosts: map[string]float64{
			"manager":  0.4, // High confidence for manager info
			"comments": 0.5, // Very high for comments
			"author":   0.3, // Medium for author info
		},
		PatternOverrides: make(map[string]*regexp.Regexp),
	}

	// Office metadata validation rules (Office documents: .docx, .xlsx, .pptx, etc.)
	v.validationRules[PreprocessorTypeOfficeMetadata] = ValidationRule{
		SensitiveFields: []string{
			"author", "creator", "lastmodifiedby", "manager", "company",
			"comments", "description", "keywords", "subject",
			"copyright", "rights", "copyrightnotice", "application",
			"template",
		},
		ConfidenceBoosts: map[string]float64{
			"manager":     0.4, // High confidence for manager info
			"comments":    0.5, // Very high for comments
			"author":      0.3, // Medium for author info
			"company":     0.4, // High confidence for company info
			"application": 0.2, // Lower for application info
		},
		PatternOverrides: make(map[string]*regexp.Regexp),
	}

	// Audio metadata validation rules
	v.validationRules[PreprocessorTypeAudioMetadata] = ValidationRule{
		SensitiveFields: []string{
			"artist", "performer", "composer", "conductor", "albumartist",
			"publisher", "label", "record_label", "management", "booking",
			"venue", "studio", "recorded_at", "tpe1", "tpe2", "tpe3", "tpe4",
			"contact", "social_media", "facebook", "twitter", "instagram",
		},
		ConfidenceBoosts: map[string]float64{
			"contact":    0.5, // High confidence for contact info
			"management": 0.4, // High for management info
			"artist":     0.3, // Medium for artist info
		},
		PatternOverrides: make(map[string]*regexp.Regexp),
	}

	// Video metadata validation rules
	v.validationRules[PreprocessorTypeVideoMetadata] = ValidationRule{
		SensitiveFields: []string{
			"gpslatitude", "gpslongitude", "gpsaltitude", "xyz",
			"gps_coordinates", "coordinates", // Add consolidated GPS coordinates
			"gps_source", // GPS data source indicator
			"camera_make", "camera_model", "device_make", "recording_device", "device_serial",
			"recorded_by", "director", "producer", "cinematographer",
			"studio", "production_company", "recording_location",
		},
		ConfidenceBoosts: map[string]float64{
			"gps":      0.6, // High confidence for GPS data
			"location": 0.5, // High for location info
			"device":   0.4, // Medium-high for device info
			"creator":  0.3, // Medium for creator info
		},
		PatternOverrides: make(map[string]*regexp.Regexp),
	}
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Validate scans file content for metadata-related sensitive information
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("metadata_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("metadata_validator", "validate_file", filePath)
		}
	}

	// Metadata validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system metadata
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "metadata_extracted": false})
	}
	if finishStep != nil {
		finishStep(true, "Metadata validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// CalculateConfidence calculates the confidence score for a match
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Start with medium-low confidence
	confidence := 0.4
	flags := make(map[string]bool)

	matchLower := strings.ToLower(match)

	// Check for email patterns
	if strings.Contains(match, "@") {
		// Look for common email domains to increase confidence
		if strings.Contains(matchLower, "gmail.com") ||
			strings.Contains(matchLower, "yahoo.com") ||
			strings.Contains(matchLower, "hotmail.com") ||
			strings.Contains(matchLower, "outlook.com") {
			confidence += 0.3
			flags["contains_common_email_domain"] = true
		} else if strings.Contains(match, "@") {
			confidence += 0.2
			flags["contains_email_pattern"] = true
		}

		if strings.Contains(matchLower, "email:") {
			confidence += 0.1
			flags["contains_email_field"] = true
		}
	}

	// Check for author/creator fields
	if strings.Contains(matchLower, "author:") {
		confidence += 0.2
		flags["contains_author_field"] = true
	}
	if strings.Contains(matchLower, "creator:") {
		confidence += 0.2
		flags["contains_creator_field"] = true
	}
	if strings.Contains(matchLower, "owner:") {
		confidence += 0.15
		flags["contains_owner_field"] = true
	}
	if strings.Contains(matchLower, "artist:") {
		confidence += 0.1
		flags["contains_artist_field"] = true
	}
	if strings.Contains(matchLower, "lastmodifiedby:") ||
		strings.Contains(matchLower, "last modified by:") {
		confidence += 0.2
		flags["contains_modifier_field"] = true
	}
	if strings.Contains(matchLower, "company:") {
		confidence += 0.15
		flags["contains_company_field"] = true
	}
	if strings.Contains(matchLower, "producer:") {
		confidence += 0.15
		flags["contains_producer_field"] = true
	}
	if strings.Contains(matchLower, "manager:") {
		confidence += 0.25 // High confidence for manager field
		flags["contains_manager_field"] = true
	}
	if strings.Contains(matchLower, "comments:") {
		confidence += 0.3 // Very high confidence for comments
		flags["contains_comments_field"] = true
	}
	if strings.Contains(matchLower, "description:") {
		confidence += 0.2
		flags["contains_description_field"] = true
	}
	if strings.Contains(matchLower, "keywords:") {
		confidence += 0.15
		flags["contains_keywords_field"] = true
	}
	if strings.Contains(matchLower, "contentstatus:") {
		confidence += 0.1
		flags["contains_content_status_field"] = true
	}
	if strings.Contains(matchLower, "identifier:") {
		confidence += 0.15
		flags["contains_identifier_field"] = true
	}

	// Enhanced copyright detection - apply intellectual property validator patterns to media
	if v.containsEnhancedCopyright(match) {
		confidence += 0.4 // Increased confidence for enhanced copyright detection
		flags["contains_enhanced_copyright"] = true
	} else if strings.Contains(matchLower, "copyright:") ||
		strings.Contains(matchLower, "rights:") ||
		strings.Contains(matchLower, "copyrightnotice:") {
		confidence += 0.3
		flags["contains_copyright_info"] = true
	}

	// Enhanced phone number detection - apply phone validator patterns to media
	if v.containsEnhancedPhoneNumber(match) {
		confidence += 0.5 // Increased confidence for enhanced phone detection
		flags["contains_enhanced_phone"] = true
	} else {
		// Fallback to basic phone pattern
		phonePattern := regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`)
		if phonePattern.MatchString(match) {
			confidence += 0.4
			flags["contains_phone_number"] = true
		}
	}

	// Enhanced GPS/location data detection - apply enhanced patterns to media
	if v.containsEnhancedGPSData(match) {
		confidence += 0.6 // Higher confidence for enhanced GPS detection
		flags["contains_enhanced_gps"] = true
	} else {
		// Fallback to existing GPS detection patterns
		if strings.Contains(matchLower, "gps position") ||
			strings.Contains(matchLower, "coordinates:") {
			confidence += 0.4
			flags["contains_gps_coordinates"] = true
		}
		if strings.Contains(matchLower, "gpslatitudedecimal") ||
			strings.Contains(matchLower, "gpslongitudedecimal") {
			confidence += 0.5 // High confidence for precise coordinates
			flags["contains_gps_decimal_coords"] = true
		}
		if strings.Contains(matchLower, "gpslatitude") ||
			strings.Contains(matchLower, "gpslongitude") {
			confidence += 0.4
			flags["contains_gps_coords"] = true
		}
		if strings.Contains(matchLower, "gpsaltitude") {
			confidence += 0.5 // Enhanced: GPS altitude is HIGH severity - precise location data
			flags["contains_gps_altitude"] = true
		}
		if strings.Contains(matchLower, "latitude") ||
			strings.Contains(matchLower, "longitude") {
			confidence += 0.3
			flags["contains_lat_long"] = true
		}
		if strings.Contains(matchLower, "gps") {
			confidence += 0.25
			flags["contains_gps_data"] = true
		}
		if strings.Contains(matchLower, "location") ||
			strings.Contains(matchLower, "position") {
			confidence += 0.2
			flags["contains_location_data"] = true
		}
		if strings.Contains(matchLower, "gpsdatestamp") ||
			strings.Contains(matchLower, "gpslatituderef") ||
			strings.Contains(matchLower, "gpslongituderef") {
			confidence += 0.3
			flags["contains_gps_metadata"] = true
		}
	}

	// Check for GPS coordinate combinations (lat+long together = higher confidence)
	hasLatitude := strings.Contains(matchLower, "latitude")
	hasLongitude := strings.Contains(matchLower, "longitude")
	if hasLatitude && hasLongitude {
		confidence += 0.2 // Bonus for coordinate pairs
		flags["contains_coordinate_pair"] = true
	}

	// Check for video-specific metadata patterns
	if strings.Contains(matchLower, "camera_make:") ||
		strings.Contains(matchLower, "camera_model:") ||
		strings.Contains(matchLower, "device_make:") ||
		strings.Contains(matchLower, "device_model:") {
		confidence += 0.3
		flags["contains_video_device_info"] = true
	}
	if strings.Contains(matchLower, "recording_device:") ||
		strings.Contains(matchLower, "capture_device:") ||
		strings.Contains(matchLower, "recorder:") {
		confidence += 0.25
		flags["contains_recording_device"] = true
	}
	if strings.Contains(matchLower, "creation_time:") ||
		strings.Contains(matchLower, "recording_date:") ||
		strings.Contains(matchLower, "capture_date:") {
		confidence += 0.2
		flags["contains_video_timestamp"] = true
	}
	if strings.Contains(matchLower, "recorded_by:") ||
		strings.Contains(matchLower, "encoded_by:") ||
		strings.Contains(matchLower, "created_by:") {
		confidence += 0.3
		flags["contains_video_creator"] = true
	}
	if strings.Contains(matchLower, "xyz:") &&
		(strings.Contains(match, "+") || strings.Contains(match, "-")) {
		confidence += 0.4 // Video GPS coordinates in xyz format
		flags["contains_video_gps_xyz"] = true
	}

	// Check for audio-specific metadata patterns
	if strings.Contains(matchLower, "artist:") ||
		strings.Contains(matchLower, "performer:") ||
		strings.Contains(matchLower, "albumartist:") ||
		strings.Contains(matchLower, "composer:") {
		confidence += 0.3
		flags["contains_audio_artist"] = true
	}
	if strings.Contains(matchLower, "recording_location:") ||
		strings.Contains(matchLower, "studio:") ||
		strings.Contains(matchLower, "venue:") ||
		strings.Contains(matchLower, "recorded_at:") {
		confidence += 0.25
		flags["contains_audio_location"] = true
	}
	if strings.Contains(matchLower, "publisher:") ||
		strings.Contains(matchLower, "label:") ||
		strings.Contains(matchLower, "record_label:") ||
		strings.Contains(matchLower, "management:") {
		confidence += 0.2
		flags["contains_audio_business"] = true
	}
	if strings.Contains(matchLower, "tpe1:") ||
		strings.Contains(matchLower, "tpe2:") ||
		strings.Contains(matchLower, "tpe3:") ||
		strings.Contains(matchLower, "tpe4:") {
		confidence += 0.25 // ID3 tag fields for performers
		flags["contains_id3_performer"] = true
	}

	// Check for document metadata fields
	if strings.Contains(matchLower, "subject:") ||
		strings.Contains(matchLower, "keywords:") ||
		strings.Contains(matchLower, "description:") {
		confidence += 0.1
		flags["contains_document_metadata"] = true
	}
	if strings.Contains(matchLower, "title:") {
		confidence += 0.05
		flags["contains_title_field"] = true
	}

	// Check for timestamps (creation/modification dates can be sensitive)
	if strings.Contains(matchLower, "creationdate:") ||
		strings.Contains(matchLower, "modificationdate:") ||
		strings.Contains(matchLower, "modificationtime:") {
		confidence += 0.1
		flags["contains_timestamp"] = true
	}

	// Check for software/application info that might contain user paths
	if (strings.Contains(matchLower, "application:") ||
		strings.Contains(matchLower, "software:") ||
		strings.Contains(matchLower, "producer:")) &&
		(strings.Contains(match, "/Users/") ||
			strings.Contains(match, "/home/") ||
			strings.Contains(match, "C:\\Users\\") ||
			strings.Contains(match, "~")) {
		confidence += 0.25
		flags["contains_user_path"] = true
	}

	// Check for device identifiers
	if strings.Contains(matchLower, "serial") {
		confidence += 0.2
		flags["contains_serial_number"] = true
	}
	if strings.Contains(matchLower, "device id") ||
		strings.Contains(matchLower, "device identifier") {
		confidence += 0.2
		flags["contains_device_id"] = true
	}

	// Check for username patterns in paths
	if strings.Contains(matchLower, "/users/") ||
		strings.Contains(matchLower, "/home/") {
		confidence += 0.15
		flags["contains_user_path"] = true
	}

	// Decrease confidence for test/example data
	if strings.Contains(matchLower, "test") ||
		strings.Contains(matchLower, "example") ||
		strings.Contains(matchLower, "sample") ||
		strings.Contains(matchLower, "demo") {
		confidence -= 0.2
		flags["likely_test_data"] = true
	}

	// Cap confidence between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.0 {
		confidence = 0.0
	}

	return confidence, flags
}

// getAuthorDetectionReason returns a human-readable reason for author detection
func (v *Validator) getAuthorDetectionReason(line string) string {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "artist:") {
		return "Image artist metadata field detected"
	} else if strings.Contains(lineLower, "iptc_byline:") {
		return "IPTC byline metadata field detected"
	} else if strings.Contains(lineLower, "author:") {
		return "Document author field detected"
	} else if strings.Contains(lineLower, "creator:") {
		return "Document creator field detected"
	} else if strings.Contains(lineLower, "lastmodifiedby:") {
		return "Last modified by field detected"
	}
	return "Author/creator information detected"
}

// AnalyzeContext analyzes the context around a match to refine confidence
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Start with no adjustment
	confidenceAdjustment := 0.0
	contextLower := strings.ToLower(context.FullLine)

	// Check for keywords that might indicate PII
	piiIndicators := []string{
		"personal", "private", "confidential", "sensitive", "restricted",
		"identity", "contact", "address", "phone", "individual", "profile",
	}

	for _, indicator := range piiIndicators {
		if strings.Contains(contextLower, indicator) {
			confidenceAdjustment += 0.1
			// Only add adjustment once to avoid excessive boosting
			break
		}
	}

	// Check for keywords that might indicate non-PII or test data
	nonPiiIndicators := []string{
		"test", "example", "sample", "demo", "placeholder", "dummy",
		"template", "default", "anonymous", "unknown",
	}

	for _, indicator := range nonPiiIndicators {
		if strings.Contains(contextLower, indicator) {
			confidenceAdjustment -= 0.15
			// Only subtract adjustment once to avoid excessive reduction
			break
		}
	}

	// Check for specific patterns that strongly indicate PII
	if strings.Contains(contextLower, "gps position") &&
		(strings.Contains(contextLower, "n") || strings.Contains(contextLower, "s")) &&
		(strings.Contains(contextLower, "e") || strings.Contains(contextLower, "w")) {
		// This looks like formatted GPS coordinates
		confidenceAdjustment += 0.2
	}

	// Check for email patterns with domain
	if strings.Contains(context.FullLine, "@") &&
		(strings.Contains(context.FullLine, ".com") ||
			strings.Contains(context.FullLine, ".org") ||
			strings.Contains(context.FullLine, ".net") ||
			strings.Contains(context.FullLine, ".edu")) {
		confidenceAdjustment += 0.15
	}

	return confidenceAdjustment
}

// ValidateContent validates preprocessed content for metadata-related sensitive information
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Only process content that appears to be actual document metadata, not file system metadata
	if !v.isDocumentMetadata(content) {
		return []detector.Match{}, nil
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Track GPS fields we've seen to avoid exact duplicates but allow different GPS data types
	seenGPSFields := make(map[string]bool)
	// Track if we've seen author/creator info to avoid duplicate matches
	seenAuthor := false
	// Track current embedded media context
	currentEmbeddedMedia := ""
	// Track GPS coordinate components for combining
	gpsCoordinates := make(map[string]string) // field -> value
	gpsLineNumbers := make(map[string]int)    // field -> line number

	for lineNumber, line := range lines {
		// Check if we're entering an embedded media section
		if strings.Contains(line, "--- Embedded Media") {
			if idx := strings.Index(line, "("); idx != -1 {
				if endIdx := strings.Index(line[idx:], ")"); endIdx != -1 {
					embeddedName := line[idx+1 : idx+endIdx]
					// Extract just the image filename from the path
					imageName := filepath.Base(embeddedName)
					currentEmbeddedMedia = fmt.Sprintf("%s -> %s", filepath.Base(originalPath), imageName)
				}
			}
			continue
		}

		// Determine filename based on context
		filename := originalPath
		if currentEmbeddedMedia != "" {
			filename = currentEmbeddedMedia
		}

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// CRITICAL FIX: Only process lines that are actual metadata fields
		// Skip document content that doesn't match metadata field patterns
		if !v.isMetadataField(line) {
			continue
		}

		// Check for GPS coordinates - collect them for combining
		if v.containsGPSCoordinates(line) {
			// Extract the field name and value
			fieldName := ""
			fieldValue := ""
			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				fieldName = strings.TrimSpace(strings.ToLower(parts[0]))
				fieldValue = strings.TrimSpace(parts[1])
			}

			// Skip if we've already seen this exact field
			if seenGPSFields[fieldName] {
				continue
			}
			seenGPSFields[fieldName] = true

			// Store GPS coordinate components for later combination
			if v.isGPSCoordinateComponent(fieldName) {
				gpsCoordinates[fieldName] = fieldValue
				gpsLineNumbers[fieldName] = lineNumber + 1
			} else {
				// Handle non-coordinate GPS fields (altitude, timestamp) individually
				// But filter out meaningless GPS values
				if v.isMeaningfulGPSValue(fieldName, fieldValue) {
					confidence, checks := v.CalculateConfidence(line)
					contextInfo := detector.ContextInfo{FullLine: line}
					contextImpact := v.AnalyzeContext(line, contextInfo)
					confidence += contextImpact
					if confidence > 1.0 {
						confidence = 1.0
					} else if confidence < 0.0 {
						confidence = 0.0
					}
					contextInfo.ConfidenceImpact = contextImpact

					matches = append(matches, detector.Match{
						Text:       line,
						LineNumber: lineNumber + 1,
						Type:       "GPS",
						Confidence: confidence * 100,
						Filename:   filename,
						Validator:  "metadata",
						Context:    contextInfo,
						Metadata: map[string]any{
							"metadata_type":     "gps_coordinates",
							"validation_checks": checks,
							"context_impact":    contextImpact,
							"source":            "preprocessed_content",
							"original_file":     originalPath,
							"detection_reason":  v.getGPSDetectionReason(line),
							"gps_field_name":    fieldName,
						},
					})
				}
			}
		}

		// Check for video-specific metadata patterns
		if videoMatch := v.checkVideoMetadata(line); videoMatch != nil {
			videoMatch.LineNumber = lineNumber + 1
			videoMatch.Filename = filename
			// Add original file context to metadata
			if videoMatch.Metadata == nil {
				videoMatch.Metadata = make(map[string]any)
			}
			videoMatch.Metadata["original_file"] = originalPath
			matches = append(matches, *videoMatch)
		}

		// Check for audio-specific metadata patterns
		if audioMatch := v.checkAudioMetadata(line); audioMatch != nil {
			audioMatch.LineNumber = lineNumber + 1
			audioMatch.Filename = filename
			// Add original file context to metadata
			if audioMatch.Metadata == nil {
				audioMatch.Metadata = make(map[string]any)
			}
			audioMatch.Metadata["original_file"] = originalPath
			matches = append(matches, *audioMatch)
		}

		// Check for specific office metadata fields first (most specific)
		if officeMatch := v.checkOfficeMetadataFields(line); officeMatch != nil {
			officeMatch.LineNumber = lineNumber + 1
			officeMatch.Filename = filename
			matches = append(matches, *officeMatch)
		}

		// Check for high priority sensitive fields
		if highPriorityMatch := v.checkHighPrioritySensitive(line); highPriorityMatch != nil {
			highPriorityMatch.LineNumber = lineNumber + 1
			highPriorityMatch.Filename = filename
			matches = append(matches, *highPriorityMatch)
		}

		// Check for medium priority sensitive fields
		if mediumPriorityMatch := v.checkMediumPrioritySensitive(line); mediumPriorityMatch != nil {
			mediumPriorityMatch.LineNumber = lineNumber + 1
			mediumPriorityMatch.Filename = filename
			matches = append(matches, *mediumPriorityMatch)
		}

		// Check for low priority sensitive fields
		if lowPriorityMatch := v.checkLowPrioritySensitive(line); lowPriorityMatch != nil {
			lowPriorityMatch.LineNumber = lineNumber + 1
			lowPriorityMatch.Filename = filename
			matches = append(matches, *lowPriorityMatch)
		}

		// Check for LastModifiedBy field specifically (high priority)
		if v.containsLastModifiedBy(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "LAST_MODIFIED_BY"),
				LineNumber: lineNumber + 1,
				Type:       "LAST_MODIFIED_BY",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "last_modified_by",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for Manager field (high priority)
		if v.containsManager(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.1 // Boost for manager field
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "MANAGER_INFO"),
				LineNumber: lineNumber + 1,
				Type:       "MANAGER_INFO",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "manager_info",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for Comments field (high priority)
		if v.containsComments(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.15 // High boost for comments
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "DOCUMENT_COMMENTS"),
				LineNumber: lineNumber + 1,
				Type:       "DOCUMENT_COMMENTS",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "document_comments",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for Description field (high priority)
		if v.containsDescription(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.1 // Boost for description
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "DOCUMENT_DESCRIPTION"),
				LineNumber: lineNumber + 1,
				Type:       "DOCUMENT_DESCRIPTION",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "document_description",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for Keywords field (medium priority)
		if v.containsKeywords(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "DOCUMENT_KEYWORDS"),
				LineNumber: lineNumber + 1,
				Type:       "DOCUMENT_KEYWORDS",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "document_keywords",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for author/creator information (legacy)
		if !seenAuthor && v.containsAuthorInfo(line) {
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact
			matches = append(matches, detector.Match{
				Text:       v.extractSensitiveValue(line, "AUTHOR_INFO"),
				LineNumber: lineNumber + 1,
				Type:       "AUTHOR_INFO",
				Confidence: confidence * 100,
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "author_info",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
			seenAuthor = true
		}

		// Check for other potentially sensitive metadata patterns
		if v.containsSensitiveMetadata(line) {
			// Extract specific sensitive item from the line
			sensitiveItem := v.extractSensitiveItem(line)
			if sensitiveItem == "" {
				sensitiveItem = line // fallback to full line if extraction fails
			}

			confidence, checks := v.CalculateConfidence(line)

			// Create context info for the line
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}

			// Analyze context and adjust confidence
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact

			// Ensure confidence stays within bounds
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}

			contextInfo.ConfidenceImpact = contextImpact

			// Determine specific type based on content
			detectionType := ""
			lineLower := strings.ToLower(line)

			if strings.Contains(line, "@") && v.extractEmail(line) != "" {
				detectionType = "EMAIL"
				sensitiveItem = v.extractEmail(line) // Extract just the email
			} else if strings.Contains(lineLower, "device id") || strings.Contains(lineLower, "serial number") || strings.Contains(lineLower, "camera model") || strings.Contains(lineLower, "phone model") {
				detectionType = "DEVICE_INFO"
			} else if (strings.Contains(lineLower, "application:") || strings.Contains(lineLower, "software:") || strings.Contains(lineLower, "producer:")) && (strings.Contains(line, "/Users/") || strings.Contains(line, "/home/") || strings.Contains(line, "C:\\Users\\") || strings.Contains(line, "~")) {
				detectionType = "SOFTWARE_PATH"
			}

			// Only create match if we found specific sensitive information
			if detectionType == "" {
				continue
			}

			matches = append(matches, detector.Match{
				Text:       sensitiveItem,
				LineNumber: lineNumber + 1,
				Type:       detectionType,
				Confidence: confidence * 100, // Convert to percentage
				Filename:   filename,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "sensitive_metadata",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}
	}

	// After processing all lines, combine GPS coordinate components
	combinedMatches := v.combineGPSCoordinates(gpsCoordinates, gpsLineNumbers, originalPath, currentEmbeddedMedia)
	matches = append(matches, combinedMatches...)

	return matches, nil
}

// containsSensitiveMetadata checks if a line contains potentially sensitive metadata
func (v *Validator) containsSensitiveMetadata(line string) bool {
	lineLower := strings.ToLower(line)

	// Check for various sensitive metadata patterns
	sensitivePatterns := []string{
		"email:", "contact:", "phone:", "address:", "location:",
		"personal", "private", "confidential", "sensitive",
		"user:", "owner:", "creator:", "author:", "artist:",
		"manager:", "company:", "organization:",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lineLower, pattern) {
			return true
		}
	}

	return false
}

// extractSensitiveItem extracts the sensitive part from a metadata line
func (v *Validator) extractSensitiveItem(line string) string {
	// Try to extract the value part after a colon
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}

	// Return the full line if no colon found
	return line
}

// extractEmail extracts email addresses from a line
func (v *Validator) extractEmail(line string) string {
	// Simple email extraction - look for @ symbol with domain
	emailPattern := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	match := emailPattern.FindString(line)
	return match
}

// validateWithPreprocessorRules validates content using preprocessor-specific rules
func (v *Validator) validateWithPreprocessorRules(content router.MetadataContent, rules ValidationRule) ([]detector.Match, error) {
	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content.Content, "\n")

	for lineNumber, line := range lines {
		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Only process lines that are actual metadata fields
		if !v.isMetadataField(line) {
			continue
		}

		// Check if this line contains any sensitive fields for this preprocessor type
		if v.containsSensitiveFieldForPreprocessor(line, rules.SensitiveFields) {
			confidence, checks := v.CalculateConfidence(line)

			// Create context info for the line
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}

			// Analyze context and adjust confidence
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact

			// Ensure confidence stays within bounds
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}

			contextInfo.ConfidenceImpact = contextImpact

			// Determine match type based on content and preprocessor type
			matchType := v.determineMatchType(line, content.PreprocessorType)

			// Extract just the sensitive value from the metadata field
			sensitiveValue := v.extractSensitiveValue(line, matchType)

			matches = append(matches, detector.Match{
				Text:       sensitiveValue,
				LineNumber: lineNumber + 1,
				Type:       matchType,
				Confidence: confidence * 100, // Convert to percentage
				Filename:   content.SourceFile,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]interface{}{
					"metadata_type":     matchType,
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
					"original_file":     content.SourceFile,
					"preprocessor_type": content.PreprocessorType,
					"preprocessor_name": content.PreprocessorName,
					"full_field":        line, // Keep the original field for reference
				},
			})
		}
	}

	return matches, nil
}

// containsSensitiveFieldForPreprocessor checks if a line contains sensitive fields for the given preprocessor
func (v *Validator) containsSensitiveFieldForPreprocessor(line string, sensitiveFields []string) bool {
	lineLower := strings.ToLower(line)

	// Skip version numbers - they're not sensitive information
	if v.isVersionNumber(line) {
		return false
	}

	for _, field := range sensitiveFields {
		if strings.Contains(lineLower, strings.ToLower(field)) {
			return true
		}
	}

	return false
}

// determineMatchType determines the match type based on content and preprocessor type
func (v *Validator) determineMatchType(line, preprocessorType string) string {
	lineLower := strings.ToLower(line)

	// GPS-related patterns
	if strings.Contains(lineLower, "gps") || strings.Contains(lineLower, "latitude") || strings.Contains(lineLower, "longitude") {
		return "GPS"
	}

	// Device information patterns
	if strings.Contains(lineLower, "camera") || strings.Contains(lineLower, "device") || strings.Contains(lineLower, "serial") {
		return "DEVICE_INFO"
	}

	// Author/creator patterns
	if strings.Contains(lineLower, "author") || strings.Contains(lineLower, "creator") || strings.Contains(lineLower, "artist") {
		return "AUTHOR_INFO"
	}

	// Contact information patterns
	if strings.Contains(line, "@") {
		return "EMAIL"
	}

	// Comments and descriptions
	if strings.Contains(lineLower, "comment") {
		return "DOCUMENT_COMMENTS"
	}
	if strings.Contains(lineLower, "description") {
		return "DOCUMENT_DESCRIPTION"
	}

	// Manager information
	if strings.Contains(lineLower, "manager") {
		return "MANAGER_INFO"
	}

	// Last modified by
	if strings.Contains(lineLower, "lastmodifiedby") {
		return "LAST_MODIFIED_BY"
	}

	// Office metadata specific fields
	if strings.Contains(lineLower, "company:") {
		return "COMPANY_INFO"
	}
	if strings.Contains(lineLower, "application:") {
		return "APPLICATION_INFO"
	}
	if strings.Contains(lineLower, "template:") {
		return "TEMPLATE_INFO"
	}

	// Preprocessor-specific types with enhanced detection
	switch preprocessorType {
	case PreprocessorTypeImageMetadata:
		return v.determineImageMetadataType(line)
	case PreprocessorTypeDocumentMetadata:
		return "DOCUMENT_METADATA"
	case PreprocessorTypeAudioMetadata:
		return "AUDIO_METADATA"
	case PreprocessorTypeVideoMetadata:
		return "VIDEO_METADATA"
	default:
		return "METADATA"
	}
}

// determineImageMetadataType provides specific categorization for image metadata
func (v *Validator) determineImageMetadataType(line string) string {
	lineLower := strings.ToLower(line)

	// Software/Application patterns
	if strings.Contains(lineLower, "photoshop") || strings.Contains(lineLower, "gimp") ||
		strings.Contains(lineLower, "lightroom") || strings.Contains(lineLower, "illustrator") ||
		strings.Contains(lineLower, "picasa") || strings.Contains(lineLower, "paint") ||
		strings.Contains(lineLower, "software:") || strings.Contains(lineLower, "application:") ||
		strings.Contains(lineLower, "ver.") || strings.Contains(lineLower, "version") ||
		strings.Contains(lineLower, "adobe") || strings.Contains(lineLower, "microsoft") ||
		strings.Contains(lineLower, "corel") || strings.Contains(lineLower, "canva") {
		return "IMAGE_SOFTWARE"
	}

	// Camera/Device specific information
	if strings.Contains(lineLower, "camera") || strings.Contains(lineLower, "lens") ||
		strings.Contains(lineLower, "focal") || strings.Contains(lineLower, "aperture") ||
		strings.Contains(lineLower, "iso") || strings.Contains(lineLower, "shutter") ||
		strings.Contains(lineLower, "exposure") || strings.Contains(lineLower, "flash") ||
		strings.Contains(lineLower, "canon") || strings.Contains(lineLower, "nikon") ||
		strings.Contains(lineLower, "sony") || strings.Contains(lineLower, "fuji") {
		return "IMAGE_CAMERA_INFO"
	}

	// Color profile and technical settings
	if strings.Contains(lineLower, "color") || strings.Contains(lineLower, "profile") ||
		strings.Contains(lineLower, "icc") || strings.Contains(lineLower, "srgb") ||
		strings.Contains(lineLower, "cmyk") || strings.Contains(lineLower, "resolution") ||
		strings.Contains(lineLower, "dpi") || strings.Contains(lineLower, "bit") {
		return "IMAGE_TECHNICAL_INFO"
	}

	// Copyright and rights information
	if strings.Contains(lineLower, "copyright") || strings.Contains(lineLower, "rights") ||
		strings.Contains(lineLower, "license") || strings.Contains(lineLower, "usage") {
		return "IMAGE_COPYRIGHT"
	}

	// Location/GPS information (more specific than general GPS)
	if strings.Contains(lineLower, "location") || strings.Contains(lineLower, "place") ||
		strings.Contains(lineLower, "city") || strings.Contains(lineLower, "country") ||
		strings.Contains(lineLower, "address") {
		return "IMAGE_LOCATION"
	}

	// Keywords and tags
	if strings.Contains(lineLower, "keyword") || strings.Contains(lineLower, "tag") ||
		strings.Contains(lineLower, "subject") || strings.Contains(lineLower, "category") {
		return "IMAGE_KEYWORDS"
	}

	// Timestamps and dates
	if strings.Contains(lineLower, "date") || strings.Contains(lineLower, "time") ||
		strings.Contains(lineLower, "created") || strings.Contains(lineLower, "modified") {
		return "IMAGE_TIMESTAMP"
	}

	// Default fallback for other image metadata
	return "IMAGE_METADATA"
}

// applyPreprocessorConfidenceBoosts applies confidence boosts based on preprocessor type
func (v *Validator) applyPreprocessorConfidenceBoosts(match *detector.Match, preprocessorType string, boosts map[string]float64) {
	lineLower := strings.ToLower(match.Text)

	// Apply confidence boosts based on field types
	for fieldType, boost := range boosts {
		if strings.Contains(lineLower, fieldType) {
			match.Confidence += boost * 100 // Convert to percentage

			// Add boost information to metadata
			if match.Metadata == nil {
				match.Metadata = make(map[string]interface{})
			}
			match.Metadata[fieldType+"_boost"] = boost * 100
		}
	}

	// Ensure confidence stays within bounds
	if match.Confidence > 100 {
		match.Confidence = 100
	} else if match.Confidence < 0 {
		match.Confidence = 0
	}
}

// containsEnhancedCopyright checks for enhanced copyright patterns
func (v *Validator) containsEnhancedCopyright(match string) bool {
	matchLower := strings.ToLower(match)

	// Enhanced copyright detection patterns
	copyrightPatterns := []string{
		"copyright", "©", "(c)", "all rights reserved", "proprietary",
		"confidential", "trade secret", "trademark", "patent",
	}

	for _, pattern := range copyrightPatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	return false
}

// containsEnhancedPhoneNumber checks for enhanced phone number patterns
func (v *Validator) containsEnhancedPhoneNumber(match string) bool {
	// Enhanced phone number patterns
	phonePatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
		regexp.MustCompile(`\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b`),
		regexp.MustCompile(`\b\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b`),
		regexp.MustCompile(`\b\d{3}\s\d{3}\s\d{4}\b`),
	}

	for _, pattern := range phonePatterns {
		if pattern.MatchString(match) {
			return true
		}
	}

	return false
}

// containsEnhancedGPSData checks for enhanced GPS data patterns
func (v *Validator) containsEnhancedGPSData(match string) bool {
	matchLower := strings.ToLower(match)

	// Enhanced GPS patterns
	gpsPatterns := []string{
		"gpslatitude", "gpslongitude", "gpsaltitude", "gpsdatestamp",
		"gpslatituderef", "gpslongituderef", "gpsaltituderef",
		"coordinates", "latitude", "longitude", "altitude",
		"xyz:", "position", "location",
	}

	for _, pattern := range gpsPatterns {
		if strings.Contains(matchLower, pattern) {
			return true
		}
	}

	// Check for coordinate patterns
	coordPattern := regexp.MustCompile(`[+-]?\d+\.\d+`)
	if coordPattern.MatchString(match) && (strings.Contains(matchLower, "n") || strings.Contains(matchLower, "s") ||
		strings.Contains(matchLower, "e") || strings.Contains(matchLower, "w")) {
		return true
	}

	return false
}

// isDocumentMetadata checks if content appears to be actual document metadata
func (v *Validator) isDocumentMetadata(content string) bool {
	// Check for metadata field patterns
	metadataIndicators := []string{
		":", "=", "author", "creator", "gps", "camera", "device",
		"metadata", "exif", "properties", "tags",
	}

	contentLower := strings.ToLower(content)
	for _, indicator := range metadataIndicators {
		if strings.Contains(contentLower, indicator) {
			return true
		}
	}

	return false
}

// isMetadataField checks if a line represents a metadata field
func (v *Validator) isMetadataField(line string) bool {
	// Skip empty lines
	if strings.TrimSpace(line) == "" {
		return false
	}

	// Check for field patterns (key: value or key = value)
	if strings.Contains(line, ":") || strings.Contains(line, "=") {
		return true
	}

	// Check for known metadata field prefixes
	lineLower := strings.ToLower(line)
	metadataFields := []string{
		"gps", "camera", "device", "author", "creator", "artist",
		"manager", "comments", "description", "keywords", "subject",
		"copyright", "rights", "software", "application", "producer",
		"venue", "studio", "recorded", "publisher", "label",
		"tpe1", "tpe2", "tpe3", "tpe4", "contact", "management",
		"director", "cinematographer", "xyz",
	}

	for _, field := range metadataFields {
		if strings.Contains(lineLower, field) {
			return true
		}
	}

	return false
}

// containsGPSCoordinates checks if a line contains GPS coordinates
func (v *Validator) containsGPSCoordinates(line string) bool {
	lineLower := strings.ToLower(line)

	// GPS field patterns
	gpsFields := []string{
		"gpslatitude", "gpslongitude", "gpsaltitude", "gpsdatestamp",
		"gpslatituderef", "gpslongituderef", "gpsaltituderef",
		"coordinates", "latitude", "longitude", "altitude", "xyz:",
	}

	for _, field := range gpsFields {
		if strings.Contains(lineLower, field) {
			return true
		}
	}

	return false
}

// getGPSDetectionReason returns the reason why GPS data was detected
func (v *Validator) getGPSDetectionReason(line string) string {
	lineLower := strings.ToLower(line)

	if strings.Contains(lineLower, "gpslatitude") {
		return "GPS latitude coordinate detected"
	}
	if strings.Contains(lineLower, "gpslongitude") {
		return "GPS longitude coordinate detected"
	}
	if strings.Contains(lineLower, "gpsaltitude") {
		return "GPS altitude coordinate detected"
	}
	if strings.Contains(lineLower, "xyz:") {
		return "Video GPS coordinates in xyz format detected"
	}
	if strings.Contains(lineLower, "coordinates") {
		return "Coordinate data detected"
	}
	if strings.Contains(lineLower, "latitude") || strings.Contains(lineLower, "longitude") {
		return "Latitude/longitude data detected"
	}

	return "GPS-related data detected"
}

// Helper methods for specific metadata checks

// isVersionNumber checks if a line contains only a version number (not sensitive)
func (v *Validator) isVersionNumber(line string) bool {
	// Check for version number patterns like "15.0000", "1.0", "2.1.3", etc.
	// These are typically software versions and not sensitive information
	lineLower := strings.ToLower(strings.TrimSpace(line))

	// Pattern for version numbers: digits, dots, and optional minor characters
	versionPattern := regexp.MustCompile(`^\d+(\.\d+)*$`)

	// If the line contains a colon, extract the value part
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			return versionPattern.MatchString(value)
		}
	}

	// Check if the entire line is just a version number
	return versionPattern.MatchString(lineLower)
}

// hasNonEmptyValue checks if a metadata field has non-empty content after the colon
func (v *Validator) hasNonEmptyValue(line string) bool {
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// containsLastModifiedBy checks for LastModifiedBy field with non-empty content
func (v *Validator) containsLastModifiedBy(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "lastmodifiedby") && !strings.Contains(lineLower, "last modified by") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	// For "last modified by" without colon, check if there's content after the field name
	if strings.Contains(lineLower, "last modified by") {
		// Extract content after "last modified by"
		idx := strings.Index(lineLower, "last modified by")
		if idx != -1 {
			remaining := strings.TrimSpace(line[idx+len("last modified by"):])
			return remaining != "" && remaining != `""` && remaining != "''"
		}
	}
	return false
}

// containsManager checks for Manager field with non-empty content
func (v *Validator) containsManager(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "manager:") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// containsComments checks for Comments field with non-empty content
func (v *Validator) containsComments(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "comments:") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// containsDescription checks for Description field with non-empty content
func (v *Validator) containsDescription(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "description:") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// containsKeywords checks for Keywords field with non-empty content
func (v *Validator) containsKeywords(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "keywords:") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// containsAuthorInfo checks for author/creator information with non-empty content
func (v *Validator) containsAuthorInfo(line string) bool {
	lineLower := strings.ToLower(line)
	if !strings.Contains(lineLower, "author:") && !strings.Contains(lineLower, "creator:") {
		return false
	}

	// Extract the value part and check if it's non-empty
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			// Only return true if there's actual content (not empty or just quotes)
			return value != "" && value != `""` && value != "''"
		}
	}
	return false
}

// checkVideoMetadata checks for video-specific metadata patterns
func (v *Validator) checkVideoMetadata(line string) *detector.Match {
	lineLower := strings.ToLower(line)

	// Video device information - check for non-empty content
	if (strings.Contains(lineLower, "camera_make:") || strings.Contains(lineLower, "camera_model:") ||
		strings.Contains(lineLower, "device_make:") || strings.Contains(lineLower, "recording_device:")) &&
		v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       line,
			Type:       "VIDEO_DEVICE_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]interface{}{
				"metadata_type":     "video_device_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Video creator information - check for non-empty content
	if (strings.Contains(lineLower, "recorded_by:") || strings.Contains(lineLower, "director:") ||
		strings.Contains(lineLower, "producer:") || strings.Contains(lineLower, "cinematographer:")) &&
		v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       line,
			Type:       "VIDEO_CREATOR_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]interface{}{
				"metadata_type":     "video_creator_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	return nil
}

// checkAudioMetadata checks for audio-specific metadata patterns
func (v *Validator) checkAudioMetadata(line string) *detector.Match {
	lineLower := strings.ToLower(line)

	// Audio artist identity - check for non-empty content
	if (strings.Contains(lineLower, "artist:") || strings.Contains(lineLower, "performer:") ||
		strings.Contains(lineLower, "composer:") || strings.Contains(lineLower, "conductor:")) &&
		v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       line,
			Type:       "AUDIO_ARTIST_IDENTITY",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]interface{}{
				"metadata_type":     "audio_artist_identity",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Audio contact information - check for non-empty content
	if (strings.Contains(lineLower, "management:") || strings.Contains(lineLower, "contact:") ||
		strings.Contains(lineLower, "booking:") || strings.Contains(line, "@")) &&
		v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       line,
			Type:       "AUDIO_CONTACT_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]interface{}{
				"metadata_type":     "audio_contact_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Audio location information - check for non-empty content
	if (strings.Contains(lineLower, "venue:") || strings.Contains(lineLower, "studio:") ||
		strings.Contains(lineLower, "recorded_at:") || strings.Contains(lineLower, "recording_location:")) &&
		v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       line,
			Type:       "AUDIO_LOCATION_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]interface{}{
				"metadata_type":     "audio_location_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	return nil
}

// checkOfficeMetadataFields checks for specific Office document metadata fields
func (v *Validator) checkOfficeMetadataFields(line string) *detector.Match {
	lineLower := strings.ToLower(strings.TrimSpace(line))

	// Company field detection
	if strings.HasPrefix(lineLower, "company:") {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.2 // Boost for company field
		if confidence > 1.0 {
			confidence = 1.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "COMPANY_INFO"),
			Type:       "COMPANY_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "company_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Application field detection
	if strings.HasPrefix(lineLower, "application:") {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.1 // Moderate boost for application field
		if confidence > 1.0 {
			confidence = 1.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "APPLICATION_INFO"),
			Type:       "APPLICATION_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "application_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Template field detection with enhanced risk analysis
	if strings.HasPrefix(lineLower, "template:") {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)

		// Enhanced template path risk analysis
		templateValue := v.extractSensitiveValue(line, "TEMPLATE_INFO")
		templateRisk := v.analyzeTemplatePathRisk(templateValue)

		// Apply risk-based confidence boost
		confidence += contextImpact + templateRisk.ConfidenceBoost
		if confidence > 1.0 {
			confidence = 1.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       templateValue,
			Type:       "TEMPLATE_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":         "template_info",
				"validation_checks":     checks,
				"context_impact":        contextImpact,
				"source":                "preprocessed_content",
				"template_risk_level":   templateRisk.RiskLevel,
				"template_risk_factors": templateRisk.RiskFactors,
			},
		}
	}

	// Custom properties detection (high-risk organizational metadata)
	if strings.HasPrefix(lineLower, "custom_") {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)

		// Enhanced custom property risk analysis
		customPropRisk := v.analyzeCustomPropertyRisk(line)

		// Apply risk-based confidence boost
		confidence += contextImpact + customPropRisk.ConfidenceBoost
		if confidence > 1.0 {
			confidence = 1.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "CUSTOM_PROPERTY"),
			Type:       "CUSTOM_PROPERTY",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":            "custom_property",
				"validation_checks":        checks,
				"context_impact":           contextImpact,
				"source":                   "preprocessed_content",
				"custom_prop_risk_level":   customPropRisk.RiskLevel,
				"custom_prop_risk_factors": customPropRisk.RiskFactors,
				"custom_prop_name":         customPropRisk.PropertyName,
			},
		}
	}

	return nil
}

// checkHighPrioritySensitive checks for high priority sensitive fields
func (v *Validator) checkHighPrioritySensitive(line string) *detector.Match {
	lineLower := strings.ToLower(line)

	// Check for author/creator information (including image metadata fields)
	if (strings.Contains(lineLower, "author:") ||
		strings.Contains(lineLower, "creator:") ||
		strings.Contains(lineLower, "artist:") ||
		strings.Contains(lineLower, "iptc_byline:") ||
		strings.Contains(lineLower, "lastmodifiedby:") ||
		strings.Contains(lineLower, "last modified by:")) &&
		v.hasNonEmptyValue(line) {

		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.2 // Boost for author/creator fields
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		// Determine the match type based on the field
		matchType := "AUTHOR_INFO"
		if strings.Contains(lineLower, "artist:") || strings.Contains(lineLower, "iptc_byline:") {
			matchType = "IMAGE_AUTHOR"
		} else if strings.Contains(lineLower, "lastmodifiedby:") {
			matchType = "LAST_MODIFIED_BY"
		}

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, matchType),
			Type:       matchType,
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "author_creator_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
				"detection_reason":  v.getAuthorDetectionReason(line),
			},
		}
	}

	// Check for manager information
	if strings.Contains(lineLower, "manager:") && v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.25 // High boost for manager field
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "MANAGER_INFO"),
			Type:       "MANAGER_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "manager_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Check for comments (very high priority)
	if strings.Contains(lineLower, "comments:") && v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.3 // Very high boost for comments
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "DOCUMENT_COMMENTS"),
			Type:       "DOCUMENT_COMMENTS",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "document_comments",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	return nil
}

// checkMediumPrioritySensitive checks for medium priority sensitive fields
func (v *Validator) checkMediumPrioritySensitive(line string) *detector.Match {
	lineLower := strings.ToLower(line)

	// Check for company information
	if strings.Contains(lineLower, "company:") && v.hasNonEmptyValue(line) {
		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.15 // Boost for company field
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "COMPANY_INFO"),
			Type:       "COMPANY_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "company_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Check for software information that might contain user paths
	if (strings.Contains(lineLower, "software:") || strings.Contains(lineLower, "application:")) &&
		v.hasNonEmptyValue(line) {

		// Only flag if it contains potentially sensitive information
		if strings.Contains(line, "/Users/") || strings.Contains(line, "/home/") ||
			strings.Contains(line, "C:\\Users\\") || strings.Contains(line, "~") {

			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.2 // Boost for user path in software field
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact

			return &detector.Match{
				Text:       v.extractSensitiveValue(line, "SOFTWARE_USER_PATH"),
				Type:       "SOFTWARE_USER_PATH",
				Confidence: confidence * 100,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "software_user_path",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
				},
			}
		}
	}

	// Check for description field
	if strings.Contains(lineLower, "description:") && v.hasNonEmptyValue(line) {
		// Only flag descriptions that are substantial (more than just a few words)
		value := v.extractSensitiveValue(line, "DESCRIPTION")
		if len(strings.TrimSpace(value)) > 20 { // Only flag substantial descriptions
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.1 // Moderate boost for description
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact

			return &detector.Match{
				Text:       value,
				Type:       "DOCUMENT_DESCRIPTION",
				Confidence: confidence * 100,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "document_description",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
				},
			}
		}
	}

	return nil
}

// checkLowPrioritySensitive checks for low priority sensitive fields
func (v *Validator) checkLowPrioritySensitive(line string) *detector.Match {
	lineLower := strings.ToLower(line)

	// Check for device/camera information
	if (strings.Contains(lineLower, "make:") || strings.Contains(lineLower, "model:") ||
		strings.Contains(lineLower, "camera_make:") || strings.Contains(lineLower, "camera_model:")) &&
		v.hasNonEmptyValue(line) {

		confidence, checks := v.CalculateConfidence(line)
		contextInfo := detector.ContextInfo{FullLine: line}
		contextImpact := v.AnalyzeContext(line, contextInfo)
		confidence += contextImpact + 0.1 // Moderate boost for device info
		if confidence > 1.0 {
			confidence = 1.0
		} else if confidence < 0.0 {
			confidence = 0.0
		}
		contextInfo.ConfidenceImpact = contextImpact

		return &detector.Match{
			Text:       v.extractSensitiveValue(line, "DEVICE_INFO"),
			Type:       "DEVICE_INFO",
			Confidence: confidence * 100,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "device_info",
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			},
		}
	}

	// Check for keywords field (only if substantial)
	if strings.Contains(lineLower, "keywords:") && v.hasNonEmptyValue(line) {
		value := v.extractSensitiveValue(line, "KEYWORDS")
		if len(strings.TrimSpace(value)) > 10 { // Only flag substantial keywords
			confidence, checks := v.CalculateConfidence(line)
			contextInfo := detector.ContextInfo{FullLine: line}
			contextImpact := v.AnalyzeContext(line, contextInfo)
			confidence += contextImpact + 0.05 // Small boost for keywords
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}
			contextInfo.ConfidenceImpact = contextImpact

			return &detector.Match{
				Text:       value,
				Type:       "DOCUMENT_KEYWORDS",
				Confidence: confidence * 100,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "document_keywords",
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
				},
			}
		}
	}

	return nil
}

// extractSensitiveValue extracts just the sensitive value from a metadata field
func (v *Validator) extractSensitiveValue(line, matchType string) string {
	// Handle different field formats: "Field: Value" or "Field = Value"
	var value string

	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
	} else if strings.Contains(line, "=") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		}
	} else {
		// If no separator found, return the original line
		return strings.TrimSpace(line)
	}

	// Clean up the value by removing quotes if present
	value = strings.Trim(value, `"'`)

	// If the value is empty after cleaning, return the original line
	if value == "" {
		return strings.TrimSpace(line)
	}

	return value
}

// isGPSCoordinateComponent checks if a field name represents a GPS coordinate component
func (v *Validator) isGPSCoordinateComponent(fieldName string) bool {
	coordinateFields := []string{
		"gpslatitude", "gpslongitude", "gpslatituderef", "gpslongituderef",
		"latitude", "longitude", "gps_coordinates", "coordinates",
	}

	for _, field := range coordinateFields {
		if strings.Contains(fieldName, field) {
			return true
		}
	}
	return false
}

// combineGPSCoordinates combines latitude and longitude into coordinate pairs
func (v *Validator) combineGPSCoordinates(gpsCoordinates map[string]string, gpsLineNumbers map[string]int, originalPath, currentEmbeddedMedia string) []detector.Match {
	var matches []detector.Match

	// Determine filename based on context
	filename := originalPath
	if currentEmbeddedMedia != "" {
		filename = currentEmbeddedMedia
	}

	// Look for latitude/longitude pairs
	var latitude, longitude, latRef, longRef string
	var latLine, longLine int

	// Check for already consolidated GPS coordinates first
	for field, value := range gpsCoordinates {
		fieldLower := strings.ToLower(field)
		if strings.Contains(fieldLower, "gps_coordinates") || strings.Contains(fieldLower, "coordinates") {
			// This is already a consolidated GPS coordinate entry
			confidence, checks := v.CalculateConfidence(fmt.Sprintf("%s: %s", field, value))
			contextInfo := detector.ContextInfo{FullLine: fmt.Sprintf("%s: %s", field, value)}
			contextImpact := v.AnalyzeContext(fmt.Sprintf("%s: %s", field, value), contextInfo)
			confidence += contextImpact

			if confidence > 1.0 {
				confidence = 1.0
			}

			match := detector.Match{
				Text:       value,
				LineNumber: gpsLineNumbers[field],
				Filename:   filename,
				Type:       "GPS",
				Confidence: confidence * 100, // Fix: multiply by 100 to match other confidence calculations
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata: map[string]any{
					"metadata_type":     "gps_coordinates",
					"field_name":        field,
					"validation_checks": checks,
					"context_impact":    contextImpact,
					"source":            "preprocessed_content",
				},
			}
			matches = append(matches, match)
			return matches // Return early since we found consolidated coordinates
		}
	}

	// Extract coordinate values for individual components (fallback)
	for field, value := range gpsCoordinates {
		switch {
		case strings.Contains(field, "gpslatitude") && !strings.Contains(field, "ref"):
			latitude = value
			latLine = gpsLineNumbers[field]
		case strings.Contains(field, "gpslongitude") && !strings.Contains(field, "ref"):
			longitude = value
			longLine = gpsLineNumbers[field]
		case strings.Contains(field, "gpslatituderef"):
			latRef = value
		case strings.Contains(field, "gpslongituderef"):
			longRef = value
		case strings.Contains(field, "latitude") && !strings.Contains(field, "gps"):
			latitude = value
			latLine = gpsLineNumbers[field]
		case strings.Contains(field, "longitude") && !strings.Contains(field, "gps"):
			longitude = value
			longLine = gpsLineNumbers[field]
		}
	}

	// If we have both latitude and longitude, combine them
	if latitude != "" && longitude != "" {
		// Clean up the values (remove quotes)
		latitude = strings.Trim(latitude, `"`)
		longitude = strings.Trim(longitude, `"`)
		latRef = strings.Trim(latRef, `"`)
		longRef = strings.Trim(longRef, `"`)

		// Format the combined coordinate
		var combinedText string
		if latRef != "" && longRef != "" {
			combinedText = fmt.Sprintf("%s°%s, %s°%s", latitude, latRef, longitude, longRef)
		} else {
			combinedText = fmt.Sprintf("%s, %s", latitude, longitude)
		}

		// Use the earlier line number
		lineNumber := latLine
		if longLine < latLine && longLine > 0 {
			lineNumber = longLine
		}

		// Calculate confidence for combined coordinates
		confidence := 1.0 // High confidence for coordinate pairs
		checks := map[string]bool{
			"contains_coordinate_pair": true,
			"contains_gps_coords":      true,
		}

		contextInfo := detector.ContextInfo{
			FullLine: combinedText,
		}

		matches = append(matches, detector.Match{
			Text:       combinedText,
			LineNumber: lineNumber,
			Type:       "GPS",
			Confidence: confidence * 100,
			Filename:   filename,
			Validator:  "metadata",
			Context:    contextInfo,
			Metadata: map[string]any{
				"metadata_type":     "gps_coordinates",
				"validation_checks": checks,
				"source":            "preprocessed_content",
				"original_file":     originalPath,
				"detection_reason":  "Combined GPS coordinate pair",
				"coordinate_type":   "lat_long_pair",
			},
		})
	}

	return matches
}

// isMeaningfulGPSValue checks if a GPS field contains meaningful location data
func (v *Validator) isMeaningfulGPSValue(fieldName, fieldValue string) bool {
	fieldNameLower := strings.ToLower(fieldName)

	// Filter out GPS reference fields that are just numeric codes
	referenceFields := []string{
		"gpsaltituderef",     // 0 = Above Sea Level, 1 = Below Sea Level
		"gpsspeedref",        // Speed reference (km/h, mph, etc.)
		"gpsimgdirectionref", // Direction reference (True North, Magnetic North)
		"gpsdestbearingref",  // Bearing reference
		"gpslatituderef",     // N/S reference (but we handle this in coordinate combination)
		"gpslongituderef",    // E/W reference (but we handle this in coordinate combination)
	}

	for _, refField := range referenceFields {
		if strings.Contains(fieldNameLower, refField) {
			// Skip reference fields that are just numeric codes
			if fieldValue == "0" || fieldValue == "1" || fieldValue == "2" {
				return false
			}
		}
	}

	// Filter out very small speed values that aren't meaningful
	if strings.Contains(fieldNameLower, "gpsspeed") && !strings.Contains(fieldNameLower, "ref") {
		// Skip very low speed values (likely stationary)
		if fieldValue == "0" || fieldValue == "0.0" {
			return false
		}
	}

	// Filter out standalone zeros or very short numeric values that aren't coordinates
	if fieldValue == "0" || fieldValue == "1" || fieldValue == "2" {
		// Allow these values only for meaningful fields like altitude
		meaningfulNumericFields := []string{
			"gpsaltitude",
			"gpslatitude",
			"gpslongitude",
		}

		isMeaningfulField := false
		for _, meaningfulField := range meaningfulNumericFields {
			if strings.Contains(fieldNameLower, meaningfulField) {
				isMeaningfulField = true
				break
			}
		}

		if !isMeaningfulField {
			return false
		}
	}

	return true
}

// TemplatePathRisk represents the risk analysis of a template path
type TemplatePathRisk struct {
	RiskLevel       string
	ConfidenceBoost float64
	RiskFactors     []string
}

// CustomPropertyRisk represents the risk analysis of a custom property
type CustomPropertyRisk struct {
	RiskLevel       string
	ConfidenceBoost float64
	RiskFactors     []string
	PropertyName    string
}

// analyzeTemplatePathRisk analyzes template paths for security risks
func (v *Validator) analyzeTemplatePathRisk(templatePath string) TemplatePathRisk {
	risk := TemplatePathRisk{
		RiskLevel:       "LOW",
		ConfidenceBoost: 0.1,
		RiskFactors:     []string{},
	}

	templateLower := strings.ToLower(templatePath)

	// Network path exposure (UNC paths)
	if strings.HasPrefix(templatePath, "\\\\") {
		risk.RiskFactors = append(risk.RiskFactors, "Network path exposes infrastructure")
		risk.ConfidenceBoost += 0.3
		risk.RiskLevel = "HIGH"
	}

	// User directory exposure
	if strings.Contains(templatePath, "\\Users\\") || strings.Contains(templatePath, "/Users/") ||
		strings.Contains(templatePath, "/home/") {
		risk.RiskFactors = append(risk.RiskFactors, "User directory path exposes username")
		risk.ConfidenceBoost += 0.3
		risk.RiskLevel = "HIGH"
	}

	// Classification markers in path
	classificationMarkers := []string{"confidential", "secret", "classified", "restricted", "internal"}
	for _, marker := range classificationMarkers {
		if strings.Contains(templateLower, marker) {
			risk.RiskFactors = append(risk.RiskFactors, "Path contains classification marker: "+marker)
			risk.ConfidenceBoost += 0.4
			risk.RiskLevel = "CRITICAL"
		}
	}

	// Department/organizational structure exposure
	deptMarkers := []string{"legal", "hr", "finance", "engineering", "sales", "marketing"}
	for _, dept := range deptMarkers {
		if strings.Contains(templateLower, dept) {
			risk.RiskFactors = append(risk.RiskFactors, "Path exposes organizational structure: "+dept)
			risk.ConfidenceBoost += 0.2
			if risk.RiskLevel == "LOW" {
				risk.RiskLevel = "MEDIUM"
			}
		}
	}

	// Project codenames (Project-, Operation-)
	if strings.Contains(templateLower, "project-") || strings.Contains(templateLower, "operation") {
		risk.RiskFactors = append(risk.RiskFactors, "Path contains project codename")
		risk.ConfidenceBoost += 0.3
		risk.RiskLevel = "HIGH"
	}

	// Server/domain names
	if strings.Contains(templatePath, "\\\\") {
		// Extract server name from UNC path
		parts := strings.Split(templatePath, "\\")
		if len(parts) > 2 && parts[2] != "" {
			risk.RiskFactors = append(risk.RiskFactors, "Exposes server name: "+parts[2])
			risk.ConfidenceBoost += 0.2
		}
	}

	return risk
}

// analyzeCustomPropertyRisk analyzes custom properties for security risks
func (v *Validator) analyzeCustomPropertyRisk(line string) CustomPropertyRisk {
	risk := CustomPropertyRisk{
		RiskLevel:       "LOW",
		ConfidenceBoost: 0.2, // Base boost for custom properties
		RiskFactors:     []string{},
	}

	// Extract property name and value
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			propName := strings.TrimSpace(strings.TrimPrefix(parts[0], "Custom_"))
			propValue := strings.TrimSpace(parts[1])

			risk.PropertyName = propName
			propNameLower := strings.ToLower(propName)
			propValueLower := strings.ToLower(propValue)

			// Classification properties (CRITICAL)
			if strings.Contains(propNameLower, "classification") ||
				strings.Contains(propNameLower, "clearance") ||
				strings.Contains(propValueLower, "secret") ||
				strings.Contains(propValueLower, "confidential") ||
				strings.Contains(propValueLower, "restricted") {
				risk.RiskFactors = append(risk.RiskFactors, "Contains security classification")
				risk.ConfidenceBoost += 0.5
				risk.RiskLevel = "CRITICAL"
			}

			// Project information (HIGH)
			if strings.Contains(propNameLower, "project") ||
				strings.Contains(propValueLower, "operation") ||
				strings.Contains(propValueLower, "project-") {
				risk.RiskFactors = append(risk.RiskFactors, "Contains project information")
				risk.ConfidenceBoost += 0.3
				if risk.RiskLevel != "CRITICAL" {
					risk.RiskLevel = "HIGH"
				}
			}

			// PII and employee information (HIGH)
			piiFields := []string{"employee", "ssn", "social", "id", "badge", "clearance"}
			for _, field := range piiFields {
				if strings.Contains(propNameLower, field) {
					risk.RiskFactors = append(risk.RiskFactors, "Contains PII: "+field)
					risk.ConfidenceBoost += 0.4
					if risk.RiskLevel != "CRITICAL" {
						risk.RiskLevel = "HIGH"
					}
				}
			}

			// Financial information (HIGH)
			if strings.Contains(propNameLower, "budget") ||
				strings.Contains(propNameLower, "cost") ||
				strings.Contains(propNameLower, "salary") ||
				strings.Contains(propValueLower, "$") {
				risk.RiskFactors = append(risk.RiskFactors, "Contains financial information")
				risk.ConfidenceBoost += 0.3
				if risk.RiskLevel != "CRITICAL" {
					risk.RiskLevel = "HIGH"
				}
			}

			// Organizational structure (MEDIUM)
			orgFields := []string{"department", "division", "team", "manager", "supervisor"}
			for _, field := range orgFields {
				if strings.Contains(propNameLower, field) {
					risk.RiskFactors = append(risk.RiskFactors, "Contains organizational info: "+field)
					risk.ConfidenceBoost += 0.2
					if risk.RiskLevel == "LOW" {
						risk.RiskLevel = "MEDIUM"
					}
				}
			}

			// Contact information (MEDIUM)
			if strings.Contains(propNameLower, "contact") ||
				strings.Contains(propNameLower, "phone") ||
				strings.Contains(propNameLower, "email") {
				risk.RiskFactors = append(risk.RiskFactors, "Contains contact information")
				risk.ConfidenceBoost += 0.2
				if risk.RiskLevel == "LOW" {
					risk.RiskLevel = "MEDIUM"
				}
			}
		}
	}

	return risk
}
