// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// Import MetadataContent from router package to avoid duplication
// This ensures compatibility with the dual-path bridge system

// Pre-compiled regex patterns. Previously these were compiled inside the
// per-call helpers below; for a metadata-heavy scan that runs into the
// hundreds-of-thousands of allocations on the hot path.
var (
	// `phoneBasic` is the three-three-four digit phone pattern. A separator
	// (- or .) between the groups is now REQUIRED: the previous optional
	// separator (`[-.]?`) matched any bare 10-digit run (timestamps, asset/ID
	// numbers like "ID: 1234567890"), producing phantom phone confidence. Bare
	// 10-digit numbers are too ambiguous to treat as phones in metadata; the
	// space-separated and parenthesized forms cover the other real layouts.
	phoneBasic         = regexp.MustCompile(`\b\d{3}[-.]\d{3}[-.]\d{4}\b`)
	phoneParenAreaCode = regexp.MustCompile(`\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b`)
	phoneInternational = regexp.MustCompile(`\b\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b`)
	phoneSpaceSep      = regexp.MustCompile(`\b\d{3}\s\d{3}\s\d{4}\b`)

	enhancedPhonePatterns = []*regexp.Regexp{
		phoneBasic,
		phoneParenAreaCode,
		phoneInternational,
		phoneSpaceSep,
	}

	emailExtractPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	gpsCoordPattern     = regexp.MustCompile(`[+-]?\d+\.\d+`)
	// gpsCoordRefPattern matches a decimal-degree coordinate with an adjacent
	// N/S/E/W hemisphere reference (optionally a degree symbol), e.g. "40.7128 N"
	// or "74.0060° W". The directional letter must sit next to the number — this
	// replaces the old "decimal anywhere AND the letters n/s/e/w appear anywhere
	// on the line" test, which matched almost any English text containing a
	// version number (e.g. "Software: Adobe Photoshop 21.0").
	gpsCoordRefPattern   = regexp.MustCompile(`(?i)[+-]?\d{1,3}\.\d+\s*°?\s*[NSEW]\b`)
	versionNumberPattern = regexp.MustCompile(`^\d+(\.\d+)*$`)
	// leadingDecimalPattern extracts a leading signed decimal from a coordinate
	// value that may carry a trailing degree symbol / hemisphere ref.
	leadingDecimalPattern = regexp.MustCompile(`^[+-]?\d+(?:\.\d+)?`)
)

// parseCoordinate extracts the leading signed decimal from a coordinate string
// (e.g. "40.7128", "40.7128° N") and returns it with ok=true. ok is false when
// no leading numeric value is present (e.g. a DMS string or placeholder text),
// in which case the caller treats the value as unparseable rather than invalid.
func parseCoordinate(s string) (float64, bool) {
	m := leadingDecimalPattern.FindString(strings.TrimSpace(s))
	if m == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(m, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

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
	observer observability.Observer

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
		if v.observer.Debug() != nil {
			v.observer.Debug().LogDetail("metadata_validator",
				fmt.Sprintf("Processing content from %s (type: %s), content length: %d",
					content.SourceFile, content.PreprocessorType, len(content.Content)))
			// Do NOT log the content itself — it is raw scanned data that may
			// contain the very secrets/PII this tool exists to protect (BSC4).
			// The previous "Content preview: <first 200 bytes>" leaked payload to
			// stderr/CI logs on plain --debug. Log only the length. (Glasswing
			// finding; same class as the socialmedia/intellectualproperty fixes.)
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
			// custom_ covers docProps/custom.xml properties. The extractor
			// already surfaces these (they appear in --preprocess-only output),
			// but without this entry validateWithPreprocessorRules filtered them
			// out and they produced ZERO findings — a Classification property
			// reading "SECRET - <codename>" was extracted, printed, and never
			// reported. analyzeCustomPropertyRisk existed for exactly this and
			// was unreachable for real documents.
			"custom_",
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
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
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
		confidence += enhancedCopyrightBoost
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
		if phoneBasic.MatchString(match) {
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

	// Check for keywords that might indicate non-PII or test data.
	//
	// This is scored against the field's VALUE, never against its NAME. The
	// claim this rule makes is "the content here is fake", and only the content
	// can be evidence of that. A field name is chosen by the file format, so it
	// says what KIND of thing the field holds and nothing at all about whether
	// the value is real.
	//
	// Scoring the whole line made several field names penalize their own
	// values, because the names collide with this very list:
	//
	//	Template: \\corp-fs01\confidential\...   ctx -0.05, net 75
	//	Tmpl:     \\corp-fs01\confidential\...   ctx +0.10, net 90
	//
	// Same value, and only the label differs — a UNC path disclosing an internal
	// fileserver lost 15 points for being stored under a field called
	// "Template". Measured over 120 real Office documents this fired on EVERY
	// one of the 80 TEMPLATE_INFO findings, and also on image metadata's
	// BitsPerSample ("sample") and on Custom_db_template_reference.
	//
	// The suppression itself is correct and is kept: a value that really is test
	// data ("Author: test user") still loses 0.15, and so does a template whose
	// VALUE names a stock template ("Template: Normal.dotm" — "normal" is not on
	// the list, but "Template: sample.dotx" is).
	// Split the ALREADY-lowercased line rather than lowercasing the value again:
	// this runs per line on every metadata field, and a second whole-line
	// strings.ToLower allocation measured 1.24-1.38x on this function.
	// strings.ToLower cannot move the ASCII ":"/"=" separator that
	// splitMetadataField looks for, so splitting either string finds the same
	// boundary.
	//
	// When there is no separator, splitMetadataField returns the whole line as
	// the value — which is exactly what a separator-less line's value is — so the
	// previous behaviour is preserved with no extra branch.
	_, valueLower, _ := splitMetadataField(contextLower)

	nonPiiIndicators := []string{
		"test", "example", "sample", "demo", "placeholder", "dummy",
		"template", "default", "anonymous", "unknown",
	}

	for _, indicator := range nonPiiIndicators {
		if strings.Contains(valueLower, indicator) {
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
	// Track GPS coordinate components for combining
	gpsCoordinates := make(map[string]string) // field -> value
	gpsLineNumbers := make(map[string]int)    // field -> line number

	// Every match this function emits is attributed to originalPath, the path the
	// CALLER supplied.
	//
	// This used to be conditional. A line containing "--- Embedded Media" switched
	// attribution for every subsequent line to filepath.Base(originalPath) + " -> " +
	// filepath.Base(text between the first "(" and the first ")"), so the reported
	// source of a finding was read out of the content being scanned. A document
	// author writes that content, so the author chose the filename: typing
	// "--- Embedded Media 1 (/etc/passwd) ---" in a Word paragraph produced
	// "report.docx -> passwd", and "(evil_test.go)" produced a name that
	// internal/explain's looksLikeTestPath reads as fixture data and downgrades the
	// verdict toward "likely test data" — advice to ignore a real finding.
	// filepath.Base did neutralize traversal in the DISPLAYED string
	// ("../../secrets.txt" showed as "secrets.txt", not as an escaping path), which
	// is why this never looked like a path-handling bug; what it did not do is stop
	// the value from being attacker-chosen in the first place.
	//
	// Filename is also an input to the suppression identity: generateFindingHash
	// folds in filepath.Base(match.Filename), so a forged name moved a finding's
	// hash — either off an existing rule (a genuinely suppressed finding reappears)
	// or onto one (a real finding is silently dropped by a rule written for
	// something else).
	//
	// The provenance is real structure, not text: the preprocessor that actually
	// read the archive member records it in ContentSection.SourceFile, the content
	// router copies that into MetadataContent.SourceFile, and it arrives here as the
	// originalPath argument. So the correct value is already in hand on the routed
	// path, and re-deriving it from the text could only ever produce a WORSE answer
	// than the one the caller passed in.
	filename := originalPath

	for lineNumber, line := range lines {
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

		// The priority helpers below cover the same fields (author, manager,
		// comments, description, keywords) as the legacy inline blocks further
		// down. Track whether any helper emitted for this line so we can skip the
		// redundant legacy blocks and avoid emitting the SAME field twice (M31).
		priorityFieldMatched := false

		// Check for high priority sensitive fields
		if highPriorityMatch := v.checkHighPrioritySensitive(line); highPriorityMatch != nil {
			highPriorityMatch.LineNumber = lineNumber + 1
			highPriorityMatch.Filename = filename
			matches = append(matches, *highPriorityMatch)
			priorityFieldMatched = true
		}

		// Check for medium priority sensitive fields
		if mediumPriorityMatch := v.checkMediumPrioritySensitive(line); mediumPriorityMatch != nil {
			mediumPriorityMatch.LineNumber = lineNumber + 1
			mediumPriorityMatch.Filename = filename
			matches = append(matches, *mediumPriorityMatch)
			priorityFieldMatched = true
		}

		// Check for low priority sensitive fields
		if lowPriorityMatch := v.checkLowPrioritySensitive(line); lowPriorityMatch != nil {
			lowPriorityMatch.LineNumber = lineNumber + 1
			lowPriorityMatch.Filename = filename
			matches = append(matches, *lowPriorityMatch)
			priorityFieldMatched = true
		}

		// Legacy inline field blocks (LastModifiedBy/Manager/Comments/Description/
		// Keywords/AuthorInfo) duplicate the priority helpers above. Skip them when
		// a helper already emitted for this line so the same field is not reported
		// twice; otherwise fall through so any field the helpers don't cover is
		// still detected.
		if !priorityFieldMatched {

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
		} // end legacy inline field blocks (skipped when a priority helper matched)

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
	combinedMatches := v.combineGPSCoordinates(gpsCoordinates, gpsLineNumbers, originalPath)
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
	return emailExtractPattern.FindString(line)
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
			// Determine match type based on content and preprocessor type
			matchType := v.determineMatchType(line, content.PreprocessorType)

			// Extract just the sensitive value from the metadata field
			sensitiveValue := v.extractSensitiveValue(line, matchType)

			// Custom properties are mostly machine bookkeeping. Skip the values
			// that cannot disclose anything, so enabling this field does not
			// bury the ones that can.
			//
			// This is deliberately BEFORE the scoring calls below: profiling
			// showed CalculateConfidence dominates this loop (33% of samples on
			// a metadata-dense package), and running it on a value that is about
			// to be discarded is pure waste. Skipping first keeps the cost of
			// enabling custom properties proportional to the findings actually
			// reported.
			if matchType == "CUSTOM_PROPERTY" && isValuelessProperty(sensitiveValue) {
				continue
			}

			confidence, checks := v.CalculateConfidence(line)

			// A custom property must not be charged for its classification word TWICE.
			//
			// CalculateConfidence is the generic metadata scorer, and its
			// containsEnhancedCopyright check matches a bare substring — "confidential",
			// "proprietary", "trade secret", "(c)" — anywhere in the line, worth
			// +enhancedCopyrightBoost. analyzeCustomPropertyRisk, reached through
			// applyValueShapeRisk below, then scores the SAME word again in its own
			// classification branch. One occurrence, two scorers.
			//
			// Measured holding the property NAME constant and varying only the value:
			//
			//	Notice: Quarterly summary                           ->  60
			//	Notice: Confidential                                -> 100
			//	Notice: Confidential - Project Nightjar acquisition -> 100
			//
			// The bare marking saturates the score, so a document that merely CARRIES a
			// sensitivity label ranks identically to one carrying the label AND naming a
			// live acquisition project. That ranking failure is the defect, not the number:
			// a Purview label is standard enterprise plumbing on a large fraction of real
			// documents, so it crowds the HIGH band operators triage first. Measured on a
			// 304-file corpus, CUSTOM_PROPERTY was the largest HIGH population of any
			// metadata type.
			//
			// The classification signal belongs to analyzeCustomPropertyRisk, which tiers
			// it deliberately (CRITICAL/HIGH/MEDIUM by name and value). Withdrawing the
			// generic copyright contribution for this ONE type leaves exactly one scorer
			// responsible for it. Other metadata types are untouched: for an image's
			// Copyright field the IP heuristic is the right signal and no second scorer
			// doubles it. See #307.
			if matchType == "CUSTOM_PROPERTY" && checks["contains_enhanced_copyright"] {
				confidence -= enhancedCopyrightBoost
				delete(checks, "contains_enhanced_copyright")
			}

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

			// Apply the value-shape risk analysis this path used to skip.
			//
			// This function is the LIVE path for every registered preprocessor
			// type (office/image/audio/video/document _metadata), while the
			// per-field blocks in checkOfficeMetadataFields are only reached as
			// a fallback for UNREGISTERED types. The per-field blocks call
			// analyzeTemplatePathRisk / analyzeCustomPropertyRisk to score the
			// field's VALUE; this one did not, so the analyzers were effectively
			// dead for real documents. Measured: a template pointing at
			// \\host\confidential\... scored 25 here versus 100 there, ranking a
			// disclosed internal fileserver path BELOW a mundane company name.
			//
			// Additive only, and never applied to a type the risk function does
			// not understand — see applyValueShapeRisk.
			riskBoost, riskMeta := v.applyValueShapeRisk(matchType, line, sensitiveValue)
			confidence += riskBoost
			if confidence > 1.0 {
				confidence = 1.0
			} else if confidence < 0.0 {
				confidence = 0.0
			}

			matchMetadata := map[string]interface{}{
				"metadata_type":     matchType,
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
				"original_file":     content.SourceFile,
				"preprocessor_type": content.PreprocessorType,
				"preprocessor_name": content.PreprocessorName,
				"full_field":        line, // Keep the original field for reference
			}
			for k, val := range riskMeta {
				matchMetadata[k] = val
			}

			matches = append(matches, detector.Match{
				Text:       sensitiveValue,
				LineNumber: lineNumber + 1,
				Type:       matchType,
				Confidence: confidence * 100, // Convert to percentage
				Filename:   content.SourceFile,
				Validator:  "metadata",
				Context:    contextInfo,
				Metadata:   matchMetadata,
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
//
// The type is decided by the field's NAME, not by its value. What KIND of thing a
// metadata field holds is a property of the field, and the value is free text
// that routinely contains other fields' names: a company genuinely called
// "Manager Tools LLC" or "Author Solutions Inc" used to be reported as
// MANAGER_INFO / AUTHOR_INFO because the type was picked by substring-matching
// the whole line. That wrong type reaches the report, the redaction path, and the
// suppression hash, and it also routed the finding to the wrong confidence boost.
//
// The one branch that deliberately reads the VALUE is the email check, because
// "contains an @-address" is a genuine value-shape signal and no field is named
// "@". It stays below the name branches so a recognized field keeps its own type,
// which is why "Author: john.doe@example.com" is AUTHOR_INFO and not EMAIL.
func (v *Validator) determineMatchType(line, preprocessorType string) string {
	name, value, ok := splitMetadataField(line)
	if !ok {
		// No separator, so there is no name/value split to make and the line is
		// all we have. Preserves the previous behaviour for such input.
		name, value = line, line
	}
	nameLower := strings.ToLower(name)

	// lineLower is retained as an alias for nameLower so that a branch added to
	// this function on another branch — which would have been written against
	// the old whole-line variable — still compiles and still behaves correctly
	// after a merge.
	//
	// This is not defensive padding. A field-name test written as
	// strings.HasPrefix(lineLower, "custom_") and a field-name test written as
	// strings.HasPrefix(nameLower, "custom_") are the same test, because the
	// name is a prefix of the line. Git merges such a hunk with zero textual
	// conflicts and the result then fails to COMPILE — measured on the union of
	// this change with the custom-property work, which merged clean and died on
	// "undefined: lineLower". Keeping the identifier bound makes the merge
	// correct instead of merely quiet.
	lineLower := nameLower

	// Custom document properties, checked FIRST because the field name is
	// author-chosen and can contain any of the substrings the checks below look
	// for: "Custom_DeviceOwner" would otherwise be typed DEVICE_INFO and
	// "Custom_ProjectManager" MANAGER_INFO, and neither would reach the
	// custom-property risk analysis. The prefix is what the extractor emits.
	if strings.HasPrefix(lineLower, "custom_") {
		return "CUSTOM_PROPERTY"
	}

	// Custom document properties, checked FIRST because the field name is
	// author-chosen and can contain any of the substrings the checks below look
	// for: "Custom_DeviceOwner" would otherwise be typed DEVICE_INFO and
	// "Custom_ProjectManager" MANAGER_INFO, and neither would reach the
	// custom-property risk analysis. The prefix is what the extractor emits.
	if strings.HasPrefix(lineLower, "custom_") {
		return "CUSTOM_PROPERTY"
	}

	// GPS-related patterns
	if strings.Contains(nameLower, "gps") || strings.Contains(nameLower, "latitude") || strings.Contains(nameLower, "longitude") {
		return "GPS"
	}

	// Device information patterns
	if strings.Contains(nameLower, "camera") || strings.Contains(nameLower, "device") || strings.Contains(nameLower, "serial") {
		return "DEVICE_INFO"
	}

	// Author/creator patterns
	if strings.Contains(nameLower, "author") || strings.Contains(nameLower, "creator") || strings.Contains(nameLower, "artist") {
		return "AUTHOR_INFO"
	}

	// Contact information patterns. Value-shaped by design — see the doc comment.
	if strings.Contains(value, "@") {
		return "EMAIL"
	}

	// Comments and descriptions
	if strings.Contains(nameLower, "comment") {
		return "DOCUMENT_COMMENTS"
	}
	if strings.Contains(nameLower, "description") {
		return "DOCUMENT_DESCRIPTION"
	}

	// Manager information
	if strings.Contains(nameLower, "manager") {
		return "MANAGER_INFO"
	}

	// Last modified by
	if strings.Contains(nameLower, "lastmodifiedby") {
		return "LAST_MODIFIED_BY"
	}

	// Office metadata specific fields. These used to carry a trailing ":" to
	// approximate "the line STARTS with this field" while matching the whole
	// line; matching the name makes that explicit and the colon is now gone.
	if strings.Contains(nameLower, "company") {
		return "COMPANY_INFO"
	}
	if strings.Contains(nameLower, "application") {
		return "APPLICATION_INFO"
	}
	if strings.Contains(nameLower, "template") {
		return "TEMPLATE_INFO"
	}

	// Preprocessor-specific types with enhanced detection.
	//
	// determineImageMetadataType still receives the whole line: unlike the
	// branches above it legitimately classifies by value as well as by name
	// ("Software: Adobe Photoshop" is IMAGE_SOFTWARE because of its value), so
	// narrowing it is a separate question from the name-versus-value bug.
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
//
// The boost table is keyed by FIELD TYPE ("manager", "comments", "author",
// "company", "gps", ...): it means "a value stored in this KIND of field is worth
// more". The keys therefore describe the field's NAME, not its contents.
//
// It matched match.Text, the extracted VALUE. Every key is an ordinary English
// word, so a value that merely contained one collected that field's boost, and —
// via determineMatchType, which had the same bug — that field's TYPE as well:
//
//	Company: Manager Tools LLC     MANAGER_INFO       95   (manager_boost 40)
//	Company: Author Solutions Inc  AUTHOR_INFO        85   (author_boost  30)
//	Subject: comments on Q3        DOCUMENT_COMMENTS 100   (comments_boost 50)
//	Company: Acme Corp             COMPANY_INFO       55   (control, no boost)
//
// Real organizations are named "Manager Tools LLC" and "Author Solutions", so
// this is ordinary input, not anything crafted. Measured over 120 real Office
// documents, it promoted a Nasdaq classification footer to AUTHOR_INFO at 100 on
// the strength of the word "authorized" inside its value.
//
// The fix is to stop crediting a field name found in a value — NOT to re-point
// the table at the field name. Those are different changes, and only the first is
// a bug fix:
//
//   - Because a value almost never repeats its own field's name, this table has
//     been dormant for its intended purpose since the initial commit. Pointing it
//     at the name wakes ~+40 on every author/company/application field at once.
//   - CalculateConfidence ALREADY scores these same field names, from the same
//     line, a few calls earlier (author: +0.20, company: +0.15, manager: +0.25,
//     comments: +0.30). Adding the table on top double-counts one signal —
//     precisely the "field boosts double-count → most TPs HIGH" note in
//     docs/proposals/CONFIDENCE_CONTRACT.md.
//   - Measured: waking it moves the corpus from 8 HIGH to 143 HIGH, and what
//     arrives in HIGH is boilerplate — "Microsoft Office User", "python-docx",
//     "Microsoft Office Word". HIGH is the band that fails a commit by default
//     (precommit.ExitOnFindings = "high"), so that is a rejected regression.
//
// Restricting the match to the value's own field name keeps the table exactly as
// dormant as it has always been for mundane fields, while removing the
// misattribution. A boost is still possible, but now only when the field name and
// the boost key genuinely agree.
//
// full_field holds the original "Name: value" line. It is absent only for the
// consolidated-GPS matches, which are assembled from parts rather than read from
// one line and so have no field name; those keep their previous behaviour.
func (v *Validator) applyPreprocessorConfidenceBoosts(match *detector.Match, preprocessorType string, boosts map[string]float64) {
	lineLower := strings.ToLower(match.Text)

	// The field this value actually came from. Empty when there is no field name
	// to check against (consolidated GPS), which disables the guard below.
	fieldNameLower := ""
	if fullField, ok := match.Metadata["full_field"].(string); ok {
		if name, _, split := splitMetadataField(fullField); split {
			fieldNameLower = strings.ToLower(name)
		}
	}

	// Apply confidence boosts based on field types
	for fieldType, boost := range boosts {
		// A field type found in the VALUE is not evidence about the value. Credit
		// it only when the value's own field name carries it too.
		if fieldNameLower != "" && !strings.Contains(fieldNameLower, fieldType) {
			continue
		}
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
// enhancedCopyrightBoost is the weight containsEnhancedCopyright contributes.
//
// Named so the CUSTOM_PROPERTY discount below subtracts exactly what was added. Two
// copies of 0.4 would drift, and a discount that no longer matches the boost is worse
// than no discount: it would silently re-inflate or over-penalise.
const enhancedCopyrightBoost = 0.4

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
	for _, pattern := range enhancedPhonePatterns {
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

	// Check for coordinate patterns. A real coordinate is a decimal value with an
	// adjacent N/S/E/W hemisphere reference. The previous test OR-ed single
	// letters across the whole line, so any field carrying a decimal version
	// number (e.g. "Software: Adobe Photoshop 21.0") was misclassified as GPS and
	// pushed to HIGH confidence.
	if gpsCoordRefPattern.MatchString(match) {
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
	// These are typically software versions and not sensitive information.
	lineLower := strings.ToLower(strings.TrimSpace(line))

	// If the line contains a colon, extract the key and value parts.
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])
			if !versionNumberPattern.MatchString(value) {
				return false
			}
			// Only treat a numeric value as a version when the field key is
			// version-related, OR the value is short and version-shaped (L18).
			// A bare long all-digit value in a NAME/AUTHOR/COPYRIGHT/MANAGER
			// field is far more likely a numeric ID/phone than a version, and
			// suppressing it hid real metadata.
			return isVersionishKey(key) || isVersionShapedValue(value)
		}
	}

	// A bare line with no key: only a short, dotted, version-shaped value counts.
	return versionNumberPattern.MatchString(lineLower) && isVersionShapedValue(lineLower)
}

// isVersionishKey reports whether a metadata field key denotes a software version.
func isVersionishKey(key string) bool {
	for _, k := range []string{"version", "ver.", "ver ", "software", "application", "app", "build", "revision", "release", "schema", "format"} {
		if strings.Contains(key, k) {
			return true
		}
	}
	return false
}

// isVersionShapedValue reports whether a numeric value looks like a version
// rather than an ID: at most 3 dotted groups (e.g. "1", "1.0", "2.1.3") and a
// short first component. A long undotted integer ("1234567890") is treated as
// an ID, not a version.
func isVersionShapedValue(value string) bool {
	groups := strings.Split(value, ".")
	if len(groups) > 4 {
		return false
	}
	if len(groups) == 1 {
		// A bare integer is only "version-shaped" if it is short (<=2 digits).
		return len(groups[0]) <= 2
	}
	// Dotted form: first component should be a small number (<=4 digits).
	return len(groups[0]) <= 4
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

// splitMetadataField splits a metadata line into its field NAME and its VALUE.
//
// Every extractor emits metadata as "Name: value" (see
// preprocessors.MetadataFormatter.FormatMetadataField), with "Name = value" also
// accepted here. The two halves are different kinds of text and must be scored
// against different vocabularies:
//
//   - The NAME says what KIND of thing this is. It is chosen by the file format
//     (or, for a custom document property, by the document's author) and is not
//     prose. It is the right input for deciding a finding's TYPE.
//   - The VALUE is the content that may or may not disclose something. It is the
//     right input for judging CONFIDENCE.
//
// Scoring one as if it were the other is what this helper exists to prevent: a
// line beginning "Template:" used to match the word "template" in the validator's
// own test-data denylist and penalize itself, and a company genuinely named
// "Manager Tools LLC" used to be typed MANAGER_INFO and collect the manager
// field's boost.
//
// ok is false when the line carries no separator at all. There is then no field
// name to speak of, and the whole line is returned as the value, so callers that
// score prose keep their previous behaviour on separator-less input.
//
// ":" wins over "=" wherever both appear, and only the FIRST separator splits,
// so a value that itself contains ":" ("Nasdaq - Internal Use: ...") stays whole.
func splitMetadataField(line string) (name, value string, ok bool) {
	sep := ":"
	if !strings.Contains(line, sep) {
		sep = "="
		if !strings.Contains(line, sep) {
			return "", strings.TrimSpace(line), false
		}
	}

	parts := strings.SplitN(line, sep, 2)
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

// extractSensitiveValue extracts just the sensitive value from a metadata field
func (v *Validator) extractSensitiveValue(line, matchType string) string {
	// Handle different field formats: "Field: Value" or "Field = Value"
	_, value, ok := splitMetadataField(line)
	if !ok {
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

// sortedGPSFields returns the GPS field names in a fixed order so
// combineGPSCoordinates visits them the same way on every run.
//
// The order is longest-name-first, then alphabetical. Length first is not
// cosmetic: the caller dispatches with strings.Contains, and the field names
// are substrings of each other ("gpslatitude" contains "latitude",
// "gpslatituderef" contains "gpslatitude"). Visiting the longest name first
// means the most specific field is seen before any name it contains, which is
// the order the switch's case sequence already assumes.
func sortedGPSFields(gpsCoordinates map[string]string) []string {
	fields := make([]string, 0, len(gpsCoordinates))
	for field := range gpsCoordinates {
		fields = append(fields, field)
	}
	sort.Slice(fields, func(i, j int) bool {
		if len(fields[i]) != len(fields[j]) {
			return len(fields[i]) > len(fields[j])
		}
		return fields[i] < fields[j]
	})
	return fields
}

// combineGPSCoordinates combines latitude and longitude into coordinate pairs.
//
// It took a currentEmbeddedMedia override that the caller derived by parsing
// "--- Embedded Media N (name) ---" out of the scanned text; see ValidateContent
// for why that made the reported source attacker-chosen. Coordinates are
// attributed to originalPath, which the caller already receives as real structure.
func (v *Validator) combineGPSCoordinates(gpsCoordinates map[string]string, gpsLineNumbers map[string]int, originalPath string) []detector.Match {
	var matches []detector.Match

	filename := originalPath

	// Look for latitude/longitude pairs
	var latitude, longitude, latRef, longRef string
	var latLine, longLine int

	// Both loops below used to range gpsCoordinates directly. That is a map, so
	// the visit order was random per run — and this function assigns to shared
	// latitude/longitude variables with no precedence, meaning last-writer-wins.
	// A file carrying BOTH a GPSLatitude/GPSLongitude pair and a plain
	// Latitude/Longitude pair with different values therefore emitted one of
	// FOUR different coordinates across runs of the same binary, two of them
	// mixing the latitude of one pair with the longitude of the other — a
	// location that appears nowhere in the file. See the precedence handling
	// below for the fix; the fixed field order here is what makes it reachable.
	fields := sortedGPSFields(gpsCoordinates)

	// Emit any already-consolidated GPS coordinate entries. We do NOT return
	// early here (M33): a stray "Coordinates:" field — possibly a placeholder
	// like "N/A" — must not short-circuit the separate GPSLatitude/GPSLongitude
	// pairing below, and a placeholder value must not be emitted as a GPS match.
	// We therefore validate the value looks like a real coordinate before
	// emitting, and fall through to the component-pairing logic regardless.
	for _, field := range fields {
		value := gpsCoordinates[field]
		fieldLower := strings.ToLower(field)
		if strings.Contains(fieldLower, "gps_coordinates") || strings.Contains(fieldLower, "coordinates") {
			// A real coordinate value contains digits; skip placeholders such as
			// "N/A", "unknown", or empty so they aren't emitted as GPS matches.
			if !v.isMeaningfulGPSValue(field, value) || !strings.ContainsAny(value, "0123456789") {
				continue
			}
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
		}
	}

	// Extract coordinate values for individual components (fallback).
	//
	// PRECEDENCE, not just order (this is the part a plain sort would get
	// wrong): a gps*-prefixed field is the authoritative EXIF/QuickTime tag,
	// while a bare "latitude"/"longitude" is a looser derived or user-supplied
	// field. When a file carries both, the gps* value must win, and — crucially
	// — latitude and longitude must be taken from the SAME source, or the pair
	// describes a place that is in neither. So each source is collected
	// separately and the winner chosen afterwards, rather than assigning to one
	// shared variable and letting whichever field is visited last decide.
	var gpsLat, gpsLong, plainLat, plainLong string
	var gpsLatLine, gpsLongLine, plainLatLine, plainLongLine int
	for _, field := range fields {
		value := gpsCoordinates[field]
		switch {
		case strings.Contains(field, "gpslatitude") && !strings.Contains(field, "ref"):
			gpsLat = value
			gpsLatLine = gpsLineNumbers[field]
		case strings.Contains(field, "gpslongitude") && !strings.Contains(field, "ref"):
			gpsLong = value
			gpsLongLine = gpsLineNumbers[field]
		case strings.Contains(field, "gpslatituderef"):
			latRef = value
		case strings.Contains(field, "gpslongituderef"):
			longRef = value
		case strings.Contains(field, "latitude") && !strings.Contains(field, "gps"):
			plainLat = value
			plainLatLine = gpsLineNumbers[field]
		case strings.Contains(field, "longitude") && !strings.Contains(field, "gps"):
			plainLong = value
			plainLongLine = gpsLineNumbers[field]
		}
	}

	// Prefer a complete gps* pair; fall back to a complete plain pair. Only if
	// neither source is complete on its own do we combine across sources, which
	// preserves the previous behavior for the files that actually relied on it
	// (e.g. "GPSLatitude" present but only "Longitude" available) while never
	// mixing two pairs that are each complete.
	switch {
	case gpsLat != "" && gpsLong != "":
		latitude, longitude = gpsLat, gpsLong
		latLine, longLine = gpsLatLine, gpsLongLine
	case plainLat != "" && plainLong != "":
		latitude, longitude = plainLat, plainLong
		latLine, longLine = plainLatLine, plainLongLine
	default:
		latitude, latLine = gpsLat, gpsLatLine
		if latitude == "" {
			latitude, latLine = plainLat, plainLatLine
		}
		longitude, longLine = gpsLong, gpsLongLine
		if longitude == "" {
			longitude, longLine = plainLong, plainLongLine
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

		// Validate the coordinate pair (L17): reject 0/0 (Null Island / unset GPS)
		// and out-of-range values rather than always scoring 100. Confidence is
		// scaled by parse validity so a syntactically valid in-range pair stays
		// HIGH while a malformed/placeholder pair drops out.
		latVal, latOK := parseCoordinate(latitude)
		longVal, longOK := parseCoordinate(longitude)
		if latOK && longOK {
			if (latVal == 0 && longVal == 0) ||
				latVal < -90 || latVal > 90 || longVal < -180 || longVal > 180 {
				return matches // not a real location; skip emitting a GPS pair
			}
		}

		// Use the earlier line number
		lineNumber := latLine
		if longLine < latLine && longLine > 0 {
			lineNumber = longLine
		}

		// Calculate confidence for combined coordinates. A pair that parsed to a
		// valid in-range decimal is high confidence; one we could not parse (DMS
		// strings, unusual formats) is still emitted but slightly lower.
		confidence := 1.0
		if !latOK || !longOK {
			confidence = 0.75
		}
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

// isValuelessProperty reports whether a custom-property VALUE cannot disclose
// anything, no matter what the property is named.
//
// Custom document properties are dominated in practice by sensitivity-label and
// content-management bookkeeping. Measured over 119 real documents, enabling the
// field emitted 1,228 findings, of which 488 were Microsoft Purview
// MSIP_Label_<guid>_* sub-properties: _Enabled "true", _ContentBits "0",
// _Method "Standard", _SetDate, _SiteId, _ActionId. None of those reveal
// anything about the document, and reporting them buries the sub-property that
// does — _Name, which holds the human-readable classification (measured values
// included "Amazon Confidential" and "Amazon Pending_Classification").
//
// The test is on the VALUE, not the property name, deliberately. A name-based
// denylist would be a denylist of the exact form BSC1 warns about: incomplete
// by construction, and it would drop a genuinely sensitive value that happened
// to sit under a boilerplate-looking name. Judging the value keeps the rule
// honest — a boolean, a bare integer, a GUID, a timestamp, or an empty string
// carries no disclosure regardless of where it appears, while any human-readable
// string is kept and scored normally.
func isValuelessProperty(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}

	switch strings.ToLower(trimmed) {
	case "true", "false", "standard", "none", "null", "n/a":
		return true
	}

	// Bare integers ("0"), integer tuples ("50, 3, 0, 1"), GUIDs, and ISO
	// timestamps are all machine identifiers or counters. A value made only of
	// digits, hex, and structural punctuation has no prose in it to disclose.
	//
	// EXCEPT when the digits are an identifier. This used to be a blanket
	// "no letter -> nothing to disclose", which swallowed exactly the values a
	// custom property is most likely to leak:
	//
	//	Custom_ControlText = "Ledger 8291746350284"  -> CUSTOM_PROPERTY 60
	//	Custom_BillingRef  = "8291746350284"         -> nothing at all
	//
	// Same digits, same part; one English word was the whole difference. A 9-digit
	// case number, a 13-digit billing reference and "449-87-4100" under a property
	// named SubscriberSSN were all reported by nothing, and a value reported by
	// nothing is never redacted. See #373.
	hasLetter := false
	for _, r := range trimmed {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return !isIdentifierDigitRun(trimmed)
	}

	// Everything below is a machine identifier of some shape, and all of those
	// forms are single-token. Any whitespace means prose, so this one check
	// short-circuits the regexes for every human-readable value — which is the
	// case worth keeping fast, since those are the values that become findings.
	// ("Amazon Confidential", "Nasdaq - Internal Use: ..." exit here.)
	if strings.ContainsAny(trimmed, " \t") {
		return false
	}

	// GUID: 8-4-4-4-12 hex. Purview writes several per label.
	if guidPattern.MatchString(trimmed) {
		return true
	}

	// Opaque machine identifiers: a long unbroken hex/base64 run is a digest or
	// an internal id, not prose. SharePoint's ContentTypeId
	// ("0x010100D3F06DC0...") and similar per-library ids are the common case;
	// hex has letters, so the has-a-letter check above lets them through.
	if opaqueIdentifierPattern.MatchString(trimmed) {
		return true
	}

	// ISO-8601 timestamp, e.g. 2026-01-14T21:22:37Z. The only letters are the
	// T/Z separators, so the hasLetter check above does not catch these.
	return isoTimestampPattern.MatchString(trimmed)
}

// isIdentifierDigitRun reports whether a letterless value is long enough, and shaped
// enough, to be an identifier rather than a counter.
//
// # The measurement this is sized against
//
// 150 real Office documents from this machine, 117 of them carrying
// docProps/custom.xml, 908 custom properties, of which 193 values contain no ASCII
// letter and are therefore invisible today. By shape:
//
//	98  bare integers of 4 digits or fewer   <- Purview MSIP_Label ContentBits
//	89  integer tuples ("11, 2, 1, 0")       <- Purview MSIP_Label Tag
//	 2  unbroken runs of 7-8 digits
//	 4  one 5-6 digit run, one date-ish, two bracket literals
//
// This rule admits 2 of those 193, and 0 of the 187 Purview bookkeeping rows —
// they are all either short or comma-separated. The two it admits are a 7-digit value
// under a property named "db_document_id" (a document identifier, which is the point)
// and a 7-digit sort key under "Order" (a false positive, one across 150 documents).
// That is the whole false-positive budget, and it is why the rule tests the VALUE's
// shape rather than the property's NAME: a name vocabulary would have to be maintained
// and would still miss a digit run under "Ref" or "Field3".
//
// # What stays valueless, and what enforces it
//
// The two patterns are anchored and accept ONLY digits, hyphens and spaces, so almost
// every exclusion follows from them rather than needing its own check:
//
//   - fewer than 7 digits: rejected by the floor. Page counts, Purview ContentBits and
//     sort positions all live here — every bare integer in the measured corpus was 4
//     digits or fewer.
//   - integer tuples ("11, 2, 1, 0"): rejected because a comma is not a separator the
//     grouped pattern accepts. This is the commonest bookkeeping shape in the corpus,
//     89 of the 193 letterless values.
//   - versions, times and slash-dates ("1.2.3.4567", "12:34:56", "2026/01/14", and the
//     measured "2026-01-14.0002" under db_template_version): same reason.
//   - a plain calendar date, "YYYY-MM-DD": this one DOES need its own check, because 8
//     digits in hyphen-separated groups is exactly what the grouped pattern accepts.
//
// An earlier version also rejected any value containing ".,:/" up front. That check was
// unreachable — no string containing one of those can match either anchored pattern —
// and a mutation removing it changed no behaviour, which is how it was found. The
// exclusions are still asserted as BEHAVIOUR by the tests, so removing the redundant
// guard did not remove their coverage.
//
// Hyphens and spaces ARE allowed as separators, because that is how a real identifier is
// written: "449-87-4100" and "415 892 4471" are the shapes this exists to recover.
func isIdentifierDigitRun(trimmed string) bool {
	if plainDatePattern.MatchString(trimmed) {
		return false
	}
	if unbrokenDigitRunPattern.MatchString(trimmed) {
		return true
	}
	if !groupedDigitRunPattern.MatchString(trimmed) {
		return false
	}
	digits := 0
	for _, r := range trimmed {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= identifierDigitFloor
}

// identifierDigitFloor is the fewest digits an identifier is assumed to carry.
//
// Seven, because that is where real schemes start (a 7-digit member or case number)
// and because everything shorter in the measured corpus is a counter: every one of the
// 98 bare integers was 4 digits or fewer.
const identifierDigitFloor = 7

var (
	// An unbroken run of digits, nothing else. The floor is identifierDigitFloor, spelled
	// out here because a regexp built by string concatenation is harder to read than the
	// one thing it expresses; the test asserts the two agree.
	unbrokenDigitRunPattern = regexp.MustCompile(`^\d{7,}$`)
	// Digit groups separated by single hyphens or spaces: 449-87-4100, 415 892 4471.
	groupedDigitRunPattern = regexp.MustCompile(`^\d+(?:[- ]\d+)+$`)
	// A plain calendar date, which the grouped form would otherwise admit.
	plainDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

var (
	guidPattern         = regexp.MustCompile(`^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$`)
	isoTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$`)
	// 0x-prefixed or bare hex of 16+ digits, or a base64-ish run of 20+ chars.
	// The length floors keep short human words (a "Privileged" label, a
	// "Confidential" marker) out of this branch.
	opaqueIdentifierPattern = regexp.MustCompile(`^(?:0[xX][0-9a-fA-F]{16,}|[0-9a-fA-F]{16,}|[A-Za-z0-9+/]{20,}={0,2})$`)
)

// applyValueShapeRisk returns the additive confidence boost and the metadata
// keys for a finding whose VALUE carries an intrinsic risk signal — a UNC path
// that discloses an internal server, a classification marker, a project
// codename, a user directory that names an employee.
//
// It exists so the preprocessor-rule path and the per-field fallback path score
// a value identically instead of drifting apart. Only types whose risk shape is
// actually understood are handled; anything else returns a zero boost, so
// adding a new metadata type can never silently pick up a wrong score.
//
// The boost is strictly ADDITIVE. It is deliberately incapable of lowering a
// confidence, because metadata values are entirely attacker-controlled: a
// subtractive rule here would hand an attacker a suppression oracle (they could
// append a token to a field and demote a real finding below the reporting
// threshold — the TM-11 shape). Raising a score cannot hide anything.
func (v *Validator) applyValueShapeRisk(matchType, line, value string) (float64, map[string]interface{}) {
	switch matchType {
	case "TEMPLATE_INFO":
		risk := v.analyzeTemplatePathRisk(value)
		return risk.ConfidenceBoost, map[string]interface{}{
			"template_risk_level":   risk.RiskLevel,
			"template_risk_factors": risk.RiskFactors,
		}

	case "CUSTOM_PROPERTY":
		risk := v.analyzeCustomPropertyRisk(line)
		return risk.ConfidenceBoost, map[string]interface{}{
			"custom_property_name":         risk.PropertyName,
			"custom_property_risk_level":   risk.RiskLevel,
			"custom_property_risk_factors": risk.RiskFactors,
		}

	default:
		return 0, nil
	}
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

			// Classification properties.
			//
			// Split by whether the VALUE carries anything beyond the marking itself. A
			// document that merely records "this is Confidential" is stating its own
			// handling class; a document whose classification property also names a
			// project, a person or a system is disclosing something. Both used to score
			// +0.5 CRITICAL, which meant the two were indistinguishable:
			//
			//	Notice: Confidential                                -> 100
			//	Notice: Confidential - Project Nightjar acquisition -> 100
			//
			// Purview/MSIP writes a bare label into custom properties on a large fraction
			// of real enterprise documents, so treating the marking as CRITICAL floods the
			// HIGH band that operators triage first — and the finding that actually
			// matters sits in the same bucket as thousands of labels. Demoting the marking
			// rather than vetoing it keeps it reportable (it IS worth knowing a document is
			// marked) while restoring the ordering.
			if isClassified(propNameLower, propValueLower) {
				if classificationIsBareMarking(propValueLower) {
					risk.RiskFactors = append(risk.RiskFactors,
						"Carries a sensitivity marking (no additional content)")
					risk.ConfidenceBoost += 0.1
					if risk.RiskLevel == "LOW" {
						risk.RiskLevel = "MEDIUM"
					}
				} else {
					risk.RiskFactors = append(risk.RiskFactors, "Contains security classification")
					risk.ConfidenceBoost += 0.5
					risk.RiskLevel = "CRITICAL"
				}
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
			//
			// "id" is matched on a whole-word boundary, not as a substring.
			// Measured over 119 real documents: a plain strings.Contains fired on
			// the SharePoint/Purview plumbing that dominates real custom
			// properties — ContentTypeId, ComplianceAssetId, _dlc_DocIdItemGuid —
			// promoting 45 occurrences of pure boilerplate to HIGH. kwmatch
			// treats '_' as a boundary, so "user_id" and "employee_id" still
			// match while "contenttypeid" does not. Compound names with no
			// separator ("employeeid", "badgeid") are still caught by their own
			// keyword in this same list.
			piiFields := []string{"employee", "ssn", "social", "badge", "clearance"}
			for _, field := range piiFields {
				if strings.Contains(propNameLower, field) {
					risk.RiskFactors = append(risk.RiskFactors, "Contains PII: "+field)
					risk.ConfidenceBoost += 0.4
					if risk.RiskLevel != "CRITICAL" {
						risk.RiskLevel = "HIGH"
					}
				}
			}
			if kwmatch.ContainsLower(propNameLower, "id") {
				risk.RiskFactors = append(risk.RiskFactors, "Contains PII: id")
				risk.ConfidenceBoost += 0.4
				if risk.RiskLevel != "CRITICAL" {
					risk.RiskLevel = "HIGH"
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

// isClassified reports whether a custom property looks like a security classification,
// by name or by value. Unchanged in substance from the inline condition it replaces;
// extracted so the bare-marking test below reads against the same predicate.
func isClassified(propNameLower, propValueLower string) bool {
	return strings.Contains(propNameLower, "classification") ||
		strings.Contains(propNameLower, "clearance") ||
		strings.Contains(propValueLower, "secret") ||
		strings.Contains(propValueLower, "confidential") ||
		strings.Contains(propValueLower, "restricted")
}

// classificationMarkings are the values a sensitivity label takes on its own.
//
// Deliberately the full label vocabulary rather than a couple of examples: the point is
// to recognise a value that is ONLY a marking, and a list that misses "highly
// confidential" would treat that one as a disclosure while treating "confidential" as a
// marking — an inconsistency worse than either rule alone.
var classificationMarkings = map[string]bool{
	"confidential": true, "highly confidential": true, "strictly confidential": true,
	"secret": true, "top secret": true, "restricted": true, "internal": true,
	"internal only": true, "internal use only": true, "public": true,
	"general": true, "private": true, "sensitive": true, "unclassified": true,
	"non-business": true, "personal": true, "protected": true,
}

// classificationIsBareMarking reports whether a value is nothing but a sensitivity
// marking, so it states the document's handling class without disclosing content.
//
// Punctuation and label-plumbing decoration are stripped before the comparison because
// real labels arrive dressed: "Confidential", "[Confidential]", "Confidential."  and
// "Confidential / Internal" are all the same statement. What must NOT be stripped is a
// project name, a person or a system — those are the content that makes a classification
// property a disclosure, and anything left over after decoration is treated as exactly
// that.
func classificationIsBareMarking(propValueLower string) bool {
	v := strings.TrimSpace(propValueLower)
	if v == "" {
		return true
	}
	// Split on the separators labels use, then require EVERY part to be a known marking.
	// Requiring all parts (rather than any) is what keeps
	// "confidential - project nightjar" out: one part is a marking, the other is not.
	parts := strings.FieldsFunc(v, func(r rune) bool {
		switch r {
		case '/', '\\', '|', ',', ';', '-', '\u2013', '\u2014', ':', '(', ')', '[', ']', '.', '_':
			return true
		}
		return false
	})
	if len(parts) == 0 {
		return true
	}
	for _, p := range parts {
		if !classificationMarkings[strings.TrimSpace(p)] {
			return false
		}
	}
	return true
}
