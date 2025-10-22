// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/formatters/shared"
	"fmt"
	"math"
	"path/filepath"
	"strings"
)

// VulnerabilityMapper converts ferret-scan detector matches to SARIF results
type VulnerabilityMapper struct {
	ruleManager *RuleManager
}

// NewVulnerabilityMapper creates a new VulnerabilityMapper instance
func NewVulnerabilityMapper(ruleManager *RuleManager) *VulnerabilityMapper {
	return &VulnerabilityMapper{
		ruleManager: ruleManager,
	}
}

// roundFloat rounds a float64 to 1 decimal place for cleaner SARIF output
func roundFloat(val float64) float64 {
	return math.Round(val*10) / 10
}

// roundMetadataFloats recursively rounds all float64 values in metadata to 1 decimal place
func roundMetadataFloats(data any) any {
	switch v := data.(type) {
	case float64:
		return roundFloat(v)
	case float32:
		return roundFloat(float64(v))
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			result[key] = roundMetadataFloats(value)
		}
		return result
	case map[string]float64:
		// Handle strongly-typed float64 maps
		result := make(map[string]float64)
		for key, value := range v {
			result[key] = roundFloat(value)
		}
		return result
	case map[string]bool:
		// Pass through boolean maps unchanged
		return v
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = roundMetadataFloats(value)
		}
		return result
	case []string:
		// Pass through string slices unchanged
		return v
	default:
		// Pass through other types unchanged (int, string, bool, etc.)
		return v
	}
}

// MapToSARIFResult converts a detector.Match to a SARIF result
// All sensitive data findings are mapped to "error" level since they represent
// security/compliance issues regardless of detection confidence
func (m *VulnerabilityMapper) MapToSARIFResult(match detector.Match, options formatters.FormatterOptions) (*SARIFResult, error) {
	// Ensure the rule exists for this detection type
	m.ruleManager.GetOrCreateRule(match.Type)

	result := &SARIFResult{
		RuleID:     match.Type,
		Level:      LevelError, // All sensitive data findings are errors
		Message:    m.buildMessage(match, options),
		Locations:  []SARIFLocation{m.buildLocation(match, options)},
		Properties: m.buildProperties(match),
		Rank:       m.calculateRank(match),
	}

	return result, nil
}

// MapSuppressedMatch converts a suppressed match to a SARIF result with level "none"
// and includes suppression information
func (m *VulnerabilityMapper) MapSuppressedMatch(suppressed detector.SuppressedMatch, options formatters.FormatterOptions) (*SARIFResult, error) {
	// Ensure the rule exists for this detection type
	m.ruleManager.GetOrCreateRule(suppressed.Match.Type)

	result := &SARIFResult{
		RuleID:     suppressed.Match.Type,
		Level:      LevelNone, // Suppressed results use "none" level
		Message:    m.buildMessage(suppressed.Match, options),
		Locations:  []SARIFLocation{m.buildLocation(suppressed.Match, options)},
		Properties: m.buildPropertiesForSuppressed(suppressed),
		Suppressions: []SARIFSuppression{
			{
				Kind:          SuppressionKindInSource,
				Justification: suppressed.RuleReason,
			},
		},
		Rank: m.calculateRank(suppressed.Match),
	}

	return result, nil
}

// buildLocation creates a SARIF location with file URI and region information
func (m *VulnerabilityMapper) buildLocation(match detector.Match, options formatters.FormatterOptions) SARIFLocation {
	location := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: m.buildArtifactLocation(match),
			Region:           m.buildRegion(match, options),
		},
	}

	// Add context region if available
	if contextRegion := m.buildContextRegion(match); contextRegion != nil {
		location.PhysicalLocation.ContextRegion = contextRegion
	}

	return location
}

// buildArtifactLocation creates the artifact location with file:// URI scheme
func (m *VulnerabilityMapper) buildArtifactLocation(match detector.Match) SARIFArtifactLocation {
	// Convert file path to URI using file:// scheme
	// Clean the path and convert to forward slashes for URI
	cleanPath := filepath.ToSlash(filepath.Clean(match.Filename))

	location := SARIFArtifactLocation{
		URI: cleanPath,
	}

	// For relative paths, use %SRCROOT% uriBaseId to map to repository root
	// This enables tools like GitHub Security to properly map file locations
	if !filepath.IsAbs(match.Filename) {
		location.URIBaseID = "%SRCROOT%"
	} else {
		// For absolute paths, use file:// scheme
		location.URI = "file://" + cleanPath
	}

	return location
}

// buildRegion extracts line number, column information, and snippet text from matches
func (m *VulnerabilityMapper) buildRegion(match detector.Match, options formatters.FormatterOptions) SARIFRegion {
	region := SARIFRegion{
		StartLine: match.LineNumber,
	}

	// Ensure line number is at least 1 (SARIF requirement)
	if region.StartLine < 1 {
		region.StartLine = 1
	}

	// Add snippet if ShowMatch is enabled and we have the full line
	if options.ShowMatch && match.Context.FullLine != "" {
		region.Snippet = &SARIFSnippet{
			Text: match.Context.FullLine,
		}
	}

	// Try to calculate column information if we have the full line and matched text
	if match.Context.FullLine != "" && match.Text != "" {
		// Find the position of the matched text in the line
		index := strings.Index(match.Context.FullLine, match.Text)
		if index >= 0 {
			// SARIF columns are 1-based
			region.StartColumn = index + 1
			region.EndColumn = index + len(match.Text) + 1
		}
	}

	return region
}

// buildContextRegion includes surrounding context when available from detector.Match.Context
func (m *VulnerabilityMapper) buildContextRegion(match detector.Match) *SARIFRegion {
	// Only include context region if we have before or after text
	if match.Context.BeforeText == "" && match.Context.AfterText == "" {
		return nil
	}

	// Build context text from before and after
	var contextText strings.Builder
	if match.Context.BeforeText != "" {
		contextText.WriteString(match.Context.BeforeText)
		contextText.WriteString("\n")
	}
	if match.Context.FullLine != "" {
		contextText.WriteString(match.Context.FullLine)
	}
	if match.Context.AfterText != "" {
		contextText.WriteString("\n")
		contextText.WriteString(match.Context.AfterText)
	}

	if contextText.Len() == 0 {
		return nil
	}

	// Context region starts a few lines before the match
	// We'll estimate based on the number of newlines in BeforeText
	contextStartLine := match.LineNumber
	if match.Context.BeforeText != "" {
		beforeLines := strings.Count(match.Context.BeforeText, "\n")
		contextStartLine = match.LineNumber - beforeLines
		if contextStartLine < 1 {
			contextStartLine = 1
		}
	}

	return &SARIFRegion{
		StartLine: contextStartLine,
		Snippet: &SARIFSnippet{
			Text: contextText.String(),
		},
	}
}

// buildProperties includes confidence, confidenceLevel, validator, and metadata in result properties
func (m *VulnerabilityMapper) buildProperties(match detector.Match) map[string]interface{} {
	properties := make(map[string]interface{})

	// Add confidence information (rounded to 1 decimal place)
	properties["confidence"] = roundFloat(match.Confidence)
	properties["confidenceLevel"] = shared.GetConfidenceLevel(match.Confidence)

	// Add validator name if available
	if match.Validator != "" {
		properties["validator"] = match.Validator
	}

	// Add metadata if available (with rounded floats)
	if len(match.Metadata) > 0 {
		// Deep copy and round all float values in metadata
		roundedMetadata := make(map[string]interface{})
		for key, value := range match.Metadata {
			roundedMetadata[key] = roundMetadataFloats(value)
		}
		properties["metadata"] = roundedMetadata
	}

	// Add context keywords if available
	if len(match.Context.PositiveKeywords) > 0 {
		properties["positiveKeywords"] = match.Context.PositiveKeywords
	}
	if len(match.Context.NegativeKeywords) > 0 {
		properties["negativeKeywords"] = match.Context.NegativeKeywords
	}

	return properties
}

// buildPropertiesForSuppressed builds properties for suppressed matches
// including expiration information
func (m *VulnerabilityMapper) buildPropertiesForSuppressed(suppressed detector.SuppressedMatch) map[string]interface{} {
	properties := m.buildProperties(suppressed.Match)

	// Add suppression-specific properties
	properties["suppressedBy"] = suppressed.SuppressedBy
	properties["expired"] = suppressed.Expired

	// Add expiration date if available
	if suppressed.ExpiresAt != nil {
		properties["expiresAt"] = suppressed.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")
	}

	return properties
}

// calculateRank computes priority ranking based on data type sensitivity and detection confidence
// Returns a value between 0.0 and 100.0 as required by SARIF specification
// Higher rank values indicate higher priority findings
func (m *VulnerabilityMapper) calculateRank(match detector.Match) float64 {
	// Define sensitivity weights for different data types (0-10 scale)
	// Higher values indicate more sensitive data
	sensitivityWeights := map[string]float64{
		"SSN":                   10.0, // Highest sensitivity
		"CREDIT_CARD":           10.0,
		"PASSPORT":              10.0,
		"SECRETS":               9.0,
		"INTELLECTUAL_PROPERTY": 7.0,
		"PERSON_NAME":           6.0,
		"EMAIL":                 5.0,
		"PHONE":                 5.0,
		"IP_ADDRESS":            4.0,
		"METADATA":              3.0,
		"SOCIAL_MEDIA":          3.0,
	}

	// Get sensitivity weight for this type, default to 5.0 for unknown types
	sensitivity := sensitivityWeights[match.Type]
	if sensitivity == 0 {
		sensitivity = 5.0
	}

	// Normalize confidence to 0-10 scale (confidence is 0-100)
	normalizedConfidence := match.Confidence / 10.0

	// Calculate rank: (sensitivity * 5) + (normalizedConfidence * 5)
	// This gives us a range of 0-100 with both factors contributing equally
	// Sensitivity contributes 0-50, confidence contributes 0-50
	rank := (sensitivity * 5.0) + (normalizedConfidence * 5.0)

	// Ensure rank is within valid range [0, 100]
	if rank > 100.0 {
		rank = 100.0
	}
	if rank < 0.0 {
		rank = 0.0
	}

	// Round to 1 decimal place for cleaner output
	return roundFloat(rank)
}

// buildMessage creates descriptive messages respecting FormatterOptions.Verbose and ShowMatch settings
func (m *VulnerabilityMapper) buildMessage(match detector.Match, options formatters.FormatterOptions) SARIFMessage {
	var message strings.Builder

	// Get the rule description for context
	desc := GetRuleDescription(match.Type)

	// Start with the short description
	message.WriteString(desc.Short)

	// Add file and line information
	message.WriteString(fmt.Sprintf(" in %s at line %d", filepath.Base(match.Filename), match.LineNumber))

	// Add confidence information
	confidenceLevel := shared.GetConfidenceLevel(match.Confidence)
	message.WriteString(fmt.Sprintf(" (confidence: %.1f%% - %s)", match.Confidence, confidenceLevel))

	// Add matched text if ShowMatch is enabled
	if options.ShowMatch && match.Text != "" {
		// Truncate long matches for readability
		matchText := match.Text
		if len(matchText) > 50 {
			matchText = matchText[:47] + "..."
		}
		message.WriteString(fmt.Sprintf(". Matched text: '%s'", matchText))
	}

	// Add verbose information if enabled
	if options.Verbose {
		if match.Validator != "" {
			message.WriteString(fmt.Sprintf(". Detected by: %s", match.Validator))
		}

		// Add context keywords if available
		if len(match.Context.PositiveKeywords) > 0 {
			message.WriteString(fmt.Sprintf(". Positive indicators: %s", strings.Join(match.Context.PositiveKeywords, ", ")))
		}
		if len(match.Context.NegativeKeywords) > 0 {
			message.WriteString(fmt.Sprintf(". Negative indicators: %s", strings.Join(match.Context.NegativeKeywords, ", ")))
		}
	}

	return SARIFMessage{
		Text: message.String(),
	}
}
