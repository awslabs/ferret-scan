// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
)

// ValidatorBridge wraps standard validators to work with the enhanced system
type ValidatorBridge struct {
	validator detector.Validator
	name      string
}

// NewValidatorBridge creates a bridge for a standard validator
func NewValidatorBridge(name string, validator detector.Validator) *ValidatorBridge {
	return &ValidatorBridge{
		validator: validator,
		name:      name,
	}
}

// Validate implements detector.Validator interface
func (vb *ValidatorBridge) Validate(filePath string) ([]detector.Match, error) {
	return vb.validator.Validate(filePath)
}

// CalculateConfidence implements detector.Validator interface
func (vb *ValidatorBridge) CalculateConfidence(match string) (float64, map[string]bool) {
	return vb.validator.CalculateConfidence(match)
}

// AnalyzeContext implements detector.Validator interface
func (vb *ValidatorBridge) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	return vb.validator.AnalyzeContext(match, context)
}

// ValidateContent implements detector.Validator interface
func (vb *ValidatorBridge) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return vb.validator.ValidateContent(content, originalPath)
}

// GetName returns the validator name
func (vb *ValidatorBridge) GetName() string {
	return vb.name
}

// ValidateWithContext implements EnhancedValidator interface
func (vb *ValidatorBridge) ValidateWithContext(content string, filePath string, contextInsights context.ContextInsights) ([]detector.Match, error) {
	// Use context insights to enhance validation
	matches, err := vb.validator.ValidateContent(content, filePath)
	if err != nil {
		return nil, err
	}

	// Apply context-based confidence adjustments
	contextAnalyzer := context.NewContextAnalyzer()
	for i := range matches {
		// Get confidence adjustment for this validator
		adjustment := contextAnalyzer.GetConfidenceAdjustment(contextInsights, vb.name)

		// Apply adjustment (keeping within 0-100 range)
		newConfidence := matches[i].Confidence + adjustment
		if newConfidence > 100 {
			newConfidence = 100
		} else if newConfidence < 0 {
			newConfidence = 0
		}

		matches[i].Confidence = newConfidence

		// Add context information to metadata if it doesn't exist
		if matches[i].Metadata == nil {
			matches[i].Metadata = make(map[string]interface{})
		}
		matches[i].Metadata["context_domain"] = contextInsights.Domain
		matches[i].Metadata["context_doctype"] = contextInsights.DocumentType
		matches[i].Metadata["confidence_adjustment"] = adjustment
	}

	return matches, nil
}

// ValidateBatch implements EnhancedValidator interface (basic implementation)
func (vb *ValidatorBridge) ValidateBatch(items []ValidationItem) ([]BatchValidationResult, error) {
	results := make([]BatchValidationResult, 0, len(items))

	for _, item := range items {
		matches, err := vb.ValidateWithContext(item.Content, item.FilePath, item.Context)
		result := BatchValidationResult{
			Item:    item,
			Matches: matches,
			Error:   err,
		}
		results = append(results, result)
	}

	return results, nil
}

// CalibrateConfidence implements EnhancedValidator interface (placeholder)
func (vb *ValidatorBridge) CalibrateConfidence(matches []detector.Match, feedback []ConfidenceFeedback) error {
	// Placeholder - not implemented in Phase 2
	return nil
}

// LearnFromFeedback implements EnhancedValidator interface (placeholder)
func (vb *ValidatorBridge) LearnFromFeedback(feedback []ValidationFeedback) error {
	// Placeholder - not implemented in Phase 2
	return nil
}

// SetLanguage implements EnhancedValidator interface (placeholder)
func (vb *ValidatorBridge) SetLanguage(lang string) error {
	// Placeholder - most validators don't need this yet
	return nil
}

// GetSupportedLanguages implements EnhancedValidator interface
func (vb *ValidatorBridge) GetSupportedLanguages() []string {
	// Default to English for now
	return []string{"en"}
}
