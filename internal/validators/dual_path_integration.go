// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"fmt"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/router"
)

// MetadataValidatorAdapter adapts a standard detector.Validator into the
// PreprocessorAwareValidator interface the metadata path expects. It is used by
// Detector.SetupValidators when the configured METADATA validator does not
// itself implement PreprocessorAwareValidator.
//
// (This is the only surviving type from the former dual-path integration layer;
// the EnhancedManagerWrapper / EnhancedValidatorManager / ValidatorIntegrationHelper /
// DualPathIntegration pass-through chain was collapsed into Detector in v2
// Phase 2, Move B — see detector.go and docs/proposals/V2_ARCHITECTURE.md.)
type MetadataValidatorAdapter struct {
	validator detector.Validator
	observer  *observability.StandardObserver
}

// Validate implements detector.Validator interface
func (mva *MetadataValidatorAdapter) Validate(filePath string) ([]detector.Match, error) {
	return mva.validator.Validate(filePath)
}

// CalculateConfidence implements detector.Validator interface
func (mva *MetadataValidatorAdapter) CalculateConfidence(match string) (float64, map[string]bool) {
	return mva.validator.CalculateConfidence(match)
}

// AnalyzeContext implements detector.Validator interface
func (mva *MetadataValidatorAdapter) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	return mva.validator.AnalyzeContext(match, context)
}

// ValidateContent implements detector.Validator interface
func (mva *MetadataValidatorAdapter) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return mva.validator.ValidateContent(content, originalPath)
}

// ValidateMetadataContent implements PreprocessorAwareValidator interface
func (mva *MetadataValidatorAdapter) ValidateMetadataContent(content router.MetadataContent) ([]detector.Match, error) {
	// Check if the underlying validator already implements PreprocessorAwareValidator
	if preprocessorAware, ok := mva.validator.(PreprocessorAwareValidator); ok {
		// Use the validator's own ValidateMetadataContent method
		return preprocessorAware.ValidateMetadataContent(content)
	}

	// Fallback: Use the standard ValidateContent method for compatibility
	matches, err := mva.validator.ValidateContent(content.Content, content.SourceFile)
	if err != nil {
		return nil, err
	}

	// Add preprocessor information to match metadata
	for i := range matches {
		if matches[i].Metadata == nil {
			matches[i].Metadata = make(map[string]interface{})
		}
		matches[i].Metadata["preprocessor_type"] = content.PreprocessorType
		matches[i].Metadata["preprocessor_name"] = content.PreprocessorName
		matches[i].Metadata["source_file"] = content.SourceFile
	}

	return matches, nil
}

// GetSupportedPreprocessors implements PreprocessorAwareValidator interface
func (mva *MetadataValidatorAdapter) GetSupportedPreprocessors() []string {
	// Return all preprocessor types for compatibility
	return []string{
		router.PreprocessorTypeImageMetadata,
		router.PreprocessorTypeDocumentMetadata,
		router.PreprocessorTypeOfficeMetadata,
		router.PreprocessorTypeAudioMetadata,
		router.PreprocessorTypeVideoMetadata,
	}
}

// SetPreprocessorValidationRules implements PreprocessorAwareValidator interface
func (mva *MetadataValidatorAdapter) SetPreprocessorValidationRules(rules map[string]ValidationRule) {
	// This is a no-op for the adapter since standard validators don't support this
	if mva.observer != nil && mva.observer.DebugObserver != nil {
		mva.observer.DebugObserver.LogDetail("metadata_adapter",
			fmt.Sprintf("SetPreprocessorValidationRules called with %d rules (no-op for standard validator)", len(rules)))
	}
}
