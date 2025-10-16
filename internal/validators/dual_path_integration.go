// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"fmt"

	"ferret-scan/internal/context"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
	"ferret-scan/internal/router"
)

// DualPathIntegration provides integration between the main application and dual-path bridge
type DualPathIntegration struct {
	enhancedBridge  *EnhancedValidatorBridge
	observer        *observability.StandardObserver
	contextAnalyzer *context.ContextAnalyzer
	fileRouter      *router.FileRouter
}

// NewDualPathIntegration creates a new dual-path integration component
func NewDualPathIntegration(observer *observability.StandardObserver) *DualPathIntegration {
	config := &DualPathConfig{
		EnableContextIntegration: true,
		EnableFallbackMode:       true,
		EnableMetrics:            true,
		EnableDebugLogging:       observer != nil && observer.DebugObserver != nil,
		MaxRetries:               3,
	}

	integration := &DualPathIntegration{
		enhancedBridge:  NewEnhancedValidatorBridge(config),
		observer:        observer,
		contextAnalyzer: context.NewContextAnalyzer(),
	}

	// Set observer on the bridge
	if observer != nil {
		integration.enhancedBridge.SetObserver(observer)
	}

	return integration
}

// RegisterDocumentValidators registers all non-metadata validators for document body content
func (dpi *DualPathIntegration) RegisterDocumentValidators(validators map[string]detector.Validator) {
	for name, validator := range validators {
		// Skip metadata validator - it will be handled separately
		if name == "METADATA" {
			continue
		}
		dpi.enhancedBridge.RegisterDocumentValidator(validator)
	}
}

// SetFileRouter sets the file router for metadata capability detection
func (dpi *DualPathIntegration) SetFileRouter(fileRouter *router.FileRouter) {
	if fileRouter == nil {
		return
	}
	dpi.fileRouter = fileRouter
	// Set the file router on the content router in the enhanced bridge
	if dpi.enhancedBridge != nil && dpi.enhancedBridge.contentRouter != nil {
		dpi.enhancedBridge.contentRouter.SetFileRouter(fileRouter)
	}
}

// SetMetadataValidator sets the metadata validator for metadata content
func (dpi *DualPathIntegration) SetMetadataValidator(validator detector.Validator) error {
	// Check if the validator implements PreprocessorAwareValidator
	if metadataValidator, ok := validator.(PreprocessorAwareValidator); ok {
		dpi.enhancedBridge.SetMetadataValidator(metadataValidator)
		return nil
	}

	// If not, wrap it with a compatibility adapter
	adapter := &MetadataValidatorAdapter{
		validator: validator,
		observer:  dpi.observer,
	}
	dpi.enhancedBridge.SetMetadataValidator(adapter)
	return nil
}

// ProcessContent processes content using the dual-path validation system
func (dpi *DualPathIntegration) ProcessContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	return dpi.enhancedBridge.ProcessContent(content)
}

// GetMetrics returns current metrics for monitoring
func (dpi *DualPathIntegration) GetMetrics() *DualPathMetrics {
	return dpi.enhancedBridge.GetMetrics()
}

// MetadataValidatorAdapter adapts a standard validator to work with the metadata bridge
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

// ValidatorIntegrationHelper provides helper methods for integrating with existing code
type ValidatorIntegrationHelper struct {
	dualPathIntegration *DualPathIntegration
}

// NewValidatorIntegrationHelper creates a new integration helper
func NewValidatorIntegrationHelper(observer *observability.StandardObserver) *ValidatorIntegrationHelper {
	return &ValidatorIntegrationHelper{
		dualPathIntegration: NewDualPathIntegration(observer),
	}
}

// SetFileRouter sets the file router for the dual path integration
func (vih *ValidatorIntegrationHelper) SetFileRouter(fileRouter *router.FileRouter) {
	vih.dualPathIntegration.SetFileRouter(fileRouter)
}

// SetupDualPathValidation sets up dual-path validation with existing validators
func (vih *ValidatorIntegrationHelper) SetupDualPathValidation(validators map[string]detector.Validator) error {
	// Register document validators (all except metadata)
	vih.dualPathIntegration.RegisterDocumentValidators(validators)

	// Set metadata validator if it exists
	if metadataValidator, exists := validators["METADATA"]; exists {
		if err := vih.dualPathIntegration.SetMetadataValidator(metadataValidator); err != nil {
			return fmt.Errorf("failed to set metadata validator: %w", err)
		}
	}

	return nil
}

// ProcessContentWithDualPath processes content using dual-path validation
func (vih *ValidatorIntegrationHelper) ProcessContentWithDualPath(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	return vih.dualPathIntegration.ProcessContent(content)
}

// GetDualPathMetrics returns metrics from the dual-path system
func (vih *ValidatorIntegrationHelper) GetDualPathMetrics() *DualPathMetrics {
	return vih.dualPathIntegration.GetMetrics()
}
