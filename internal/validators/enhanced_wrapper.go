// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"ferret-scan/internal/detector"
	"ferret-scan/internal/preprocessors"
)

// ProcessedContentValidator interface for validators that can handle ProcessedContent
type ProcessedContentValidator interface {
	detector.Validator
	ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
}

// EnhancedManagerWrapper wraps the enhanced manager to work with the existing parallel processing system
type EnhancedManagerWrapper struct {
	manager *EnhancedValidatorManager
}

// NewEnhancedManagerWrapper creates a wrapper for the enhanced manager
func NewEnhancedManagerWrapper(manager *EnhancedValidatorManager) *EnhancedManagerWrapper {
	return &EnhancedManagerWrapper{
		manager: manager,
	}
}

// Validate implements detector.Validator interface
func (w *EnhancedManagerWrapper) Validate(filePath string) ([]detector.Match, error) {
	// This method is not used in the current flow, but required by interface
	return nil, nil
}

// CalculateConfidence implements detector.Validator interface
func (w *EnhancedManagerWrapper) CalculateConfidence(match string) (float64, map[string]bool) {
	// This method is not used in the current flow, but required by interface
	return 0.0, nil
}

// AnalyzeContext implements detector.Validator interface
func (w *EnhancedManagerWrapper) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// This method is not used in the current flow, but required by interface
	return 0.0
}

// ValidateContent implements detector.Validator interface - this is the main method used
func (w *EnhancedManagerWrapper) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Create a ProcessedContent object for dual path validation
	processedContent := &preprocessors.ProcessedContent{
		Text:         content,
		OriginalPath: originalPath,
		Success:      true,
	}

	// Use dual path validation when available
	return w.ValidateProcessedContent(processedContent)
}

// ValidateProcessedContent implements ProcessedContentValidator interface
func (w *EnhancedManagerWrapper) ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	// Use the dual path validation when ProcessedContent is available
	return w.manager.ValidateContentWithDualPath(content)
}
