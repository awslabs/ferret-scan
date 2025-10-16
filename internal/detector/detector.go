// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"ferret-scan/internal/security"
	"time"
)

// ContextInfo stores contextual information about a match
type ContextInfo struct {
	// Text before and after the match
	BeforeText string
	AfterText  string

	// Line containing the match
	FullLine string

	// Contextual keywords found near the match
	PositiveKeywords []string // Keywords that increase confidence
	NegativeKeywords []string // Keywords that decrease confidence

	// Impact on confidence score
	ConfidenceImpact float64
}

// Validator interface defines methods for validating sensitive data
type Validator interface {
	Validate(filePath string) ([]Match, error)
	CalculateConfidence(match string) (float64, map[string]bool)

	// New method for contextual analysis
	AnalyzeContext(match string, context ContextInfo) float64

	// New method for validating preprocessed content
	ValidateContent(content string, originalPath string) ([]Match, error)
}

// Match represents a detected sensitive data match
type Match struct {
	Text       string
	SecureText *security.SecureString // Secure version of Text
	LineNumber int
	Type       string
	Confidence float64
	Metadata   map[string]any
	Filename   string // Path to the file where the match was found
	Validator  string // Name of the validator that created this match

	// New field for context information
	Context ContextInfo
}

// SuppressedMatch represents a finding that was suppressed by a rule
type SuppressedMatch struct {
	Match        Match      `json:"finding"`
	SuppressedBy string     `json:"suppressed_by"`
	RuleReason   string     `json:"rule_reason"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Expired      bool       `json:"expired"`
}

// Clear securely wipes sensitive data from memory
func (m *Match) Clear() {
	// Clear sensitive text
	m.Text = ""
	if m.SecureText != nil {
		m.SecureText.Clear()
		m.SecureText = nil
	}

	// Clear context
	m.Context.BeforeText = ""
	m.Context.AfterText = ""
	m.Context.FullLine = ""
}

// ContextExtractor extracts context from a file around a specific match
type ContextExtractor struct {
	// Number of lines before and after the match to consider
	ContextLines int

	// Number of characters before and after the match to consider
	ContextChars int
}

// NewContextExtractor creates a new context extractor with default settings
func NewContextExtractor() *ContextExtractor {
	return &ContextExtractor{
		ContextLines: 2,  // Look at 2 lines before and after by default
		ContextChars: 50, // Look at 50 chars before and after by default
	}
}

// WithContextLines sets the number of context lines
func (ce *ContextExtractor) WithContextLines(lines int) *ContextExtractor {
	ce.ContextLines = lines
	return ce
}

// WithContextChars sets the number of context characters
func (ce *ContextExtractor) WithContextChars(chars int) *ContextExtractor {
	ce.ContextChars = chars
	return ce
}
