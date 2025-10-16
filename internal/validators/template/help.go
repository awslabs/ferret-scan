// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package template

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about this check
// IMPORTANT: When implementing your own validator:
// 1. Create a new package with a unique name (e.g., "ssn" instead of "template")
// 2. Keep the method name as GetCheckInfo() but customize the content
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		// Basic information
		Name:             "SAMPLE_CHECK", // Replace with your check name (e.g., "SSN", "API_KEY", etc.)
		ShortDescription: "Short one-line description of what this check detects",
		DetailedDescription: `Detailed multi-line description of what this check does.
Explain what kind of sensitive data it detects, how it works, and any other
relevant information that would help users understand the check.`,

		// Patterns this check looks for (examples)
		Patterns: []string{
			"Pattern description 1 (e.g., 9 digits with optional dashes)",
			"Pattern description 2 (e.g., alphanumeric string with specific prefix)",
			// Add more pattern descriptions as needed
		},

		// Formats or types supported by this check
		SupportedFormats: []string{
			"Format 1 description",
			"Format 2 description",
			// Add more format descriptions as needed
		},

		// Factors that affect confidence scoring
		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Factor 1", Description: "Description of factor 1", Weight: 20},
			{Name: "Factor 2", Description: "Description of factor 2", Weight: 15},
			// Add more factors as needed (weights should add up to 100)
		},

		// Keywords that affect contextual analysis
		// These are automatically populated from the validator's fields
		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		// Usage examples
		Examples: []string{
			"ferret-scan --file example1.txt --confidence high",
			"ferret-scan --file example2.txt --verbose | grep SAMPLE_CHECK",
			// Add more examples as needed
		},
	}
}
