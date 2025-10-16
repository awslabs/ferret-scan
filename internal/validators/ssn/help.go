// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the SSN check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "SSN",
		ShortDescription: "Detects Social Security Numbers in various formats",
		DetailedDescription: `The SSN check detects Social Security Numbers in documents and text files using pattern matching and contextual analysis.

It validates SSN format according to official Social Security Administration rules, filtering out invalid area numbers (000, 666, 900-999) and identifying test/placeholder SSNs. The validator uses contextual keywords to improve accuracy and reduce false positives.

The check looks for 9-digit numbers that may be formatted with hyphens or spaces in XXX-XX-XXXX or XXX XX XXXX patterns. It validates the area number, group number, and serial number components according to SSA rules.`,

		Patterns: []string{
			"XXX-XX-XXXX (standard hyphenated format)",
			"XXXXXXXXX (9 consecutive digits)",
			"XXX XX XXXX (space-separated format)",
		},

		SupportedFormats: []string{
			"Valid area numbers: 001-665, 667-899",
			"Valid group numbers: 01-99",
			"Valid serial numbers: 0001-9999",
			"Excludes known test patterns",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "Must be 9 digits in valid SSN format", Weight: 20},
			{Name: "Valid Area", Description: "Area number must be in valid range", Weight: 15},
			{Name: "Not Test Number", Description: "Must not match known test SSNs", Weight: 25},
			{Name: "Not Sequential", Description: "Must not be sequential digits", Weight: 15},
			{Name: "Not Repeating", Description: "Must not have repeating patterns", Weight: 15},
			{Name: "Context", Description: "Contextual keywords nearby", Weight: 10},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file employee-records.txt --checks SSN",
			"ferret-scan --file tax-documents.pdf --confidence high | grep SSN",
		},
	}
}
