// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the phone check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "PHONE",
		ShortDescription: "Detects phone numbers in various international formats",
		DetailedDescription: `The Phone check detects phone numbers using multiple pattern matching approaches for different international formats.

It supports US/Canada, UK, European, and international phone number formats with various separators (spaces, dashes, dots, parentheses). The validator performs validation checks including length verification, test number detection, and sequential/repeating pattern analysis.

The check recognizes country codes, validates format consistency, and uses contextual keywords to improve accuracy. It handles both domestic and international number formats while filtering out common test numbers and placeholder patterns.`,

		Patterns: []string{
			"US/Canada: (555) 123-4567, 555-123-4567, 5551234567",
			"International: +1 555 123 4567, +44 20 1234 5678",
			"UK: 0207 123 4567, +44 207 123 4567",
			"European: +33 1 42 34 56 78, +49 30 12345678",
			"Toll-free: 1-800-555-1234, (800) 555-1234, +1-800-555-1234",
			"With extensions: 555-123-4567 ext 123, +1-555-123-4567 x456",
			"Various separators: spaces, dashes, dots, parentheses",
		},

		SupportedFormats: []string{
			"US/Canada domestic (10 digits)",
			"US/Canada international (+1 XXX XXX XXXX)",
			"US/Canada toll-free (800, 833, 844, 855, 866, 877, 888)",
			"UK domestic (0XXX XXXXXXX)",
			"UK international (+44 XXX XXXXXXX)",
			"European international (+XX XXXX XXXX)",
			"Global mobile formats (+XXX XXXX XXXX)",
			"Legacy international (00XX XXXX XXXX)",
			"Extensions (ext, extension, x + 1-6 digits)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Valid Format", Description: "Must match recognized phone patterns", Weight: 18},
			{Name: "Reasonable Length", Description: "Must be 7-15 digits", Weight: 14},
			{Name: "Not Test Number", Description: "Must not match known test patterns", Weight: 18},
			{Name: "Valid Digits", Description: "Must contain valid phone characters", Weight: 9},
			{Name: "Not Sequential", Description: "Must not be sequential digits", Weight: 14},
			{Name: "Not Repeating", Description: "Must not have excessive repeating digits", Weight: 14},
			{Name: "Valid Country", Description: "Must match country format rules", Weight: 5},
			{Name: "Not Timestamp", Description: "Must not match timestamp patterns", Weight: 8},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file contacts.csv --checks PHONE",
			"ferret-scan --file customer-records.txt --confidence high | grep PHONE",
			"ferret-scan --file support-logs.json --verbose --checks PHONE",
		},
	}
}
