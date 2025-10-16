// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the passport check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "PASSPORT",
		ShortDescription: "Detects passport numbers from various countries",
		DetailedDescription: `The Passport check detects passport numbers from various countries including US, UK, Canada, EU, and Machine Readable Zone (MRZ) formats.

It uses pattern matching to identify potential passport numbers and then performs validation checks to determine the confidence level. The validator also analyzes surrounding context to improve accuracy and reduce false positives.

The check looks for country-specific patterns and validates them against known passport number formats. It also considers contextual clues to distinguish between actual passport numbers and other similar alphanumeric strings.`,

		Patterns: []string{
			"US passport: 1 letter followed by 8 digits (e.g., A12345678)",
			"UK passport: 9 digits (e.g., 123456789)",
			"Canadian passport: 2 letters followed by 6 digits (e.g., AB123456)",
			"EU passport: 2 letters followed by 7 alphanumeric characters (e.g., DE1234567)",
			"Machine Readable Zone (MRZ) formats",
		},

		SupportedFormats: []string{
			"US passport format",
			"UK passport format",
			"Canadian passport format",
			"EU passport format",
			"Generic passport format (6-10 alphanumeric characters)",
			"Machine Readable Zone (MRZ) format",
			"MRZ TD3 format",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "Must match country-specific pattern", Weight: 30},
			{Name: "Length", Description: "Must have correct length for the country", Weight: 20},
			{Name: "Valid Characters", Description: "Must have valid characters for passport numbers", Weight: 15},
			{Name: "Test Number", Description: "Must not be a known test number", Weight: 15},
			{Name: "Sequential", Description: "Must not be sequential or repeated characters", Weight: 10},
			{Name: "False Positive", Description: "Must not match common non-passport patterns", Weight: 25},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file travel-documents.txt --confidence high,medium",
			"ferret-scan --file customer-data.txt --format json --output passports.json",
		},
	}
}
