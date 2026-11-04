// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the SSN check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "SSN",
		ShortDescription: "Detects Social Security Numbers and ITINs in various formats",
		DetailedDescription: `The SSN check detects Social Security Numbers in documents and text files using pattern matching and contextual analysis.

It validates SSN format according to official Social Security Administration rules, rejecting the area numbers the SSA never issues as an SSN (000, 666, 900-999) and identifying test/placeholder SSNs. The validator uses contextual keywords to improve accuracy and reduce false positives.

It also reports IRS Individual Taxpayer Identification Numbers (ITIN) under their own type, ITIN. An ITIN is written like an SSN but begins with 9 and has 4th and 5th digits in 50-65, 70-88, 90-92 or 94-99. The separated forms 9XX-XX-XXXX and 9XX XX XXXX are always checked; nine bare digits, or half of a glued 18-digit run in a Word document, count as an ITIN only when the line or the column header says "ITIN" or "Individual Taxpayer Identification Number". The SSA advertising block 987-65-4320 to 987-65-4329 and 999-99-9999 are never reported.

The check looks for 9-digit numbers that may be formatted with hyphens or spaces in XXX-XX-XXXX or XXX XX XXXX patterns. It validates the area number, group number, and serial number components according to SSA rules.`,

		Patterns: []string{
			"XXX-XX-XXXX (standard hyphenated format)",
			"XXXXXXXXX (9 consecutive digits)",
			"XXX XX XXXX (space-separated format)",
			"9XX-XX-XXXX / 9XX XX XXXX (ITIN; bare 9XXXXXXXX only under an ITIN label)",
		},

		SupportedFormats: []string{
			"Valid area numbers: 001-665, 667-899",
			"Valid group numbers: 01-99",
			"Valid serial numbers: 0001-9999",
			"ITIN: area 900-999 with group 50-65, 70-88, 90-92 or 94-99",
			"Excludes known test patterns",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "Must be 9 digits in valid SSN format", Weight: 20},
			{Name: "Valid Area", Description: "Area number must be in valid range (for an ITIN, 900-999 with an ITIN group)", Weight: 15},
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
