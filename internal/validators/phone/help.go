// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the phone check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	positive := make([]string, 0, len(phoneEvidenceTokens)+len(phoneEvidencePhrases))
	positive = append(positive, phoneEvidenceTokens...)
	positive = append(positive, phoneEvidencePhrases...)

	return help.CheckInfo{
		Name:             "PHONE",
		ShortDescription: "Detects phone numbers in various international formats",
		DetailedDescription: `The Phone check detects phone numbers using multiple pattern matching approaches for different international formats.

It supports US/Canada, UK, European, and international phone number formats with various separators (spaces, dashes, dots, parentheses). The validator performs validation checks including length verification, test number detection, and sequential/repeating pattern analysis.

Confidence comes from phone evidence on the match's line: each phone word (phone, tel, mobile, fax, call, ...) or phrase (phone number, contact no, direct line, ...) adds 15, as do a phone label on the value ("Office: ..."), a phone column header in a CSV or TSV, and a formatted toll-free area code; a match with none loses 20, and each negative word (test, example, serial, ...) costs 35. Words count only as whole words outside the number, in any case. The adjustment stays between -80 and +40. A match nothing corroborates (and not written in the + form) never scores above 85, and a reserved fictional number (555-0100 to 555-0199) never above 15, in any document. A ten-digit number the North American plan cannot assign (area or exchange code starting 0 or 1, or an N11 area code) is still reported, without the US/Canada label or the country bonus.`,

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
			{Name: "Reasonable Length", Description: "7-15 digits, a leading + counted as one (-15 otherwise); a + or 00 number is also held to E.164 and capped at 15 when its country code is unassigned or it has more than 15 digits, or when its national length is not one its code's plan allows and no phone evidence is on its line", Weight: 14},
			{Name: "Not Test Number", Description: "Must not match known test patterns", Weight: 18},
			{Name: "Valid Digits", Description: "Must contain valid phone characters", Weight: 9},
			{Name: "Not Sequential", Description: "Must not be sequential digits", Weight: 14},
			{Name: "Not Repeating", Description: "Must not have excessive repeating digits", Weight: 14},
			{Name: "Valid Country", Description: "+5 when the number fits its country's plan; 0 for a ten-digit number the North American plan cannot assign; -10 for any other misfit", Weight: 5},
			{Name: "Not Timestamp", Description: "Must not match timestamp patterns", Weight: 8},
		},

		PositiveKeywords: positive,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file contacts.csv --checks PHONE",
			"ferret-scan --file customer-records.txt --confidence high | grep PHONE",
			"ferret-scan --file support-logs.json --verbose --checks PHONE",
		},
	}
}
