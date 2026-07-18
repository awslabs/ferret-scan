// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the MEDICAL_ID check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "MEDICAL_ID",
		ShortDescription: "Detects medical identifiers (NPI, DEA, MRN, Insurance IDs, Medicare MBI)",
		DetailedDescription: `The MEDICAL_ID check detects medical and healthcare identifiers in documents and text files using pattern matching, checksum validation, and contextual analysis.

It identifies five types of medical identifiers:
- NPI (National Provider Identifier): 10-digit numbers starting with 1 or 2, validated with Luhn checksum
- DEA (Drug Enforcement Administration) numbers: 2-letter prefix + 7 digits with DEA-specific checksum
- MRN (Medical Record Number): 6-10 digit institution-specific identifiers, detected only with strong medical context
- Insurance Member IDs: Alphanumeric 8-20 character strings with insurance/health plan context
- Medicare Beneficiary Identifier (MBI): 11-character strings with specific positional format

The validator prioritizes false-positive suppression: digit-only sequences (MRN) require strong medical context keywords, and structurally validated types (NPI, DEA) require checksum validity.`,

		Patterns: []string{
			"NPI: 10 digits starting with 1 or 2 (Luhn validated)",
			"DEA: [ABCDFGM][A-Z] + 7 digits (checksum validated)",
			"MRN: 6-10 digits (requires medical context keywords)",
			"Insurance Member ID: 8-20 alphanumeric chars (requires insurance context)",
			"Medicare MBI: 11 chars in C-A-N-N/A-A-N-A-N-N/A-A-N positional format",
		},

		SupportedFormats: []string{
			"NPI numbers (National Provider Identifier)",
			"DEA registration numbers",
			"Medical Record Numbers (institution-specific)",
			"Health insurance member/subscriber IDs",
			"Medicare Beneficiary Identifiers (MBI, post-2018 format)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Checksum (NPI)", Description: "Luhn checksum validation for NPI numbers", Weight: 30},
			{Name: "Checksum (DEA)", Description: "DEA-specific checksum validation", Weight: 35},
			{Name: "Format (MBI)", Description: "Positional character-class format validation", Weight: 25},
			{Name: "Context Keywords", Description: "Medical/healthcare keywords nearby", Weight: 20},
			{Name: "Negative Context", Description: "Non-medical keywords suppress confidence", Weight: 15},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file patient-records.txt --checks MEDICAL_ID",
			"ferret-scan --file claims-data.csv --checks MEDICAL_ID --confidence high",
		},
	}
}
