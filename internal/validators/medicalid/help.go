// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the MEDICAL_ID check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "MEDICAL_ID",
		ShortDescription: "Detects medical identifiers (NPI, DEA, MRN, Insurance IDs, Medicare MBI, UK NHS and Scottish CHI numbers)",
		DetailedDescription: `The MEDICAL_ID check detects medical and healthcare identifiers in documents and text files using pattern matching, checksum validation, and contextual analysis.

It identifies five types of medical identifiers:
- NPI (National Provider Identifier): 10-digit numbers starting with 1 or 2, validated with Luhn checksum
- DEA (Drug Enforcement Administration) numbers: a registrant-type letter, the registrant's last-name initial or 9 (a business address), then 7 digits with the DEA check digit, in either case
- MRN (Medical Record Number): 6-10 digit institution-specific identifiers, detected only with strong medical context
- Insurance Member IDs: Alphanumeric 8-20 character strings with insurance/health plan context
- Medicare Beneficiary Identifier (MBI): 11-character strings in the CMS positional format, in either case

The validator prioritizes false-positive suppression: digit-only sequences (MRN) require strong medical context keywords, and structurally validated types (NPI, DEA) require checksum validity. A DEA number whose first letter is outside ` + deaUngatedRegistrantLetters + `, or whose second character is 9, is reported only beside DEA context (on the line, on a label line above, or in its column header), and a lowercase MBI only beside a Medicare-specific label (medicare, mbi, hicn and their compound keys).`,

		Patterns: []string{
			"NPI: 10 digits starting with 1 or 2 (Luhn validated)",
			"DEA: [" + deaRegistrantLetters + "] + a letter or 9 + 7 digits, either case (checksum validated)",
			"MRN: 6-10 digits (requires medical context keywords)",
			"Insurance Member ID: 8-20 alphanumeric chars (requires insurance context)",
			"Medicare MBI: 11 chars in the CMS C-A-AN-N-A-AN-N-A-A-N-N positional format, either case",
		},

		SupportedFormats: []string{
			"NPI numbers (National Provider Identifier)",
			"DEA registration numbers",
			"Medical Record Numbers (institution-specific)",
			"Health insurance member/subscriber IDs",
			"Medicare Beneficiary Identifiers (MBI, post-2018 format)",
			"UK NHS numbers (England, Wales, Isle of Man; Northern Ireland H&C numbers): 10 digits or 3-3-4, mod-11 check digit, reported only beside a label bound to the value (NHS number, nhs_number, a column header, the FHIR system, HL7 ^^^NHS^NH)",
			"Scottish CHI numbers: DDMMYY + 4 digits or 6-4, mod-11 check digit and a real date, reported only beside a label bound to the value (CHI number, chi_number, a column header)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Checksum (NPI)", Description: "Luhn checksum validation for NPI numbers", Weight: 30},
			{Name: "Checksum (DEA)", Description: "DEA-specific checksum validation", Weight: 35},
			{Name: "Checksum (NHS/CHI)", Description: "Mod-11 check digit, plus a real DDMMYY date for a CHI; the NHS test range 999 and repdigits are capped at 15", Weight: 30},
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
