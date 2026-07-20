// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the BANK_ACCOUNT check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "BANK_ACCOUNT",
		ShortDescription: "Detects bank account numbers, routing numbers, IBANs, and SWIFT/BIC codes",
		DetailedDescription: `The BANK_ACCOUNT check detects banking-related identifiers in documents and text files using pattern matching, checksum validation, and contextual analysis.

It identifies the following types of banking data:
- US ABA routing numbers (9 digits with valid prefix and checksum)
- US bank account numbers (8-17 digits in banking context)
- IBAN (International Bank Account Number) with mod-97 checksum validation
- SWIFT/BIC codes (8 or 11 character bank identifiers)

The validator uses strict structural validation before keyword boosting: ABA routing numbers are checksum-verified, IBANs are validated with mod-97, and SWIFT codes are checked against ISO country codes. US bank account numbers require banking keywords nearby to avoid flagging arbitrary digit sequences.`,

		Patterns: []string{
			"NNNNNNNNN (9-digit ABA routing number with checksum)",
			"CCNN + up to 30 alphanumeric (IBAN with mod-97 validation)",
			"BBBBCCLLBBB (8 or 11 char SWIFT/BIC code)",
			"NNNNNNNN-NNNNNNNNNNNNNNNNN (8-17 digit US bank account in context)",
		},

		SupportedFormats: []string{
			"ABA: first 2 digits 01-32 or 61-72 or 80, checksum validated",
			"IBAN: 70+ country formats validated with correct length and mod-97",
			"SWIFT: 4 bank letters + 2 country + 2 location + optional 3 branch",
			"US Account: 8-17 digits requiring banking keyword context",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Checksum", Description: "ABA/IBAN pass mathematical checksum", Weight: 30},
			{Name: "Format", Description: "Matches expected structural format", Weight: 20},
			{Name: "Country Validation", Description: "Valid ISO country code for IBAN/SWIFT", Weight: 15},
			{Name: "Context Keywords", Description: "Banking keywords nearby boost confidence", Weight: 25},
			{Name: "Not Test Number", Description: "Not a known test routing number", Weight: 10},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file financial-records.txt --checks BANK_ACCOUNT",
			"ferret-scan --file wire-transfers.csv --checks BANK_ACCOUNT --confidence high",
		},
	}
}
