// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the credit card check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "CREDIT_CARD",
		ShortDescription: "Detects credit card numbers from major card providers",
		DetailedDescription: `The Credit Card check detects credit card numbers from major providers and automatically identifies specific credit card types for better categorization.

It uses pattern matching to identify potential credit card numbers and then performs validation checks to determine the confidence level. The validator also analyzes surrounding context to improve accuracy and reduce false positives.

The check looks for 16-digit numbers (15 for American Express) that may be formatted with spaces or dashes between groups of 4 digits. It validates the numbers using the Luhn algorithm and identifies the specific card type based on the number pattern.

**Supported Credit Card Types:**
- **VISA** - Cards starting with 4
- **MASTERCARD** - Cards starting with 5 (51-55) or 2221-2720 range
- **AMERICAN_EXPRESS** - Cards starting with 34 or 37
- **DISCOVER** - Cards starting with 6011, 65, or 644-649 range
- **DINERS_CLUB** - Cards starting with 30, 36, or 38
- **JCB** - Cards starting with 35
- **UNIONPAY** - Cards starting with 62
- **MAESTRO** - Cards starting with 50 or 56-58 range
- **PRIVATE_LABEL_CARD** - Cards starting with 8 (private label or regional cards)
- **CREDIT_CARD** - Generic type for unrecognized patterns`,

		Patterns: []string{
			"4 groups of 4 digits (e.g., 1234 5678 9012 3456)",
			"16 consecutive digits (e.g., 1234567890123456)",
			"4 groups of 4 digits with dashes (e.g., 1234-5678-9012-3456)",
		},

		SupportedFormats: []string{
			"Visa (starts with 4)",
			"MasterCard (starts with 51-55, 2221-2720)",
			"American Express (starts with 34 or 37)",
			"Discover (starts with 6011 or 65)",
			"JCB (starts with 35, 2131, or 1800)",
			"Diners Club (starts with 30, 36, or 38)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Length", Description: "Must be 16 digits (15 for AmEx)", Weight: 15},
			{Name: "Digits", Description: "Must contain only digits", Weight: 20},
			{Name: "Vendor", Description: "Must match a known card vendor pattern", Weight: 25},
			{Name: "Luhn", Description: "Must pass the Luhn checksum algorithm", Weight: 20},
			{Name: "Test Number", Description: "Must not be a known test number", Weight: 10},
			{Name: "Sequential", Description: "Must not be sequential digits", Weight: 10},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file financial-data.txt --confidence high",
			"ferret-scan --file logs.txt --verbose | grep CREDIT_CARD",
		},
	}
}
