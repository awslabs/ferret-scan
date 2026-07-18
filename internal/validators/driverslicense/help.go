// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the DRIVERS_LICENSE check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "DRIVERS_LICENSE",
		ShortDescription: "Detects US driver's license numbers by state format with keyword context",
		DetailedDescription: `The DRIVERS_LICENSE check detects US driver's license numbers from the top 10 states by population using state-specific format patterns and contextual keyword analysis.

Because driver's license formats overlap heavily with generic numeric patterns (8-digit account numbers, 9-digit order IDs, etc.), this validator is extremely keyword-dependent: a pattern match alone produces very low confidence (20). DL-specific keywords must be present on the same line to raise confidence to actionable levels.

Supported state formats:
- California: 1 letter + 7 digits (e.g. D1234567)
- Texas/Pennsylvania: 8 digits
- Florida/Michigan: 1 letter + 12 digits
- New York/Georgia: 9 digits
- Illinois: 1 letter + 11 digits
- Ohio: 2 letters + 6 digits`,

		Patterns: []string{
			"1 letter + 7 digits (California)",
			"8 digits (Texas, Pennsylvania)",
			"1 letter + 12 digits (Florida, Michigan)",
			"9 digits (New York, Georgia)",
			"1 letter + 11 digits (Illinois)",
			"2 letters + 6 digits (Ohio)",
		},

		SupportedFormats: []string{
			"California: 1 letter + 7 digits",
			"Texas: 8 digits",
			"Florida: 1 letter + 12 digits",
			"New York: 9 digits",
			"Pennsylvania: 8 digits",
			"Illinois: 1 letter + 11 digits",
			"Ohio: 2 letters + 6 digits",
			"Georgia: 9 digits",
			"Michigan: 1 letter + 12 digits",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format Match", Description: "Pattern matches a known state DL format", Weight: 20},
			{Name: "DL Keyword", Description: "DL-specific keyword present on line (+45)", Weight: 45},
			{Name: "State Name", Description: "State name present adds boost (+20)", Weight: 20},
			{Name: "DL Prefix", Description: "Explicit DL:/Driver's License: prefix (+75)", Weight: 75},
			{Name: "Negative Keywords", Description: "Non-DL keywords suppress (-20)", Weight: -20},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file applicant-records.txt --checks DRIVERS_LICENSE",
			"ferret-scan --file identity-docs/ --recursive --checks DRIVERS_LICENSE --confidence high",
		},
	}
}
