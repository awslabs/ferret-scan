// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the DRIVERS_LICENSE check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "DRIVERS_LICENSE",
		ShortDescription: "Detects driver's license numbers (US state shapes, GB DVLA, Ontario, Quebec) with keyword context",
		DetailedDescription: `The DRIVERS_LICENSE check detects driver's license numbers in eight US state shapes, Great Britain (DVLA) driver numbers, and Ontario and Quebec licences as printed, using shape patterns and contextual keyword analysis.

Because driver's license formats overlap heavily with generic numeric patterns (8-digit account numbers, 9-digit order IDs, etc.), this validator is extremely keyword-dependent: a shape alone scores 20 and is not reported. A candidate is reported only with licence vocabulary on its line (or a state name with "id" or "number"), a licence label alone on the line above it, or a licence column header, and DL-specific keywords raise it to actionable levels. Licence labels are matched in every spelling of driver, drivers, driver's or driving with license or licence, with or without "number" or "no", in any case or key style (driversLicense, driving_licence).

A finding's format names the shape it matched, not the jurisdiction that issued it: some states share a shape (NY_GA_9D is New York or Georgia), and a number from elsewhere with a US shape reports under that shape's name (a contiguous Ontario number as NJ_1L14D, a contiguous Quebec number as FL_MI_1L12D). A GB number must also fit the DVLA layout: surname letters then 9-padding, birth month 01-12 or 51-62, day 01-31, and initials.`,

		Patterns: []string{
			"1 letter + 7 digits (California)",
			"8 digits (Texas, Pennsylvania)",
			"1 letter + 12 digits (Florida, Michigan)",
			"9 digits (New York, Georgia)",
			"1 letter + 11 digits (Illinois)",
			"2 letters + 6 digits (Ohio)",
			"1 letter + 14 digits (New Jersey)",
			"1 letter + 13 digits (Wisconsin)",
			"The US shapes written with dashes or spaces (e.g. D123-4567-8901)",
			"GB DVLA driver number: 5 surname characters, 6 date digits, 2 initials, 1 digit, 2 check characters (16, or 18 with the issue number), contiguous or in 5/6/5 groups",
			"Ontario as printed: 1 letter + 4, 5 and 5 digits with hyphens (e.g. A1234-12345-12345)",
			"Quebec as printed: 1 letter + 4, 6 and 2 digits with hyphens (e.g. A1234-123456-12)",
		},

		// One entry per format value a finding can carry, the value first.
		SupportedFormats: []string{
			"CA_1L7D: California, 1 letter + 7 digits",
			"TX_PA_8D: Texas or Pennsylvania, 8 digits",
			"FL_MI_1L12D: Florida or Michigan, 1 letter + 12 digits",
			"NY_GA_9D: New York or Georgia, 9 digits",
			"IL_1L11D: Illinois, 1 letter + 11 digits",
			"OH_2L6D: Ohio, 2 letters + 6 digits",
			"NJ_1L14D: New Jersey, 1 letter + 14 digits",
			"WI_1L13D: Wisconsin, 1 letter + 13 digits",
			"GB_DVLA: Great Britain DVLA driver number",
			"CA_ON: Ontario, printed with hyphens",
			"CA_QC: Quebec, printed with hyphens",
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
