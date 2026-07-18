// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the DATE_OF_BIRTH check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "DATE_OF_BIRTH",
		ShortDescription: "Detects dates of birth in PII context",
		DetailedDescription: `The DATE_OF_BIRTH check detects dates that represent a person's date of birth based on contextual analysis.

Unlike generic date detection, this validator is extremely conservative: most dates are NOT dates of birth. A date is only flagged with meaningful confidence when it appears near DOB-specific keywords (e.g., "date of birth", "dob", "born", "birthday").

The validator supports multiple date formats including MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD, Month DD YYYY, and DD Month YYYY. It validates calendar correctness and restricts year ranges to plausible human lifetimes (1900-2025).

Dates near negative keywords (created, modified, expires, due, meeting, published, version, build) are strongly suppressed to prevent false positives on timestamps, deadlines, and metadata dates.`,

		Patterns: []string{
			"MM/DD/YYYY or DD/MM/YYYY (slash or hyphen separated)",
			"YYYY-MM-DD (ISO 8601 format)",
			"Month DD, YYYY (e.g., January 15, 1990)",
			"DD Month YYYY (e.g., 15 January 1990)",
			"Abbreviated months (Jan, Feb, Mar, etc.)",
		},

		SupportedFormats: []string{
			"Valid months: 01-12 or full/abbreviated names",
			"Valid days: 01-31 (respects per-month limits)",
			"Valid years: 1900-2025 (plausible human lifetime)",
			"Requires DOB-context keywords for meaningful confidence",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Valid Date", Description: "Must be a calendrically valid date", Weight: 10},
			{Name: "Plausible Year", Description: "Year must be in plausible DOB range (1900-2025)", Weight: 10},
			{Name: "Positive Keywords", Description: "DOB-specific keywords nearby (primary signal)", Weight: 60},
			{Name: "Negative Keywords", Description: "Non-DOB date keywords suppress confidence", Weight: 20},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file patient-records.txt --checks DATE_OF_BIRTH",
			"ferret-scan --file application-forms.pdf --checks DATE_OF_BIRTH --confidence high",
		},
	}
}
