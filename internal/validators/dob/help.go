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

Unlike generic date detection, this validator is extremely conservative: most dates are NOT dates of birth. A date is only flagged with meaningful confidence when it appears near DOB-specific keywords (e.g., "date of birth", "dob", "born", "birthday"). Keywords are matched as labels, so camelCase and concatenated keys such as "dateOfBirth" and "patientDob" count as "date of birth" and "patient dob".

The validator supports multiple date formats including MM/DD/YYYY, DD/MM/YYYY, YYYY-MM-DD, Month DD YYYY, and DD Month YYYY, with slash, hyphen or dot separators and two-digit years. It validates calendar correctness and restricts years to plausible human lifetimes (1900 to the current year).

A further set of shapes is reported only when an explicit DOB label ends at most 8 separator bytes before the value ("Date of Birth: ", "DOB ", {"dob": "...}, <DateOfBirth>): ISO 8601 date-times (the date part is the finding), year-first dates with slash or dot (1987/03/14), unpadded ISO dates (1987-3-14), and month names in any case or order (14-MAR-1987, 14MAR1987, MARCH 14, 1987, Mar. 14, 1987, Sept, 14th of March 1987, 1987 March 14). Those shapes are common in timestamps and file names, so the same value without an adjacent label is not reported at all.

Dates near negative keywords (created, modified, expires, due, meeting, published, version, build) are strongly suppressed to prevent false positives on timestamps, deadlines, and metadata dates.`,

		Patterns: []string{
			"MM/DD/YYYY or DD/MM/YYYY (slash, hyphen or dot separated; also 2-digit years)",
			"YYYY-MM-DD (ISO 8601 date)",
			"Month DD, YYYY (e.g., January 15, 1990)",
			"DD Month YYYY (e.g., 15 January 1990)",
			"Abbreviated months (Jan, Feb, Mar, etc.)",
			"After an adjacent DOB label only: ISO 8601 date-time (YYYY-MM-DDTHH:MM..., date part reported)",
			"After an adjacent DOB label only: YYYY/MM/DD, YYYY.MM.DD, YYYY-M-D",
			"After an adjacent DOB label only: month names in any case or order (14-MAR-1987, 14MAR1987, Mar. 14, 1987, 14th of March 1987, 1987 March 14)",
		},

		SupportedFormats: []string{
			"Valid months: 01-12 or full/abbreviated names",
			"Valid days: 01-31 (respects per-month limits)",
			"Valid years: 1900 to the current year (plausible human lifetime)",
			"Requires DOB-context keywords for meaningful confidence",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Valid Date", Description: "Must be a calendrically valid date", Weight: 10},
			{Name: "Plausible Year", Description: "Year must be in plausible DOB range (1900 to the current year)", Weight: 10},
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
