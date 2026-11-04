// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the VIN check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "VIN",
		ShortDescription: "Detects Vehicle Identification Numbers (VINs) in various formats",
		DetailedDescription: `The VIN check detects 17-character Vehicle Identification Numbers
using regex pattern matching combined with the standard check digit algorithm
(ISO 3779). The check digit is compulsory only in North America and China: there
a failed check digit rejects the VIN. Elsewhere a VIN without a valid check digit
is kept when its manufacturer code (WMI) is a known one, or when a VIN label sits
beside it, heads its column, or stands alone on the line above it. The validator
also scores manufacturer codes and model year encoding to minimize false
positives.`,

		Patterns: []string{
			"17-character alphanumeric string (excluding I, O, Q)",
			"Example: 1HGBH41JXMN109186",
		},

		SupportedFormats: []string{
			"Standard 17-character VIN (ISO 3779 / SAE J853)",
			"North America (regions 1-5 and 7) and China (H, L): position 9 check digit required",
			"Other regions: check digit optional; a VIN without one needs a known WMI or a VIN label",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "17 valid characters, no I/O/Q (base score)", Weight: 65},
			{Name: "Check Digit", Description: "Position 9 check digit passes mod-11; -10 when it fails where it is optional", Weight: 20},
			{Name: "Known WMI", Description: "Recognized manufacturer prefix", Weight: 10},
			{Name: "Model Year", Description: "Valid model year code at position 10", Weight: 5},
			{Name: "Context", Description: "Keywords on the line (+25 or -15 each), plus +25 for a VIN label that admitted a VIN with no check digit or known WMI; capped at +/-50", Weight: 50},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file vehicle-records.txt --checks VIN",
			"ferret-scan --file fleet-data.csv --checks VIN --confidence high",
		},
	}
}
