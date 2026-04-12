// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the VIN check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "VIN",
		ShortDescription: "Detects Vehicle Identification Numbers (VINs) in various formats",
		DetailedDescription: `The VIN check detects 17-character Vehicle Identification Numbers
using regex pattern matching combined with the standard check digit algorithm
(ISO 3779). The validator verifies format, check digit correctness, known
manufacturer codes (WMI), and model year encoding to minimize false positives.`,

		Patterns: []string{
			"17-character alphanumeric string (excluding I, O, Q)",
			"Example: 1HGBH41JXMN109186",
		},

		SupportedFormats: []string{
			"Standard 17-character VIN (ISO 3779 / SAE J853)",
			"North American (position 9 check digit validated)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "17 valid characters, no I/O/Q", Weight: 20},
			{Name: "Check Digit", Description: "Position 9 check digit passes mod-11", Weight: 25},
			{Name: "Known WMI", Description: "Recognized manufacturer prefix", Weight: 15},
			{Name: "Model Year", Description: "Valid model year code at position 10", Weight: 10},
			{Name: "Context", Description: "Surrounding keywords", Weight: 30},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file vehicle-records.txt --checks VIN",
			"ferret-scan --file fleet-data.csv --checks VIN --confidence high",
		},
	}
}
