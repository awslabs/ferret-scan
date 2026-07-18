// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the PHYSICAL_ADDRESS check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "PHYSICAL_ADDRESS",
		ShortDescription: "Detects US physical/mailing addresses including street addresses and PO Boxes",
		DetailedDescription: `The PHYSICAL_ADDRESS check detects US street addresses and PO Box addresses in documents and text files using pattern matching and contextual analysis.

It identifies addresses that contain a street number, street name, and a recognized street type suffix (St, Ave, Blvd, Dr, Ln, Ct, Rd, Way, Pkwy, Cir, Pl, Ter, Trl, Hwy, etc.). The minimum required for a match is street number + street name + street type. Without a recognized street type suffix, addresses are not matched to avoid false positives.

The validator also detects PO Box addresses in various formats (P.O. Box, PO Box, Post Office Box). Confidence is increased when city/state/ZIP information appears on the same or adjacent lines, and when address-related keywords appear nearby.

False positive suppression filters out IP addresses, version numbers, code line references, numbered list items, and mathematical expressions.`,

		Patterns: []string{
			"<number> <street name> <street type> (e.g., 123 Main St)",
			"<number> <multi-word name> <type>, <City>, <ST> <ZIP> (e.g., 456 Oak Ave, Austin, TX 78701)",
			"P.O. Box <number> / PO Box <number> / Post Office Box <number>",
			"Apartment/Suite/Unit indicators (Apt, Ste, Unit, #)",
		},

		SupportedFormats: []string{
			"US street addresses with recognized type suffixes",
			"PO Box in multiple formats",
			"ZIP codes: 5-digit and ZIP+4",
			"All 50 US states + DC abbreviations",
			"Multi-word street names",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Street Components", Description: "Street number + name + type suffix present", Weight: 50},
			{Name: "City/State/ZIP", Description: "City, state abbreviation, and ZIP on same or adjacent line", Weight: 30},
			{Name: "Address Keywords", Description: "Positive keywords like address, shipping, billing nearby", Weight: 15},
			{Name: "Apt/Suite/Unit", Description: "Apartment or suite indicator present", Weight: 10},
			{Name: "Negative Context", Description: "Test/example/mock keywords reduce confidence", Weight: -25},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file customer-data.txt --checks PHYSICAL_ADDRESS",
			"ferret-scan --file invoices/ --recursive --checks PHYSICAL_ADDRESS --confidence high",
		},
	}
}
