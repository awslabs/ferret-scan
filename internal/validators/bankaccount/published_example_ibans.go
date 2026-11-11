// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import "github.com/awslabs/ferret-scan/v2/internal/detector"

// publishedExampleIBANs are IBANs a published source prints as a fictitious example, so that a
// document or a test can show one without naming a real account (#930). The compact, upper-case
// form, as isValidIBAN reads it.
//
// Admission follows the creditcard validator's published test numbers (#883,
// creditcard/published_test_pans.go): a value is listed only when the page that prints it says
// it is not a real account, the entry cites that page and the date it was read, and the value is
// not a positive of the golden or score corpus. Popularity in documentation is not enough, and no
// registry reserves IBAN values, so the list is short on purpose:
//
//   - The German example #930 also names is a positive of two golden cases
//     (new_validators_display_formats and new_validators_decoys, IBAN MEDIUM 80 and 60). Listing
//     it would move both snapshots, so it waits until those fixtures use another value.
//   - The SWIFT IBAN registry's per-country samples change between releases, so they are not a
//     stable list either (docs/proposals/CONFIDENCE_CONTRACT.md measured that).
//
// A listed value is capped, never dropped: it is still reported, so redaction still rewrites it,
// at no more than publishedExampleCeiling, and the ceiling is published so the document bridge
// cannot lift it back. The lookup is an exact match on the validated IBAN, so nothing in the
// scanned content can steer it, and a value one digit away is a different IBAN that keeps its score.
var publishedExampleIBANs = map[string]string{
	// https://en.wikipedia.org/wiki/International_Bank_Account_Number, "Validating the IBAN",
	// read 2026-11-11: "Example (fictitious United Kingdom bank, sort code 12-34-56, account number
	// 98765432)", printed as GB82 WEST 1234 5698 7654 32.
	"GB82WEST12345698765432": "Wikipedia IBAN article, fictitious United Kingdom bank example",
}

// publishedExampleCeiling is the confidence a published example IBAN is held to: the top of LOW,
// the number creditcard gives a published test card and otp a published test secret, so the
// three treat the same class of value alike.
const publishedExampleCeiling = 15.0

// capPublishedExample holds the IBAN finding m to publishedExampleCeiling when normalized, its
// compact upper-case form, is a published example, and records why: confidence_ceiling for the
// bridge and not_published_example=false in validation_checks for --explain. Any other finding
// is left exactly as it was, metadata included.
func capPublishedExample(m *detector.Match, normalized string) {
	if _, listed := publishedExampleIBANs[normalized]; !listed {
		return
	}
	if m.Confidence > publishedExampleCeiling {
		m.Confidence = publishedExampleCeiling
	}
	m.Metadata[confidenceCeilingKey] = publishedExampleCeiling
	if checks, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		checks["not_published_example"] = false
	}
}
