// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "github.com/awslabs/ferret-scan/v2/internal/detector"

// publishedExampleNPIs are NPIs a published source prints as a worked example, so that a document
// or a test can show one without naming a real provider (#930).
//
// Admission follows the bankaccount validator's published example IBAN (#971,
// bankaccount/published_example_ibans.go): a value is listed only when the page that prints it
// presents it as an example rather than a provider, the entry cites that page and the date it was
// read, and the value is not a positive of the golden or score corpus. Popularity in documentation is
// not enough, so the list is short on purpose.
//
// A listed value is capped, never dropped: it is still reported, so redaction still rewrites it, at
// no more than publishedExampleCeiling, and the ceiling is published so the document bridge cannot
// lift it back. The lookup is an exact match on the 10-digit candidate, so nothing in the scanned
// content can steer it, and any other NPI, an NPI-Luhn-valid value two digits away included, keeps
// its score (published_example_npis_test.go).
var publishedExampleNPIs = map[string]string{
	// CMS, "Requirements for National Provider Identifier (NPI) and NPI Check Digit" (January 23,
	// 2004), https://www.cms.gov/Regulations-and-Guidance/Administrative-Simplification/NationalProvIdentStand/Downloads/NPIcheckdigit.pdf,
	// read 2026-11-11: the worked example ends "NPI with check digit = 1234567893".
	"1234567893": "CMS NPI check-digit specification, worked example",
}

// publishedExampleCeiling is the confidence a published example NPI is held to: the top of LOW, the
// number bankaccount gives the published example IBAN and creditcard a published test card, so the
// validators treat the same class of value alike.
const publishedExampleCeiling = 15.0

// capPublishedExampleNPI returns the NPI finding m held to publishedExampleCeiling when its text is
// a published example, recording why: confidence_ceiling for the bridge and
// not_published_example=false in validation_checks for --explain. Any other finding is returned
// exactly as it was, metadata included.
func capPublishedExampleNPI(m detector.Match) detector.Match {
	if _, listed := publishedExampleNPIs[m.Text]; !listed {
		return m
	}
	if m.Confidence > publishedExampleCeiling {
		m.Confidence = publishedExampleCeiling
	}
	m.Metadata["confidence_ceiling"] = publishedExampleCeiling
	if checks, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		checks["not_published_example"] = false
	}
	return m
}
