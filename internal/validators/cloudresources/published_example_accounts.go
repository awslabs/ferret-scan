// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import "github.com/awslabs/ferret-scan/v2/internal/detector"

// publishedExampleAWSAccounts are AWS account ids a published AWS page prints as the example
// account in its ARN examples, so that a document or a test can show an ARN without naming a
// real account (#1027, part of #930).
//
// Admission follows the bankaccount validator's published example IBAN (#971) and the medicalid
// published example NPI: a value is listed only when the page that prints it presents it as an
// example, the entry cites that page and the date it was read, and the list stays short on purpose.
//
// A match whose account id is listed is capped, never dropped: it is still reported, so redaction
// still rewrites it, at no more than publishedExampleCeiling, and the ceiling is published so the
// document bridge cannot lift it back. The lookup is an exact match on the 12-digit account field
// of the ARN, so nothing else in the scanned content can steer it, and an ARN with any other
// account, one digit away included, keeps its score.
var publishedExampleAWSAccounts = map[string]string{
	// AWS IAM User Guide, "IAM identifiers", https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html,
	// read 2026-11-19: the "Examples" list under "IAM ARNs" prints every ARN with account
	// 123456789012 (arn:aws:iam::123456789012:role/S3Access and the rest).
	"123456789012": "AWS IAM User Guide, IAM identifiers, ARN examples",
}

// publishedExampleCeiling is the confidence a published example is held to: the top of LOW, the
// number bankaccount gives the published example IBAN and creditcard a published test card.
const publishedExampleCeiling = 15.0

// confidenceCeilingKey is the Match.Metadata key the document bridge reads to keep a validator's
// cap from being lifted (validators.ConfidenceCeilingKey).
const confidenceCeilingKey = "confidence_ceiling"

// capPublishedExampleAccount holds the AWS_ARN match m to publishedExampleCeiling when its account
// id is a published example, recording why in confidence_ceiling. Any other match is left exactly
// as it was, metadata included.
func capPublishedExampleAccount(m *detector.Match) {
	if m.Type != "AWS_ARN" {
		return
	}
	if _, listed := publishedExampleAWSAccounts[extractAWSAccountID(m.Text)]; !listed {
		return
	}
	if m.Confidence > publishedExampleCeiling {
		m.Confidence = publishedExampleCeiling
	}
	m.Metadata[confidenceCeilingKey] = publishedExampleCeiling
}
