// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "strings"

// publishedExampleSecrets are credential values that a vendor or standards owner prints as a worked
// example, so that documentation and tests can show one without naming a real account (#930).
//
// The pattern is medicalid/published_example_npis.go (#996) and bankaccount's published example IBAN
// (#971): a value is listed only when a page its publisher owns presents it as an example, the entry
// names that page and the date it was read, and popularity in other people's code is not enough, so the
// list is short on purpose. The AWS example access key ID is not here: provider_rules.go and
// awsDocPlaceholderCap already hold it, and the other AWS credential types, by the EXAMPLE marker.
//
// A listed value is capped, never dropped: it is still reported, so redaction still rewrites it, at no
// more than publishedExampleCeiling, and the ceiling is published (ConfidenceCeilingKey) so the document
// bridge cannot lift it back. The lookup is an EXACT match on the whole candidate, so a real credential
// with the example text beside it keeps its score, and any value one character away is not listed: this
// is not the substring rule awsDocPlaceholderCap cannot extend to the generic type.
var publishedExampleSecrets = map[string]string{
	// AWS, STS API reference, GetAccessKeyInfo, read 2026-11-18: "a secret access key (for example,
	// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)".
	// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html
	// Held at 15 on the AWS-secret path since #364; this entry holds it on the generic path, where
	// `secret = "<value>"` read API_KEY_OR_SECRET 100.
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS STS API reference, GetAccessKeyInfo",

	// Stripe, the changelog entry "Adds a demographic information hash to the Persons API", read
	// 2026-11-18: `curl https://api.stripe.com/v1/accounts/acct_xxxxx/persons -u "sk_test_…:"`.
	// https://docs.stripe.com/changelog/basil/2025-04-30/add-us-cfpb-data-to-person
	"sk_test_4eC39HqLyjWDarjtT1zdp7dc": "Stripe documentation, API changelog example",

	// Stripe's own stripe-js README, read 2026-11-18: `loadStripe('pk_test_…')`, "We've placed a
	// random API key in this example. Replace it with your actual publishable API keys".
	// https://github.com/stripe/stripe-js
	"pk_test_TYooMQauvdEDq54NiTphI7jx": "Stripe stripe-js README, loadStripe example",

	// Google, the google-authenticator wiki, "Key Uri Format", Examples, read 2026-11-18: the first
	// example provisions a TOTP key with `secret=JBSWY3DPEHPK3PXP&issuer=Example`, and the page says
	// the Base32 key decodes to the bytes of `Hello!` and four fixed bytes.
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	"JBSWY3DPEHPK3PXP": "Google Authenticator Key Uri Format wiki, example TOTP secret",
}

// publishedExampleCeiling is the top of LOW, the number creditcard gives a published test card,
// bankaccount a published example IBAN and medicalid a published example NPI.
const publishedExampleCeiling = 15.0

// publishedExampleCap returns publishedExampleCeiling when match, with the quote characters a
// capture may carry trimmed, is a listed published example, and 0 otherwise.
func publishedExampleCap(match string) float64 {
	if _, listed := publishedExampleSecrets[strings.Trim(match, `"'`)]; listed {
		return publishedExampleCeiling
	}
	return 0
}
