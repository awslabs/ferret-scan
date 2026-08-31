// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// MultiCheckCases extends the corpus beyond SSN to every validator that fires on
// plain text with the default configuration.
//
// The first version of this package scored SSN only, which made the headline
// numbers look authoritative while 18 of the tool's 19 checks were unmeasured. The
// machinery was never SSN-specific — the registry (registry.go) is the only
// coupling — so this file is data, not mechanism.
//
// Every value here was verified against the real CLI before being labelled, and the
// recorded MinBand is what the tool actually produces today. Nothing is aspirational:
// TestEveryLabelIsSatisfiedToday rejects a label no version of the tool satisfies,
// so the recall denominator cannot be padded with wishes.
//
// Coverage and its gaps, measured 2026-08-05:
//
//	scored here (15): BANK_ACCOUNT, CLOUD_RESOURCES, CREDIT_CARD, DATE_OF_BIRTH,
//	                  DRIVERS_LICENSE, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS,
//	                  MEDICAL_ID, PASSPORT, PERSON_NAME, PHONE, PHYSICAL_ADDRESS,
//	                  SECRETS, VIN
//	scored elsewhere: SSN (cases_ssn.go, 91 cases), METADATA (container cases —
//	                  it needs a real file, not a string)
//	NOT scored (2):   OTP, SOCIAL_MEDIA. Both WORK; they simply
//	                  need a case shape this corpus does not carry yet. See
//	                  UnscoredChecks in registry.go for the root cause of each,
//	                  and TestUnscoredChecksAreAccountedFor, which fails if a check
//	                  is neither scored nor explained.
//
// The negative cases are as important as the positives. Precision is only
// measurable against values that LOOK like PII and are not: an order reference that
// fails Luhn, a policy effective date, a build-system notification address.
var MultiCheckCases = []Case{
	{
		Name:   "person_hyphen_both_parts",
		Origin: "authored 2026-08 for scorecorpus; was quarantined as a known leak, fixed same day",
		Rationale: "A hyphen in BOTH the given name and the surname. This was a real cleartext " +
			"leak: no pattern spanned the whole name, so two overlapping partials were " +
			"reported and redaction wrote \"Reviewed by Anne-********************\", leaving " +
			"the given name in the clear. Fixed by adding the compound_first_and_hyphenated_last " +
			"pattern. Hyphenated surnames are common and disproportionately non-Anglo, so a " +
			"recall gap here is not an edge case.",
		Checks: []string{"PERSON_NAME"},
		Input: "Reviewed by Anne-Marie Delacroix-Webb on Tuesday.\n" +
			"Contact Mary-Jane Watson-Parker today\n",
		Labels: []Label{
			{Line: 1, Value: "Anne-Marie Delacroix-Webb", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 2, Value: "Mary-Jane Watson-Parker", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:   "person_hyphen_first_multiword_last",
		Origin: "authored 2026-08 for scorecorpus; second half of the same leak",
		Rationale: "A hyphenated given name with a multi-token surname carrying a nobiliary " +
			"particle. Same root cause as person_hyphen_both_parts and the same leak shape: " +
			"redaction wrote \"Signed: Jean-****************\". four_part_name already covered " +
			"the unhyphenated \"Jean Claude Van Damme\", so only the combination was missing.",
		Checks: []string{"PERSON_NAME"},
		Input:  "Signed: Jean-Claude Van Damme\n",
		Labels: []Label{
			{Line: 1, Value: "Jean-Claude Van Damme", Types: []string{"PERSON_NAME"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:   "ip_public_routable",
		Origin: "authored 2026-08 for scorecorpus; values verified against the real CLI",
		Rationale: "A routable public address in a log line identifies a host and often a " +
			"person behind it. This is the shape IP_ADDRESS exists for.",
		Checks: []string{"IP_ADDRESS"},
		Input: "Origin host 13.52.11.22 rejected the request.\n" +
			"peer 52.94.236.248 connected\n",
		Labels: []Label{
			{Line: 1, Value: "13.52.11.22", Types: []string{"IP_ADDRESS"}, MinBand: BandHigh},
			{Line: 2, Value: "52.94.236.248", Types: []string{"IP_ADDRESS"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:   "ip_negative_reserved_ranges",
		Origin: "authored 2026-08 for scorecorpus; behavior verified against the real CLI",
		Rationale: "RFC 5737 documentation ranges (192.0.2.x, 198.51.100.x, 203.0.113.x) and " +
			"well-known public resolvers (8.8.8.8, 1.1.1.1) must NOT be reported: they appear " +
			"in every tutorial, README and config sample, and flagging them would bury real " +
			"findings in noise. This case exists because the FIRST draft of this corpus probed " +
			"IP_ADDRESS using only these addresses, concluded the validator was broken, and " +
			"was wrong. The exclusion is deliberate (nonSensitiveNets), and now it is pinned.",
		Checks: []string{"IP_ADDRESS"},
		Input: "docs example 203.0.113.47 and 198.51.100.22\n" +
			"resolver 8.8.8.8 and 1.1.1.1\n" +
			"sample 192.0.2.5 in the tutorial\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "bank_routing_and_account",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A routing+account pair is everything needed to move money.",
		Checks:    []string{"BANK_ACCOUNT"},
		Input:     "Routing number 021000021 account 1234567890 for payroll.\n",
		Labels: []Label{
			{Line: 1, Value: "1234567890", Types: []string{"US_BANK_ACCOUNT"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "cloud_s3_arn",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "An ARN naming a production bucket is infrastructure disclosure.",
		Checks:    []string{"CLOUD_RESOURCES"},
		Input:     "arn:aws:s3:::acme-prod-invoices\n",
		Labels: []Label{
			{Line: 1, Value: "arn:aws:s3:::acme-prod-invoices", Types: []string{"AWS_ARN"}, MinBand: BandLow},
		},
		Redactable: true,
	},
	{
		Name:      "card_visa_prose",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A Luhn-valid Visa beside an expiry is a payment card, not a random number.",
		Checks:    []string{"CREDIT_CARD"},
		Input:     "Card on file 4532015112830366 exp 04/28.\n",
		Labels: []Label{
			{Line: 1, Value: "4532015112830366", Types: []string{"VISA"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "card_amex_prose",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "AMEX is 15 digits, a different shape the same validator must cover.",
		Checks:    []string{"CREDIT_CARD"},
		Input:     "AMEX 374245455400126 authorised for the deposit.\n",
		Labels: []Label{
			{Line: 1, Value: "374245455400126", Types: []string{"AMERICAN_EXPRESS"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "card_spaced_groups",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "Cards are usually written in four-digit groups.",
		Checks:    []string{"CREDIT_CARD"},
		Input:     "Payment 4532 0151 1283 0366 cleared.\n",
		Labels: []Label{
			{Line: 1, Value: "4532 0151 1283 0366", Types: []string{"VISA"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:       "card_negative_luhn_fail",
		Origin:     "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale:  "A 16-digit order reference that FAILS the Luhn check is not a payment card. The checksum is value-intrinsic evidence and must be respected.",
		Checks:     []string{"CREDIT_CARD"},
		Input:      "order reference 4532015112830367 shipped\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "dob_iso_labelled",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "An explicitly labelled DOB is health/HR PII.",
		Checks:    []string{"DATE_OF_BIRTH"},
		Input:     "Patient DOB: 1978-03-14 confirmed at intake.\n",
		Labels: []Label{
			{Line: 1, Value: "1978-03-14", Types: []string{"DATE_OF_BIRTH"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:       "dob_negative_effective_date",
		Origin:     "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale:  "A policy effective date is not a date of birth. Any ISO date must not become health PII.",
		Checks:     []string{"DATE_OF_BIRTH"},
		Input:      "Policy effective date: 2024-01-01 through 2024-12-31\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "dl_labelled",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A labelled licence number is government-issued ID.",
		Checks:    []string{"DRIVERS_LICENSE"},
		Input:     "Driver License Number: D1234567 expires 2027.\n",
		Labels: []Label{
			{Line: 1, Value: "D1234567", Types: []string{"DRIVERS_LICENSE"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:      "email_business_prose",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A work address in ordinary prose is the commonest PII in a document.",
		Checks:    []string{"EMAIL"},
		Input:     "Contact alice.morgan@northwind-labs.com for access.\n",
		Labels: []Label{
			{Line: 1, Value: "alice.morgan@northwind-labs.com", Types: []string{"BUSINESS"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "email_csv_column",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "An email column in an export; the whole column is PII.",
		Checks:    []string{"EMAIL"},
		Input: "name,email,dept\n" +
			"A Morgan,alice.morgan@northwind-labs.com,Finance\n" +
			"B Osei,bola.osei@northwind-labs.com,Legal\n",
		Labels: []Label{
			{Line: 2, Value: "alice.morgan@northwind-labs.com", Types: []string{"BUSINESS"}, MinBand: BandHigh},
			{Line: 3, Value: "bola.osei@northwind-labs.com", Types: []string{"BUSINESS"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "email_negative_machine",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "Build-system notification addresses are machine identities, not people. Reporting them at HIGH trains reviewers to ignore EMAIL findings, which is how a real address gets waved through.",
		Checks:    []string{"EMAIL"},
		Input: "from: noreply@build-system.internal\n" +
			"to: ci-notifications@build-system.internal\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "ip_trade_secret_banner",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "An explicit trade-secret banner marks the document as restricted.",
		Checks:    []string{"INTELLECTUAL_PROPERTY"},
		Input:     "CONFIDENTIAL - TRADE SECRET: formula 7A\n",
		Labels: []Label{
			{Line: 1, Value: "CONFIDENTIAL - TRADE SECRET: formula 7A", Types: []string{"INTELLECTUAL_PROPERTY"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:      "medical_npi_labelled",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A labelled NPI identifies a provider on a claim.",
		Checks:    []string{"MEDICAL_ID"},
		Input:     "Provider NPI: 1234567893 on the claim.\n",
		Labels: []Label{
			{Line: 1, Value: "1234567893", Types: []string{"NPI"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "passport_labelled",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A labelled passport number is travel-document PII.",
		Checks:    []string{"PASSPORT"},
		Input:     "Passport No: X12345678 issued 2019.\n",
		Labels: []Label{
			{Line: 1, Value: "X12345678", Types: []string{"PASSPORT"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "person_prose_byline",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A named individual in a document byline is personal data.",
		Checks:    []string{"PERSON_NAME"},
		Input:     "Prepared by Margaret Chen, senior analyst.\n",
		Labels: []Label{
			{Line: 1, Value: "Margaret Chen", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
		},
		Redactable: true,
	},

	{
		Name:      "phone_us_parens",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "The most common written US phone format.",
		Checks:    []string{"PHONE"},
		Input:     "Call the desk at (312) 726-4401 before noon.\n",
		Labels: []Label{
			{Line: 1, Value: "(312) 726-4401", Types: []string{"PHONE"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "phone_dashed",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "Dashed form, no parentheses.",
		Checks:    []string{"PHONE"},
		Input:     "Direct line 415-892-3307 for escalations.\n",
		Labels: []Label{
			{Line: 1, Value: "415-892-3307", Types: []string{"PHONE"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:       "phone_negative_version",
		Origin:     "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale:  "A dotted version string and a reserved 555-01xx placeholder are not contact numbers.",
		Checks:     []string{"PHONE"},
		Input:      "build 10.1.2.3 released; ticket 555-0100 is a placeholder\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "address_us_street",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A street address locates a person.",
		Checks:    []string{"PHYSICAL_ADDRESS"},
		Input:     "Ship to 1600 Amphitheatre Parkway, Mountain View, CA 94043\n",
		Labels: []Label{
			{Line: 1, Value: "1600 Amphitheatre Parkway", Types: []string{"US_STREET_ADDRESS"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "secret_github_token",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A live-shaped GitHub token is a credential leak.",
		Checks:    []string{"SECRETS"},
		Input:     "github_token=" + fakeGitHubToken + "\n",
		Labels: []Label{
			{Line: 1, Value: fakeGitHubToken, Types: []string{"GITHUB_TOKEN"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:      "secret_aws_access_key",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "An AWS access key id in a config file. This one is AWS's published documentation placeholder, so the band it lands in is a policy decision, not an accident.",
		Checks:    []string{"SECRETS"},
		Input:     "AWS_ACCESS_KEY_ID=" + fakeAWSAccessKeyID + "\n",
		Labels: []Label{
			// BandLow, lowered from BandMedium by #364. MinBand records what the tool
			// produces TODAY, and a documentation placeholder is now capped at 15 (top
			// of LOW) so surrounding context cannot present it as a real credential.
			//
			// The label is kept rather than deleted, and that is the point of this
			// case: BandLow still requires the value to be REPORTED, and only reported
			// findings reach the redactor. If the demotion ever turns into a drop this
			// label becomes FN(miss) — a genuine cleartext leak — instead of passing
			// quietly. Redactable: true below puts it through the sink gate too.
			{Line: 1, Value: fakeAWSAccessKeyID, Types: []string{"AWS_ACCESS_KEY"}, MinBand: BandLow},
		},
		Redactable: true,
	},
	{
		Name:      "secret_negative_plain_kv",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "Ordinary key=value config with no credential shape must stay silent, or every config file becomes noise.",
		Checks:    []string{"SECRETS"},
		Input: "log_level=debug\n" +
			"service_name=invoice-worker\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:      "vin_labelled",
		Origin:    "authored 2026-08 for scorecorpus; value verified against the real CLI",
		Rationale: "A VIN identifies a specific vehicle and its owner records.",
		Checks:    []string{"VIN"},
		Input:     "VIN: 1HGBH41JXMN109186 on the title.\n",
		Labels: []Label{
			{Line: 1, Value: "1HGBH41JXMN109186", Types: []string{"VIN"}, MinBand: BandHigh},
		},
		Redactable: true,
	}}

// MultiCheckQuarantine holds shapes whose correct label is not settled, or that the
// tool provably cannot satisfy today. Counted and printed, never scored.
//
// A quarantined case is not a case that was dropped: the count is baselined, so
// moving something in or out of this list changes a number and fails the gate until
// the change is explained.
// MultiCheckQuarantine holds shapes whose correct label is not settled, or that the
// tool provably cannot satisfy today. Counted and printed, never scored.
//
// Currently EMPTY. It held person_hyphenated until 2026-08-05, when the underlying
// validator bug was fixed and the case was promoted into MultiCheckCases as three
// scored labels. That is the intended lifecycle: quarantine records a real gap, the
// gap gets fixed, the case graduates and the recall floor rises so it cannot regress.
//
// The list is kept rather than deleted, and its size is baselined, so adding a case
// here is a visible, explained change and not a quiet way to drop a failing one.
var MultiCheckQuarantine = []Case{}
