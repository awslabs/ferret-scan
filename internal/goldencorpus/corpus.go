// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package goldencorpus provides the behavior-locking regression net for the v2
// consolidation (Phase 0 in docs/proposals/V2_ARCHITECTURE.md). It scans a
// curated set of representative and adversarial inputs through the REAL scan and
// formatting paths (core.ScanContent + formatters.Export + pkg/redact) and
// snapshots the output to committed golden files.
//
// The purpose is NOT to assert that any particular detection is "correct" — it
// is to assert that detection, confidence scoring, output formats, and redaction
// do not CHANGE as the internal architecture is consolidated. Any diff against a
// golden file during a refactor is a signal to stop and confirm the change is
// intended (then regenerate with UPDATE_GOLDEN=1), rather than a silent
// behavioral regression.
//
// Determinism: the scan pipeline aggregates matches in goroutine-completion
// order, and a couple of formatters embed wall-clock timestamps. This package
// canonicalizes match order (CanonicalSort) and normalizes timestamps
// (NormalizeOutput) so snapshots are byte-stable across runs.
package goldencorpus

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// Case is one corpus entry: a named input plus the validator set to run against
// it. Keeping checks explicit per-case (rather than always "all") makes each
// snapshot small, focused, and stable — adding a new validator does not churn
// every unrelated golden file.
type Case struct {
	// Name is a filesystem-safe identifier used for the golden filename.
	Name string
	// Description documents what behavior this case is meant to lock.
	Description string
	// Checks is the validator set to enable (nil/empty means "all").
	Checks []string
	// Input is the content scanned via core.ScanContent.
	Input string
}

// Cases is the curated corpus. It deliberately mixes:
//   - representative positives (real-shaped secrets/PII that SHOULD match),
//   - negatives / known false-positive guards (test values that must NOT match),
//   - adversarial / pathological shapes (single very long line, many matches,
//     dense punctuation) that exercise the DoS-prone scanning paths.
//
// SSNs use realistic, non-denylisted values (e.g. 449-87-4100); well-known fakes
// like 123-45-6789 are intentionally used only where a NEGATIVE is expected.
var Cases = []Case{
	{
		Name:        "mixed_pii_basic",
		Description: "Representative multi-type document: email, phone, AWS key, valid SSN, credit card.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD"},
		Input: "Contact john.doe@example.com or call 212-555-0142.\n" +
			"AWS key AKIAIOSFODNN7EXAMPLE in the config.\n" +
			"SSN 449-87-4100 on file.\n" +
			"Card 4532-0151-1283-0366 expires soon.\n",
	},
	{
		Name:        "email_variants",
		Description: "Business vs personal-domain emails; locks EMAIL confidence tiers.",
		Checks:      []string{"EMAIL"},
		Input: "support@acme-corp.com\n" +
			"alice@gmail.com\n" +
			"no-reply@internal.example.org\n" +
			"not.an.email.at.all\n",
	},
	{
		Name:        "ssn_positive_and_denylisted",
		Description: "A realistic SSN must match; the canonical fake 123-45-6789 must be rejected as a false positive.",
		Checks:      []string{"SSN"},
		Input: "real: 449-87-4100\n" +
			"fake-should-not-match: 123-45-6789\n" +
			"sequential-should-not-match: 111-11-1111\n",
	},
	{
		Name:        "creditcard_brands",
		Description: "Luhn-valid cards across brands; locks brand classification in Match.Type.",
		Checks:      []string{"CREDIT_CARD"},
		Input: "visa 4532015112830366\n" +
			"mastercard 5425233430109903\n" +
			"amex 374245455400126\n" +
			"invalid-luhn 4532015112830367\n",
	},
	{
		Name: "creditcard_phone_overlap",
		Description: "A space-separated card the PHONE validator also fires on (its trailing " +
			"groups look like a phone number). Locks the overlap fix: format-preserving " +
			"redaction must mask the whole card including the BIN (**** **** **** 0366), " +
			"not just the head — the contained PHONE match must not win the tail and hide " +
			"the card's un-redacted BIN. A standalone phone on the next line must still redact.",
		Checks: []string{"CREDIT_CARD", "PHONE"},
		Input: "card 4532 0151 1283 0366 here\n" +
			"call 212-555-0142 today\n",
	},
	{
		Name:        "secrets_aws",
		Description: "AWS access key + secret-key shaped strings; locks SECRETS detection and confidence.",
		Checks:      []string{"SECRETS"},
		Input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
			"just_a_word=hello\n",
	},
	{
		Name:        "ip_addresses",
		Description: "Public vs private/loopback IPv4; locks IP_ADDRESS context handling.",
		Checks:      []string{"IP_ADDRESS"},
		Input: "server 203.0.113.42 reached\n" +
			"localhost 127.0.0.1 ignored-ish\n" +
			"private 10.0.0.5 internal\n" +
			"version string 1.2.3.4 maybe\n",
	},
	{
		Name:        "negative_clean_text",
		Description: "Ordinary prose with no secrets; the no-finding case must stay empty.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD", "IP_ADDRESS"},
		Input: "The quick brown fox jumps over the lazy dog.\n" +
			"Meeting at 3pm to discuss the roadmap for version 2.\n",
	},
	{
		Name:        "adversarial_single_long_line",
		Description: "One very long single line (~8KB) with an embedded email — exercises the per-line scanning path the audit flagged as O(n^2)-prone. Locks (a) that the scan completes (with bounded execution it cannot hang) and (b) the CURRENT detection outcome on this shape, whatever it is, so a future refactor that changes long-line handling is flagged.",
		Checks:      []string{"EMAIL"},
		Input:       longLineWithEmbeddedEmail(),
	},
	{
		Name:        "adversarial_many_matches",
		Description: "Twelve emails across twelve lines — exercises high match counts and aggregation ordering without bloating the committed fixtures.",
		Checks:      []string{"EMAIL"},
		Input:       manyEmails(12),
	},
	{
		Name:        "cloud_resources_test_context",
		Description: "Same AWS IAM-role ARN on two lines: one clean, one carrying a same-line test-context keyword (\"example\"). Locks the CLOUD_RESOURCES negative-keyword penalty (-20, per-line/local), the behavior the per-line hasKeywordToken hoist must preserve.",
		Checks:      []string{"CLOUD_RESOURCES"},
		Input: "prod arn:aws:iam::123456789012:role/PaymentsAdmin\n" +
			"example arn:aws:iam::123456789012:role/PaymentsAdmin\n",
	},
	{
		Name: "new_validators_display_formats",
		Description: "Card/print display formats for the new validators: dashed MBI (as printed " +
			"on Medicare cards), space-grouped IBAN (invoice format), dashed DL, dotted and " +
			"2-digit-year DOB, ordinal street name, highway with route number, lowercase address " +
			"with keyword context. Locks the separator-normalization and format-coverage behavior " +
			"added after the recall-gap audit.",
		Checks: []string{"MEDICAL_ID", "BANK_ACCOUNT", "DRIVERS_LICENSE", "DATE_OF_BIRTH", "PHYSICAL_ADDRESS"},
		Input: "medicare beneficiary 1EG4-TE5-MK73 on card\n" +
			"pay to IBAN DE89 3704 0044 0532 0130 00 per invoice\n" +
			"driver's license D123-4567-8901 verified\n" +
			"patient dob 3/14/87 and sibling born March 14th, 1987\n" +
			"admission date of birth 03.14.1987 on form\n" +
			"ship to 123 42nd Street, New York, NY 10036\n" +
			"mailing address 1234 US Highway 61\n" +
			"deliver to 742 evergreen terrace, springfield, il 62704\n",
	},
	{
		Name: "validator_coverage_expansion",
		Description: "Formats added in the coverage-expansion pass: military APO/FPO (PSC/Unit + " +
			"Box + APO/FPO/DPO + AA/AE/AP + ZIP), rural routes (full and Box-anchored short " +
			"forms), apostrophe/hyphen street names, NJ (1L+14D) and WI (1L+13D) licenses, and " +
			"lowercase base32 OTP secrets (keyword-gated, word-guarded). Decoy lines lock the " +
			"guards: RR-as-abbreviation stays LOW, APO-as-word and prose apostrophes stay out, " +
			"lowercase English prose is not a secret.",
		Checks: []string{"PHYSICAL_ADDRESS", "DRIVERS_LICENSE", "OTP"},
		Input: "mail to PSC 1523, Box 25, APO AE 09009 promptly\n" +
			"mailing Rural Route 3 Box 88, Roanoke, VA 24012\n" +
			"send to 123 O'Brien St, Boston, MA 02101\n" +
			"deliver 456 King-Smith Rd today\n" +
			"new jersey driver license D12345678901234 on record\n" +
			"wisconsin dl J1234567890123 verified\n" +
			// Not the otpauth documentation secret this used to be. That value is now
			// capped at the top of LOW as a published test secret, which would have
			// left this case asserting the cap instead of the lowercase detection pass
			// it exists for. See otp/published_secret_test.go.
			"2fa secret: k5cuwy3znrxw4z3t lowercase\n" +
			"The package weighs RR 4 lbs on the scale\n" +
			"APO is an abbreviation for Apollo\n" +
			"123 O' clock reading on the dial\n" +
			"the authentication protocol requires base configuration\n",
	},
	{
		Name: "new_validators_decoys",
		Description: "Shape-valid values in PII-contradicting context for the new validators' " +
			"broadest patterns: SSN-shaped and date-shaped tokens near DL keywords, a version " +
			"string near DOB keywords, test-context IBAN/routing numbers, an MBI shape without " +
			"medicare context, and prose that embeds lowercase suffix words. Locks the " +
			"suppression behavior (shape guards, denylists, keyword gates) that keeps the " +
			"normalization passes from widening the false-positive surface.",
		Checks: []string{"MEDICAL_ID", "BANK_ACCOUNT", "DRIVERS_LICENSE", "DATE_OF_BIRTH", "PHYSICAL_ADDRESS"},
		Input: "license check ssn 123-45-6789 cross-reference\n" +
			"license issued 12-31-1987 expires 12-31-2031\n" +
			"zip on license record 12345-6789\n" +
			"upgrade dob service to version 2.14.87 build\n" +
			"test iban DE89 3704 0044 0532 0130 00 example fixture\n" +
			"routing 021000021 test transfer\n" +
			"shape only 1EG4-TE5-MK73 without context\n" +
			"5 people way too many for the room\n" +
			"3 items in way of progress\n",
	},
	{
		Name: "medical_long_form_labels",
		Description: "Long-form field labels as printed on physical insurance/Medicare cards and " +
			"used in EDI 837 exports (\"member identification number\") alongside the abbreviated " +
			"forms already covered (\"member id\"). Keyword matching is whole-token, so the " +
			"abbreviations did not cover the long forms: the card's own wording scored the MBI " +
			"and MRN LOW, and an all-uppercase insurance ID was dropped entirely (the strong " +
			"keyword gates the uppercase-shape check), which meant it passed through redaction " +
			"in cleartext. Decoy lines lock the deliberate exclusions: a bare \"certificate " +
			"number\" names an X.509 certificate and \"policy identification\" names an IAM or " +
			"Terraform policy far more often than an insurance one, so neither is a keyword.",
		Checks: []string{"MEDICAL_ID"},
		Input: "member identification number: W1234567801\n" +
			"subscriber identification number: X9876543210\n" +
			"medicare member identification number: 1EG4TE5MK73\n" +
			"patient identification number: 4472901\n" +
			"policyholder id: P5551234567\n" +
			"member id: W1122009988\n" +
			"X.509 certificate serial number: 0A1B2C3D4E5F6789\n" +
			"policy identification for terraform module: MODULEVERSION123\n",
	},
	{
		Name: "keyword_separator_forms",
		Description: "The same field labels written with the separators real files use: " +
			"snake_case config keys, kebab-case column headers, tab-separated exports and " +
			"space-padded aligned columns. Keyword matching split a multi-word keyword on a " +
			"literal space only, so \"member id\" covered none of \"member_id\", \"member-id\" or " +
			"\"member\\tid\" — and because the strong keyword gates the uppercase-shape check " +
			"rather than merely boosting confidence, a labelled ID written the snake_case way " +
			"produced no finding at all and passed through redaction in cleartext. Decoy lines " +
			"lock the exclusions: '.' and '/' are NOT separators, because they cross sentence " +
			"and URL boundaries where the two words are unrelated. The last two lines pin that " +
			"the outer whole-word rule still applies at both ends of the separator-flexible " +
			"match. " +
			"LINE 6, THE RUN-TOGETHER FORM, IS A FINDING SINCE #372, and how it got there is " +
			"the part worth keeping. camelCase is the default key style of JSON, REST payloads " +
			"and ORM exports, and text is lowercased before matching, so \"memberId\" and " +
			"\"memberid\" are the same string: in a two-key object one member ID sat in " +
			"cleartext beside its redacted twin. But the fix is NOT that a keyword space now " +
			"means \"zero or more separators\" everywhere — that was tried and it LEAKED. The " +
			"suppressor \"ip address\" began matching \"ipAddress\", an ordinary JSON key, and " +
			"that veto is unconditional, so a real member ID beside it was silenced and written " +
			"back in cleartext. So the widened form is OPT-IN (kwmatch.ContainsLabel) and only " +
			"positive label lists use it; every suppressor still requires a separator, which is " +
			"why the four decoy lines below stay silent and why '.' and '/' — a recorded " +
			"false-positive measurement — are untouched in both modes. medicalid opts in, which " +
			"is what makes line 6 report here.",
		Checks: []string{"MEDICAL_ID"},
		Input: "member_id: W1234567801\n" +
			"member-id: X9876543210\n" +
			"member\tid: W1122009988\n" +
			"subscriber_id: X5556667778\n" +
			"member  id: W3344556677\n" +
			"memberid: W9998887776\n" +
			"see member.id in the schema docs: W1231231234\n" +
			"https://example.com/member/id/lookup?q=W4564564567\n" +
			"remember id: W7897897890\n" +
			"member idx column: W3213213210\n",
	},
	{
		Name: "medical_hex_member_ids",
		Description: "Insurance member IDs whose characters happen to all be hex digits, beside " +
			"hex decoys that must stay suppressed. The all-hex shape gate used to fire before " +
			"the strong-keyword check, so a labelled ID like \"member id: E1122334455\" produced " +
			"no finding at all and passed through redaction in cleartext with exit code 0 — real " +
			"IDs are commonly a letter prefix plus digits and 6 of 26 leading letters are hex, " +
			"so this was a whole slice of that shape. The keyword alone cannot lift the gate, " +
			"because a digest genuinely does appear beside a member-id label; casing is the " +
			"discriminator, since hex digests are conventionally all-lowercase (git SHAs, " +
			"sha256sum, HTTP etags) while a card-printed ID is not. Lines 1-5 must be detected " +
			"and redacted; lines 6-9 must stay clean. Line 10 pins the subtype arbitration a " +
			"valid DEA (2 letters + 7 digits, so entirely hex) must win over INSURANCE_MEMBER_ID " +
			"— the old gate had been suppressing that duplicate by accident.",
		Checks: []string{"MEDICAL_ID"},
		Input: "member id: E1122334455\n" +
			"member id: ABCDEF123456\n" +
			"member id: BEEF1234567\n" +
			"subscriber id: 1234567890AB\n" +
			"member id: 55DEADBEEF12\n" +
			"commit 9462e98abcdef1234567890abcdef1234567890a\n" +
			"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4\n" +
			"member id verification hash: 1234abcd5678ef90\n" +
			"cache blob 0xDEADBEEF12345678 evicted\n" +
			"insurance member id for prescriber: AB1234563\n",
	},
	{
		Name: "context_decoys_original",
		Description: "Real-context vs decoy-context pairs for the ORIGINAL validators (SSN, " +
			"PHONE, CREDIT_CARD, EMAIL): the same shaped value framed as PII on one line and " +
			"as a part number / error code / SKU on another. Locks CURRENT context-scoring " +
			"behavior including known warts — e.g. SSN-shaped part numbers today score the " +
			"same as real SSNs (no context discrimination). A future context-scoring change " +
			"must show up here as an intentional diff, not slip through silently.",
		Checks: []string{"SSN", "PHONE", "CREDIT_CARD", "EMAIL"},
		Input: "employee ssn 449-87-4100 on file\n" +
			"part number 449-87-4100 from the catalog\n" +
			"requisition 526-33-8210 approved for shipment\n" +
			"call us at 212-555-0142 today\n" +
			"error code 212-555-0142 in the diagnostics log\n" +
			"SKU 313-555-0175 restocked\n",
	},
	{
		Name: "ip_consolidation_long_line",
		Description: "A single ~8KB line of ~63 concatenated AWS slide footers — the shape PDF " +
			"text extraction produces when every slide carries the same copyright/confidential " +
			"footer (user-reported: one finding whose Text was the entire 11,871-char line). " +
			"Locks the bounded consolidated match text (\"<primary> [+N more matches on line]\", " +
			"<= 256 bytes, match_text_truncated=true) AND that redaction still masks the ENTIRE " +
			"line (redactors.RestoreBoundedMatchText restores the full-line span before masking).",
		Checks: []string{"INTELLECTUAL_PROPERTY"},
		Input:  repeatedFooterLine(8000),
	},
	{
		Name: "context_decoys_personname",
		Description: "Multi-line document (PERSON_NAME is document-length sensitive) mixing " +
			"real person references with decoy name-shaped strings: geographic features " +
			"(Jordan River), products (Lincoln Continental), and companies (Amazon Web " +
			"Services) that share surface shape with person names. Locks CURRENT " +
			"disambiguation behavior, whatever it is, so future name-context changes " +
			"surface as intentional diffs.",
		Checks: []string{"PERSON_NAME"},
		Input: "Contact Maria Delgado for approval\n" +
			"the Jordan River flows north\n" +
			"Please forward the report to James Whitfield by Friday\n" +
			"Lincoln Continental parked outside\n" +
			"Sarah Okonkwo will present the quarterly results\n" +
			"Amazon Web Services launched\n" +
			"Schedule a review with Daniel Moreau next week\n" +
			"the Hudson Valley orchard shipped apples\n" +
			"Priya Raghavan approved the budget request\n" +
			"Ford Mustang sales rose sharply\n",
	},
	{
		Name: "context_soft_negative_labels",
		Description: "Real PII labelled with an identifier word that is a SOFT suppressor " +
			"(account/order for CREDIT_CARD, patient-account for MEDICAL_ID MRN). Locks the " +
			"two-tier negative fix: a soft label must NOT hard-drop a real value when a strong " +
			"positive keyword co-occurs (card word / MRN keyword), so lines 1-2 stay HIGH. " +
			"Lines 4-5 (bare IMEI decoy, bare 'order id' label) are suppressed to zero by the " +
			"keyword and then held at the CREDIT_CARD intrinsic-value floor of 15.00 LOW rather " +
			"than erased: a keyword is document content, so letting one zero out a Luhn-valid PAN " +
			"let anyone who could add a word to a line both hide the card and skip redaction " +
			"(threat model TM-11). Demotion to the bottom of LOW is the intended outcome; " +
			"disappearance is not. A regression that reinstates the old -100 hard-drop shows up " +
			"here as lines 4-5 vanishing; one that ignores the keyword shows up as them returning " +
			"to HIGH.",
		Checks: []string{"CREDIT_CARD", "MEDICAL_ID"},
		Input: "Order 5678 paid with card 4532015112830366\n" +
			"Account Number for visa 5425233430109903\n" +
			"Patient account number: 1234567 on chart\n" +
			"imei 490154203237518 on the handset\n" +
			"order id: 4532015112830366 catalog\n",
	},
	{
		Name: "context_keywords_snake_case",
		Description: "Context keywords carried by snake_case / SCREAMING_SNAKE identifiers rather " +
			"than spaced prose — the dominant shape in the code and config files this tool scans. " +
			"Locks the fix for '_' being treated as a word byte, which made keyword matching miss " +
			"inside an identifier in BOTH directions: positive keywords did not boost " +
			"(customer_ssn / my_dob_field scored as bare numbers) and negative keywords did not " +
			"suppress (a Luhn-valid card in TEST_/_test fixture context stayed MEDIUM). Each line " +
			"here has a spaced counterpart in the cases above, and the two must score the same; a " +
			"regression that reinstates '_' as a word byte shows up as the underscore lines " +
			"dropping back to bare-value confidence. The two card lines land at the CREDIT_CARD " +
			"intrinsic-value floor of 15.00 LOW: the keyword suppressed them to zero, and the floor " +
			"then keeps them emitted so redaction still covers them (TM-11). Note what the " +
			"pre-floor snapshot of this very case recorded -- 'TEST_CARD_NUMBER = 4532015112830366' " +
			"and 'account_number_test: 4012888888881881' survived --enable-redaction in cleartext, " +
			"because redaction can only rewrite what was reported.",
		Checks: []string{"SSN", "CREDIT_CARD", "DATE_OF_BIRTH"},
		Input: "customer_ssn: 449-87-4100\n" +
			"SSN_VALUE=449-87-4101\n" +
			"my_dob_field: 1985-03-14\n" +
			"TEST_CARD_NUMBER = 4532015112830366\n" +
			"account_number_test: 4012888888881881\n" +
			"sample_ssn = 449-87-4102\n",
	},
	{
		Name: "passport_csv_header_column",
		Description: "A pure delimited export whose ONLY passport label is the header row. PASSPORT is " +
			"label-gated and its label search stops at the newline, so before header-aware " +
			"context this produced zero findings on every data row while the identical text " +
			"written inline as 'Passport Number: 987654321' scored HIGH -- and an unreported " +
			"value is never handed to the redactor, so the redacted output kept every passport " +
			"number in cleartext. Four data rows on purpose: a fix that only reaches the first " +
			"one leaves the rest of the export leaking. The email column is present so the case " +
			"also shows the pre-fix state was not 'nothing detected' but 'the wrong things " +
			"detected'.",
		Checks: []string{"PASSPORT", "EMAIL"},
		Input: "name,email,passport_number,country\n" +
			"Jane,jane.smith@acmecorp.io,987654321,US\n" +
			"Bob,bob.jones@acmecorp.io,512345678,GB\n" +
			"Amy,amy.lee@acmecorp.io,512345671,CA\n" +
			"Sam,sam.roe@acmecorp.io,987654322,AU\n",
	},
	{
		Name: "passport_shapes",
		Description: "PASSPORT had ZERO golden coverage, so nothing here was gated at all. Locks the " +
			"labelled 9-digit form, the ICAO 9303 TD3 machine-readable zone, and two negatives " +
			"(an unlabelled bare number, and a labelled value on a line that says 'sample'). " +
			"The MRZ line is deliberately included because the MRZ and MRZ_TD3 patterns OVERLAP " +
			"by construction -- MRZ_TD3's {39} sits inside MRZ's {38,40} -- so one physical " +
			"document is claimed by two patterns. The snapshot records ONE row for that line: " +
			"span arbitration keeps the outermost claim. Before that arbitration existed the " +
			"same MRZ was reported twice, so this row is also the gate that catches the " +
			"duplicate coming back.",
		Checks: []string{"PASSPORT"},
		Input: "Passport Number: 512345678\n" +
			"passport no 987654321\n" +
			"P<GBRSMITH<<JOHN<ALBERT<<<<<<<<<<<<<<<<<<<<<\n" +
			"512345670\n" +
			"passport 123456789 sample data\n",
	},
	{
		Name: "passport_label_above_value",
		Description: "The cross-line shape: a label on its own line with the value on the next, which " +
			"is how a form, a config block and every CSV export are written. PASSPORT is " +
			"label-GATED -- it reports nothing without a nearby label -- and the label search " +
			"stops at the newline, so all three of these currently produce NOTHING while the " +
			"identical text inline scores HIGH. Snapshotted as the CURRENT (leaking) behavior on " +
			"purpose: an unreported value is never handed to the redactor, so this case is the " +
			"gate that will show a cross-line context fix working, and will fail loudly if such " +
			"a fix regresses.",
		Checks: []string{"PASSPORT"},
		Input: "passport_number\n" +
			"987654321\n" +
			"Field: Passport Number\n" +
			"Value: 512345678\n" +
			"name,email,passport_number,country\n" +
			"Jane,jane.smith@acmecorp.io,512345671,US\n",
	},
	{
		Name: "vin_check_digit",
		Description: "VIN had ZERO golden coverage. Locks that the ISO 3779 check digit (position 9) " +
			"is actually verified: the first and third VINs are valid and must be reported, the " +
			"fourth is the first VIN with its check digit incremented and must NOT be. That pairing " +
			"is what makes this non-vacuous -- a snapshot of positives alone would still pass if " +
			"check-digit validation were deleted.",
		Checks: []string{"VIN"},
		Input: "vin 1HGCM82633A004352\n" +
			"vehicle identification number 2FMDK3GC4BBA12345\n" +
			"VIN: JH4KA7561PC008269\n" +
			"vin 1HGCM82633A004353\n",
	},
	{
		Name: "passport_mrz_line2_check_digits",
		Description: "A complete ICAO 9303 TD3 machine-readable zone: line 1 (the holder's NAME) " +
			"followed by line 2 (the passport NUMBER, date of birth, sex, expiry and personal " +
			"number). Line 2 was matched by NOTHING, so on the most ordinary passport shape " +
			"there is -- a scan or OCR pipeline emits both lines -- line 1 was redacted and " +
			"line 2 passed through in cleartext. The redaction snapshot is the real gate here. " +
			"The fourth line is the same line 2 with ONE check digit corrupted and must NOT be " +
			"reported: the 44-character pattern matches any run of MRZ characters, so the five " +
			"7-3-1 check digits are the only thing separating a passport from a base32 secret. " +
			"Pairing them is what makes this case non-vacuous -- a snapshot of the positive " +
			"alone would still pass if check-digit validation were deleted.",
		Checks: []string{"PASSPORT"},
		Input: "P<GBRSMITH<<JOHN<ALBERT<<<<<<<<<<<<<<<<<<<<<\n" +
			"L898902C36GBR7408122M1204159ZE184226B<<<<<10\n" +
			"corrupted check digit, must not be reported:\n" +
			"L898902C30GBR7408122M1204159ZE184226B<<<<<10\n",
	},
}

// FileCase is one file-based corpus entry. Unlike Case (which scans an in-memory
// string via core.ScanContent), a FileCase is written to a real file on disk and
// scanned via core.ScanFile — exercising the worker pool, the FileRouter,
// CanProcessFile/CanContainMetadata routing, and (for metadata-bearing types)
// the dual-path metadata branch that core.ScanContent skips entirely.
type FileCase struct {
	// Name is a filesystem-safe identifier used for the golden filename.
	Name string
	// Description documents what file-path behavior this case locks.
	Description string
	// Checks is the validator set to enable (nil/empty means "all").
	Checks []string
	// Filename is the basename written into the temp dir. Its EXTENSION drives
	// FileRouter routing (text vs metadata-capable), so it is significant.
	Filename string
	// Content is written verbatim to the file as bytes.
	Content []byte
	// Tier1Parity, when true, asserts that file-mode findings equal
	// content-mode (core.ScanContent) findings for the same bytes — the
	// file-path-specific machinery must not change WHICH matches are produced
	// for plain-text/source inputs. Only valid for non-metadata file types.
	Tier1Parity bool
	// EnablePreprocessors must be true for binary/metadata-capable file types
	// (e.g. .wav): CanProcessFile rejects binary documents unless preprocessors
	// are enabled. Plain-text/source cases leave this false (the CLI default).
	EnablePreprocessors bool
}

// FileCases is the Tier 1 + Tier 2 file corpus.
//
//	Tier 1 (text/source): fully deterministic, no binaries, no external
//	  extraction libs. Exercises ScanFile -> worker pool -> FileRouter ->
//	  non-metadata dual-path branch. Asserts file-mode == content-mode parity.
//	Tier 2 (metadata-bearing, generated in-test): a deterministically
//	  constructed file whose metadata branch can be exercised without
//	  committing an opaque binary. See metadata determinism note in NormalizeOutput.
//
// Snapshotting third-party PDF/Office *extraction byte-output* is intentionally
// OUT OF SCOPE (it would lock library behavior, not ferret-scan's, and require
// committed binaries). See README.md "What it does NOT cover".
var FileCases = []FileCase{
	// --- Tier 1: text / source-code files (deterministic, parity-checked) ---
	{
		Name:        "file_txt_mixed_pii",
		Description: "Tier 1: a .txt file with mixed PII through the full ScanFile/worker-pool path. Parity-checked against ScanContent.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD"},
		Filename:    "notes.txt",
		Content: []byte("Contact john.doe@example.com or call 212-555-0142.\n" +
			"AWS key AKIAIOSFODNN7EXAMPLE in the config.\n" +
			"SSN 449-87-4100 on file.\n" +
			"Card 4532-0151-1283-0366 expires soon.\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_source_code_secrets",
		Description: "Tier 1: a .go source file with an embedded secret + email — locks source-code routing (must NOT take the metadata path).",
		Checks:      []string{"SECRETS", "EMAIL"},
		Filename:    "config.go",
		Content: []byte("package config\n\n" +
			"// owner: ops@example.com\n" +
			"const AWSKey = \"AKIAIOSFODNN7EXAMPLE\"\n" +
			"const Secret = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_json_config",
		Description: "Tier 1: a .json config with PII — locks structured-text routing and parity.",
		Checks:      []string{"EMAIL", "IP_ADDRESS"},
		Filename:    "settings.json",
		Content: []byte("{\n" +
			"  \"admin_email\": \"admin@example.com\",\n" +
			"  \"server_ip\": \"203.0.113.42\",\n" +
			"  \"note\": \"no secrets here\"\n" +
			"}\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_negative_clean",
		Description: "Tier 1: a clean .txt with no PII — file-mode no-finding case must stay empty.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD", "IP_ADDRESS"},
		Filename:    "readme.txt",
		Content:     []byte("The quick brown fox jumps over the lazy dog.\nNothing sensitive here.\n"),
		Tier1Parity: true,
	},
	// --- Tier 2: metadata-bearing file, generated deterministically in-test ---
	// A CSV is plain text (so no external extractor / no binary), but exercises
	// the FileRouter's metadata-capability decision and the dual-path routing
	// for a "data" file type. This locks the routing branch without committing
	// an opaque binary. (PDF/Office/image extraction byte-output is out of scope
	// per the README; here we lock our routing + validation, not a 3rd-party lib.)
	{
		Name:        "file_csv_tabular_pii",
		Description: "Tier 2: a .csv with PII columns — exercises FileRouter routing for a data file and locks detection through ScanFile.",
		Checks:      []string{"EMAIL", "SSN", "CREDIT_CARD"},
		Filename:    "people.csv",
		Content: []byte("name,email,ssn,card\n" +
			"Alice,alice@example.com,449-87-4100,4532015112830366\n" +
			"Bob,bob@example.org,529-11-2233,5425233430109903\n"),
		Tier1Parity: false, // CSV may route differently than raw plaintext; lock file-mode output only
	},
	// --- Tier 2: TRUE metadata/dual-path branch coverage via a synthesized WAV ---
	// This is the case that actually exercises the metadata branch core.ScanContent
	// skips: a .wav routes to the audio_metadata preprocessor (pure-Go RIFF/LIST
	// parser — no external binary, no committed fixture), whose extracted INFO
	// fields feed the METADATA validator through the dual-path bridge. PII is
	// embedded in the INFO tags (IART=artist, ICMT=comment). The WAV is built
	// deterministically in-test; its ModTime is normalized in the snapshot.
	{
		Name:        "file_wav_metadata_pii",
		Description: "Tier 2 (the real one): synthesized .wav with PII in INFO tags — exercises the audio_metadata preprocessor + METADATA validator + dual-path branch that ScanContent cannot reach.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "METADATA"},
		Filename:    "clip.wav",
		Content: BuildWAVWithInfo(map[string]string{
			"INAM": "Quarterly Review Recording",
			"IART": "john.doe@example.com",
			"ICMT": "contact 212-555-0142 or AKIAIOSFODNN7EXAMPLE",
		}),
		Tier1Parity:         false, // metadata branch has no content-mode equivalent
		EnablePreprocessors: true,  // required: .wav is a binary document
	},
	// --- Tier 3: OOXML containers — the combined_preprocessors routing arm -------
	//
	// These are the corpus's first Office cases. They exist because the arm where
	// the FileRouter concatenates two extractors' output with "--- name ---"
	// separators, and the ContentRouter re-splits that text to decide what is
	// document body versus metadata, had NO coverage at all: every prior case is a
	// single-extractor .txt/.go/.json/.csv or a .wav. A change could therefore
	// rewrite which validators see a document's body and the whole corpus would
	// stay green.
	//
	// Each pair is (control, variant) differing in ONE input, so a diff isolates
	// that input's effect. Per the README, these lock ferret-scan's own routing and
	// validation — not a third-party extractor's byte output — which is why the
	// containers are synthesized in-test rather than committed.
	{
		Name:        "file_docx_body_and_metadata",
		Description: "Tier 3 control: a .docx with PII in the body AND in core properties — locks the combined_preprocessors arm where both the text and office_metadata extractors claim one file.",
		Checks:      []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename:    "report.docx",
		Content: BuildDOCX("Jane Analyst", "Ops Reviewer", []string{
			"Quarterly summary follows.",
			"Employee SSN 449-87-4100 on file.",
			"Card 4532-0151-1283-0366 expires soon.",
		}),
		Tier1Parity:         false, // container extraction has no content-mode equivalent
		EnablePreprocessors: true,
	},
	{
		Name: "file_docx_forged_separator_midbody",
		Description: "Tier 3: same .docx as the control plus ONE body paragraph that is exactly the router's own section separator. " +
			"Locks what the document path is given when document text forges a section boundary. Diff against file_docx_body_and_metadata.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "forged_mid.docx",
		Content: BuildDOCX("Jane Analyst", "Ops Reviewer", []string{
			"Quarterly summary follows.",
			"--- office_metadata ---",
			"Employee SSN 449-87-4100 on file.",
			"Card 4532-0151-1283-0366 expires soon.",
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_docx_forged_separator_firstline",
		Description: "Tier 3: the forged separator as the FIRST paragraph, so the pre-separator body is empty. " +
			"A distinct routing state from the mid-body case (empty document body vs a short one), which is why it gets its own snapshot.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "forged_first.docx",
		Content: BuildDOCX("Jane Analyst", "Ops Reviewer", []string{
			"--- office_metadata ---",
			"Employee SSN 449-87-4100 on file.",
			"Card 4532-0151-1283-0366 expires soon.",
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name:        "file_xlsx_sheet_cells",
		Description: "Tier 3 control: an .xlsx with PII in worksheet cells at the conventional sheet part name.",
		Checks:      []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename:    "books.xlsx",
		Content: BuildXLSX("xl/worksheets/sheet1.xml", "Jane Analyst", []string{
			"Employee SSN 449-87-4100",
			"Card 4532-0151-1283-0366",
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_xlsx_sheet_part_named_metadata",
		Description: "Tier 3: identical cells, but the worksheet PART is named so the extractor's emitted section label collides with a metadata section name. " +
			"No body text is involved — the collision comes from the archive member name, which a document producer controls. Diff against file_xlsx_sheet_cells.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "books_named.xlsx",
		Content: BuildXLSX("xl/worksheets/sheet_office_metadata.xml", "Jane Analyst", []string{
			"Employee SSN 449-87-4100",
			"Card 4532-0151-1283-0366",
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_docx_main_part_alternate_case",
		Description: "Tier 3: the document body at \"word/Document.xml\" instead of \"word/document.xml\" — a part name that differs only in case. " +
			"Locks that body text at a non-conventional part name is still extracted and scanned; it previously was not, which cost this case its SSN and VISA findings. " +
			"Diff against file_docx_body_and_metadata.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "alt_case.docx",
		Content: BuildDOCXWithMainPart("word/Document.xml", "Jane Analyst", "Ops Reviewer", []string{
			"Quarterly summary follows.",
			"Employee SSN 449-87-4100 on file.",
			"Card 4532-0151-1283-0366 expires soon.",
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	// --- Tier 4: legacy Office (OLE compound files) ---------------------------
	//
	// A .doc/.xls/.ppt is an OLE Compound File Binary container, not a ZIP, so it
	// shares no code with the OOXML cases above: a different preprocessor, a
	// different property format, a different redactor. Before legacy support
	// existed these files produced "legacy Office formats not supported" and
	// NOTHING in them was scanned — so the corpus recorded no expectation at all
	// for a format still common in email archives and shared drives.
	//
	// The container is synthesized in-test via internal/olefixture, matching the
	// OOXML precedent. Body text and properties are recovered by different means
	// (properties exactly, from a documented key/value format; body text
	// approximately, by a printable-run scan), so both halves are present in each
	// case and the snapshot records what each actually yields.
	{
		Name: "file_doc_legacy_body_and_properties",
		Description: "Tier 4 control: a legacy .doc with PII in the WordDocument body stream AND an author in " +
			"SummaryInformation. Locks the OLE path end to end — a format that was previously reported as an " +
			"error with nothing scanned.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "quarterly.doc",
		Content: olefixture.LegacyDoc(
			"Quarterly summary follows.\r"+
				"Employee SSN 449-87-4100 on file.\r"+
				"Card 4532-0151-1283-0366 expires soon.\r",
			map[uint32]string{
				olefixture.PropAuthor:     "Jane Analyst",
				olefixture.PropLastAuthor: "Ops Reviewer",
				olefixture.PropAppName:    "Microsoft Word 97",
			}),
		Tier1Parity:         false, // OLE extraction has no content-mode equivalent
		EnablePreprocessors: true,  // required: .doc is a binary document
	},
	{
		Name: "file_doc_legacy_template_path",
		Description: "Tier 4: a legacy .doc whose Template property holds an internal UNC share. Locks a field " +
			"users do not know is in the file, and which only the metadata path can surface. Diff against " +
			"file_doc_legacy_body_and_properties.",
		Checks:   []string{"SSN", "METADATA"},
		Filename: "from_template.doc",
		Content: olefixture.LegacyDoc(
			"Employee SSN 449-87-4100 recorded here.\r",
			map[uint32]string{
				olefixture.PropAuthor:   "Jane Analyst",
				olefixture.PropTemplate: `\\corp-fs01\templates\quarterly.dot`,
			}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_xls_legacy_workbook_stream",
		Description: "Tier 4: a legacy .xls, whose body lives in a stream named \"Workbook\" rather than " +
			"\"WordDocument\". The stream-name table is the entire selection mechanism, so this locks that a " +
			"second legacy format is actually read and not silently skipped.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "budget.xls",
		Content: olefixture.MustBuild([]olefixture.Stream{
			{Name: olefixture.StreamWorkbook, Data: []byte(
				"Employee SSN 449-87-4100 in the sheet.\r" +
					"Card 4532-0151-1283-0366 on record.\r")},
			{Name: olefixture.StreamSummaryInformation, Data: olefixture.SummaryInformation(
				map[uint32]string{olefixture.PropAuthor: "Jane Analyst"})},
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_doc_legacy_wide_encoded_body",
		Description: "Tier 4: a legacy .doc whose body text is UTF-16LE, as Word actually stores much of it. " +
			"A single-byte-only recovery pass sees every OTHER character and can split a value down the middle, " +
			"so this locks that wide text yields the same findings as narrow. Diff against " +
			"file_doc_legacy_body_and_properties.",
		Checks:   []string{"SSN", "CREDIT_CARD", "METADATA"},
		Filename: "wide.doc",
		Content: olefixture.MustBuild([]olefixture.Stream{
			{Name: olefixture.StreamWordDocument, Data: olefixture.UTF16LE(
				"Employee SSN 449-87-4100 on file. " +
					"Card 4532-0151-1283-0366 expires soon.")},
			{Name: olefixture.StreamSummaryInformation, Data: olefixture.SummaryInformation(
				map[uint32]string{olefixture.PropAuthor: "Jane Analyst"})},
		}),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
	{
		Name: "file_doc_legacy_not_a_container",
		Description: "Tier 4: plain text named .doc — the extension routes to the OLE path, but the bytes are not a " +
			"compound file. This used to record \"No matches found.\": routing is decided by extension, the Office " +
			"extractor failed, no other preprocessor had claimed the file, and the SSN in it was never reported and " +
			"therefore never redacted. It now records the SSN as FOUND, which is the point of the case — a " +
			"mislabelled file is exactly as sensitive as a correctly named one, and needs no attacker (an export " +
			"pipeline, a hand-rename, or a truncated download all land here). The failure must still be graceful and " +
			"must not invent metadata, which the METADATA check keeps covered.",
		Checks:              []string{"SSN", "METADATA"},
		Filename:            "notreally.doc",
		Content:             []byte("This is plain text that happens to be named .doc.\nEmployee SSN 449-87-4100 here.\n"),
		Tier1Parity:         false,
		EnablePreprocessors: true,
	},
}

// BuildWAVWithInfo synthesizes a minimal but valid WAV file (RIFF/WAVE + fmt +
// LIST/INFO + data) carrying the given INFO tags, in a DETERMINISTIC field order
// (sorted by id) so the bytes are stable across runs. This lets the corpus
// exercise the audio metadata extraction + dual-path validation branch without
// committing an opaque binary fixture. Supported INFO ids include INAM (title),
// IART (artist), ICMT (comment), ICOP (copyright) — see the WAV extractor.
func BuildWAVWithInfo(info map[string]string) []byte {
	// fmt chunk: 16-byte PCM, mono, 8kHz, 8-bit.
	fmtChunk := new(bytes.Buffer)
	writeLE(fmtChunk, uint16(1), uint16(1), uint32(8000), uint32(8000), uint16(1), uint16(8))

	// INFO chunk body, fields emitted in sorted id order for determinism.
	ids := make([]string, 0, len(info))
	for id := range info {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	infoBody := new(bytes.Buffer)
	infoBody.WriteString("INFO")
	for _, id := range ids {
		v := info[id]
		field := append([]byte(v), 0) // null-terminated
		if len(field)%2 == 1 {
			field = append(field, 0) // pad to even boundary
		}
		infoBody.WriteString(id)
		writeLE(infoBody, uint32(len(v)+1))
		infoBody.Write(field)
	}

	list := new(bytes.Buffer)
	list.WriteString("LIST")
	writeLE(list, uint32(infoBody.Len()))
	list.Write(infoBody.Bytes())

	data := []byte{0, 0, 0, 0} // 4 bytes of silence

	body := new(bytes.Buffer)
	body.WriteString("WAVE")
	body.WriteString("fmt ")
	writeLE(body, uint32(fmtChunk.Len()))
	body.Write(fmtChunk.Bytes())
	body.Write(list.Bytes())
	body.WriteString("data")
	writeLE(body, uint32(len(data)))
	body.Write(data)

	out := new(bytes.Buffer)
	out.WriteString("RIFF")
	writeLE(out, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// --- Office (OOXML) builders -------------------------------------------------
//
// Until these existed the corpus had NO .docx/.xlsx/.pptx/.pdf case at all (the
// census was 2 .txt, 1 .go, 1 .json, 1 .csv, 1 .wav). That mattered because the
// interesting routing arm is `combined_preprocessors`: it is reached only when
// TWO OR MORE preprocessors claim the same file, which no single-extractor type
// does. So the whole path where the FileRouter concatenates extractor output with
// "--- name ---" separators, and the ContentRouter re-splits it, was unsnapshotted
// — a change could rewrite what the document path sees and the corpus would stay
// green. These builders close that gap with in-test deterministic zips rather than
// committed binaries, matching the BuildWAVWithInfo precedent.
//
// Determinism: zip.Writer stamps a modtime per entry, and archive/zip writes
// whatever Modified holds, so an unset FileHeader would embed "now" and the bytes
// would differ every run. Every entry here pins Modified to a fixed UTC instant and
// parts are written in a fixed order, so the archive is byte-stable. (The
// ScanFile-side ModTime of the temp file is separately normalized in
// NormalizeOutput.)

// ooxmlEpoch is the fixed timestamp stamped into every synthesized OOXML entry.
// Any constant works; it only has to be stable and not depend on the clock.
var ooxmlEpoch = time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

// ooxmlPart is one archive member, written in slice order.
type ooxmlPart struct {
	name string
	body string
}

// buildOOXML zips the given parts with pinned modtimes, yielding byte-identical
// output for identical input.
func buildOOXML(parts []ooxmlPart) []byte {
	out := new(bytes.Buffer)
	zw := zip.NewWriter(out)
	for _, p := range parts {
		w, err := zw.CreateHeader(&zip.FileHeader{
			Name:     p.name,
			Method:   zip.Deflate,
			Modified: ooxmlEpoch,
		})
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, p.body); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// BuildDOCX synthesizes a minimal .docx whose body is one paragraph per element of
// paras, and which ALSO carries docProps/core.xml. The core properties are what
// make this a dual-preprocessor file: the text extractor and the office metadata
// extractor both claim it, so the FileRouter takes the combined_preprocessors arm
// and the ContentRouter's document/metadata split actually runs. A .docx with only
// word/document.xml takes the single-extractor fast path and would not exercise it.
//
// creator/lastModifiedBy land in the metadata path; paras land in the document
// path. Passing a paragraph that is exactly "--- office_metadata ---" is how a
// case locks the forged-separator behavior.
func BuildDOCX(creator, lastModifiedBy string, paras []string) []byte {
	return buildOOXML(docxParts("word/document.xml", creator, lastModifiedBy, paras))
}

// BuildDOCXWithMainPart is BuildDOCX with control over the main part's NAME, so a
// case can lock what happens when the document body is not at the conventional
// path. It also points the package relationship at that name, as a real producer
// would.
//
// The text extractor used to match part names as literal, case-SENSITIVE strings,
// so "word/Document.xml" was a different part from "word/document.xml" and the
// body was never extracted — one capital letter took the case from 4 findings to 2
// and put the SSN and card number outside everything the scanner could see.
// Selection is now driven by the relationships and by case-insensitive
// conventional names, so this case records the body being scanned.
func BuildDOCXWithMainPart(mainPart, creator, lastModifiedBy string, paras []string) []byte {
	return buildOOXML(docxParts(mainPart, creator, lastModifiedBy, paras))
}

func docxParts(mainPart, creator, lastModifiedBy string, paras []string) []ooxmlPart {
	var body strings.Builder
	for _, p := range paras {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">`)
		body.WriteString(escapeXML(p))
		body.WriteString(`</w:t></w:r></w:p>`)
	}
	doc := xmlDecl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() + `</w:body></w:document>`

	contentTypes := xmlDecl + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/` + mainPart + `" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		`</Types>`

	rels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="` + mainPart + `"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
		`</Relationships>`

	return []ooxmlPart{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"docProps/core.xml", coreProps(creator, lastModifiedBy)},
		{mainPart, doc},
	}
}

// BuildXLSX synthesizes a minimal .xlsx with one worksheet whose single column
// holds cells, plus docProps/core.xml so the file is dual-preprocessor like
// BuildDOCX.
//
// sheetPart is the worksheet's archive name (conventionally
// "xl/worksheets/sheet1.xml"). It is a parameter because the office text extractor
// derives its emitted section label from that name — it strips the
// "xl/worksheets/" prefix and ".xml" suffix and writes "--- <rest> ---" into the
// same text stream the ContentRouter re-parses. A sheet part named
// "sheet_office_metadata.xml" therefore emits a label the router reads as a
// metadata section boundary, with no document body text involved at all. Cases use
// it to lock that behavior.
func BuildXLSX(sheetPart, creator string, cells []string) []byte {
	var siBuf, rowBuf strings.Builder
	for i, c := range cells {
		siBuf.WriteString(`<si><t xml:space="preserve">` + escapeXML(c) + `</t></si>`)
		rowBuf.WriteString(fmt.Sprintf(`<row r="%d"><c r="A%d" t="s"><v>%d</v></c></row>`, i+1, i+1, i))
	}
	shared := xmlDecl + fmt.Sprintf(
		`<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="%d" uniqueCount="%d">%s</sst>`,
		len(cells), len(cells), siBuf.String())
	sheet := xmlDecl + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		rowBuf.String() + `</sheetData></worksheet>`

	contentTypes := xmlDecl + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
		`<Override PartName="/` + sheetPart + `" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
		`<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		`</Types>`

	rels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
		`</Relationships>`

	// The sheet name shown in Excel is independent of the part name; keep it fixed
	// so only the part name varies between cases.
	workbook := xmlDecl + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		`<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`

	sheetTarget := strings.TrimPrefix(sheetPart, "xl/")
	workbookRels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="` + sheetTarget + `"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>` +
		`</Relationships>`

	return buildOOXML([]ooxmlPart{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"docProps/core.xml", coreProps(creator, "")},
		{"xl/workbook.xml", workbook},
		{"xl/_rels/workbook.xml.rels", workbookRels},
		{"xl/sharedStrings.xml", shared},
		{sheetPart, sheet},
	})
}

const xmlDecl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

// coreProps renders docProps/core.xml. lastModifiedBy is omitted when empty.
func coreProps(creator, lastModifiedBy string) string {
	s := xmlDecl +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/">` +
		`<dc:creator>` + escapeXML(creator) + `</dc:creator>`
	if lastModifiedBy != "" {
		s += `<cp:lastModifiedBy>` + escapeXML(lastModifiedBy) + `</cp:lastModifiedBy>`
	}
	return s + `</cp:coreProperties>`
}

// escapeXML escapes text for an XML text node. Cases deliberately contain "---"
// and "<"-free payloads, but escaping keeps the builder honest for any input.
func escapeXML(s string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(s)); err != nil {
		panic(err)
	}
	return b.String()
}

// writeLE writes each value to buf in little-endian order, panicking on error
// (bytes.Buffer writes never fail; this keeps the builder readable).
func writeLE(buf *bytes.Buffer, vals ...any) {
	for _, v := range vals {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
}

// longLineWithEmbeddedEmail builds a single ~8KB line of filler with one real
// email embedded near the end. This is the input shape that drove the documented
// quadratic blowups; the golden snapshot locks the resulting findings.
func longLineWithEmbeddedEmail() string {
	const filler = "lorem ipsum dolor sit amet consectetur adipiscing elit "
	line := ""
	for len(line) < 8000 {
		line += filler
	}
	return line + "needle@example.com end\n"
}

// repeatedFooterLine builds a single line of >= n bytes made of concatenated
// copies of the standard AWS slide footer, mimicking PDF text extraction of a
// deck whose every slide carries the footer. Exercises the IP validator's
// same-line legal-notice consolidation on a pathologically long line.
func repeatedFooterLine(n int) string {
	const footer = "© 2026, Amazon Web Services, Inc. or its affiliates. All rights reserved. Amazon Confidential and Trademark. "
	var sb strings.Builder
	sb.Grow(n + len(footer))
	for sb.Len() < n {
		sb.WriteString(footer)
	}
	return sb.String() + "\n"
}

// manyEmails generates n lines each containing a distinct email address.
func manyEmails(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += fmt.Sprintf("user%02d@example.com line %d\n", i, i)
	}
	return out
}

// CanonicalSort imposes a deterministic TOTAL order on matches so snapshots are
// stable regardless of the goroutine-completion order in which validators emit
// them. The formatters' own sorts (text/junit) are stable but not total — they
// leave equal-confidence matches in input order — so we sort here before
// formatting. The key is intentionally exhaustive: every field that can vary is
// part of the order, with Text last so two otherwise-identical matches still
// have a defined sequence.
func CanonicalSort(matches []detector.Match) []detector.Match {
	out := make([]detector.Match, len(matches))
	copy(out, matches)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Validator != b.Validator {
			return a.Validator < b.Validator
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence // higher confidence first
		}
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Text < b.Text
	})
	return out
}

// timestampPatterns matches the non-deterministic wall-clock timestamps that a
// couple of formatters embed (gitlab-sast emits ISO-8601 start/end times). They
// are replaced with a fixed sentinel so the snapshot is byte-stable.
var timestampPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	// gitlab-sast: "2026-06-30T11:07:42"
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`), "<TIMESTAMP>"},
	// INTELLECTUAL_PROPERTY legal-notice reconstruction stamps a Unix-epoch
	// string into metadata ("reconstruction_timestamp": "1784686027"); it
	// varies every run, so normalize the digits wherever the key appears
	// (JSON, YAML, CSV metadata blobs, and gitlab-sast description bullets)
	// while keeping the key itself intact.
	{regexp.MustCompile(`(reconstruction_timestamp[^0-9]*)\d+`), "${1}<TIMESTAMP>"},
}

// NormalizeOutput makes formatter output byte-stable for snapshotting by
// removing sources of run-to-run variance that are NOT behavior:
//
//   - wall-clock timestamps (gitlab-sast) → "<TIMESTAMP>" sentinel;
//   - JSON object-key order → canonical sorted form;
//   - the per-run temp-dir-derived gitlab-sast vulnerability id hash.
//
// These normalizations lock the *content* of the output, not the incidental
// ordering the current formatters happen to emit. If a future change alters
// what data appears (a new field, a changed message, a different detection),
// the snapshot still catches it. format is the formatter name (e.g. "sarif").
//
// Deliberately NOT normalized any more: the SARIF tool.driver.rules array and
// the gitlab-sast "Additional Information" bullet list. Both used to be sorted
// here to paper over Go map iteration order in the formatters themselves. The
// formatters now emit both in sorted order at the source, so re-sorting here
// would only re-hide a regression — this snapshot is the guard for those two
// emit paths.
func NormalizeOutput(format, s string) string {
	for _, p := range timestampPatterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}

	switch format {
	case "sarif", "gitlab-sast", "json":
		if c, ok := canonicalizeJSON(s); ok {
			s = c
		}
	}
	if format == "gitlab-sast" {
		s = ferretIDPattern.ReplaceAllString(s, "ferret-<HASH>")
	}
	return s
}

// ferretIDPattern matches the gitlab-sast vulnerability id "ferret-<16 hex>".
// The id is a SHA256 over "filename:line:type" (mapper.go GenerateVulnerabilityID),
// so it is stable for a fixed file path but varies with the per-run temp dir.
// The snapshot already locks the filename/line/type it derives from, so the raw
// hash carries no extra signal — normalize it to keep file-mode snapshots stable.
var ferretIDPattern = regexp.MustCompile(`ferret-[0-9a-f]{16}`)

// canonicalizeJSON re-marshals a JSON document with object keys sorted
// (encoding/json sorts map keys deterministically). Array order is left alone:
// every array the formatters emit is now ordered at the source, so the snapshot
// should hold them to it. Returns (normalized, true) on success, or ("", false)
// if the input is not valid JSON (in which case the caller keeps the original).
func canonicalizeJSON(s string) (string, bool) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", false
	}
	// Unmarshaling into any -> map[string]any means re-marshaling already emits
	// keys in sorted order, so object key order is now canonical.
	return buf.String(), true
}

// sortFindings imposes a deterministic total order on redact findings so the
// redaction snapshot is stable regardless of emission order.
func sortFindings(f []redact.FindingWithMatchText) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Confidence != b.Confidence {
			return a.Confidence < b.Confidence
		}
		return a.MatchText < b.MatchText
	})
}

// itoa is a tiny wrapper kept local so the test file doesn't import strconv.
func itoa(n int) string { return strconv.Itoa(n) }

// formatConf renders a confidence score as a stable 2-decimal string for use in
// identity keys (avoids float formatting drift across the comparison).
func formatConf(c float64) string { return strconv.FormatFloat(c, 'f', 2, 64) }

// NormalizePaths replaces the per-run temp directory (which varies by machine,
// run, and OS) with a stable sentinel so file-mode snapshots are portable —
// including ACROSS OPERATING SYSTEMS. The FileRouter stamps the absolute file
// path into Match.Filename and metadata keys ("source_file"/"original_file");
// without this every file-mode snapshot would change on every run, and on
// Windows the path separator (`\`) and JSON-escaped form (`\\`) would diverge
// from snapshots generated on Unix. tmpDir is the t.TempDir() the fixture was
// written into. Applied BEFORE NormalizeOutput (which canonicalizes JSON), so
// the sentinel survives JSON round-tripping.
//
// Cross-platform strategy: replace the temp dir in BOTH its native form and a
// forward-slash form (covers raw text/csv/yaml and unescaped JSON values), then
// collapse any path separator that immediately follows the <TMPDIR> sentinel to
// "/" so a fixture's basename renders identically on every OS. We only rewrite
// separators adjacent to the sentinel, never globally, so JSON string escaping
// elsewhere is untouched.
func NormalizePaths(s, tmpDir string) string {
	if tmpDir == "" {
		return s
	}
	// Forms the temp dir can appear in: native (filepath separators), forward-
	// slash (Unix / some renderers), and JSON-escaped backslashes (`\\`, Windows
	// inside JSON string values). Replace longest/most-specific first.
	fwd := strings.ReplaceAll(tmpDir, "\\", "/")
	jsonEsc := strings.ReplaceAll(tmpDir, "\\", "\\\\")
	for _, form := range []string{jsonEsc, tmpDir, fwd} {
		s = strings.ReplaceAll(s, form, "<TMPDIR>")
	}
	// Collapse the separator immediately after the sentinel to "/" so
	// "<TMPDIR>\notes.txt", "<TMPDIR>\\notes.txt", and "<TMPDIR>/notes.txt" all
	// normalize to "<TMPDIR>/notes.txt".
	s = strings.ReplaceAll(s, `<TMPDIR>\\`, "<TMPDIR>/")
	s = strings.ReplaceAll(s, `<TMPDIR>\`, "<TMPDIR>/")
	return s
}
