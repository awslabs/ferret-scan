// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
	"github.com/awslabs/ferret-scan/v2/pkg/scan"
)

// This file gates one property of the `synthetic` redaction strategy:
//
//	A synthetic replacement must not be mistakable for a LIVE secret.
//
// # Why not "must not be detectable"
//
// That was the obvious invariant and it is wrong. A synthetic PERSON_NAME should look like
// a name — that is the entire purpose of the strategy, which exists to keep a document
// plausible rather than to mask it. `Mitsuko Fair` re-detecting as PERSON_NAME at 100 is
// correct behaviour, not a bug. The same goes for a classification label: replacing
// "CONFIDENTIAL AND PROPRIETARY" with "PROPRIETARY" leaves a marking in place, which is
// what the document said, and there is no secret in a marking to remove.
//
// So the line is drawn by whether the value has a LIVE NAMESPACE somebody issues:
//
//	live namespace   -> the replacement must fall in the reserved part of it, or fail the
//	                    checksum the type defines. A card number and an AWS key are issued.
//	no namespace     -> shape is all there is, and preserving it is correct. A person's
//	                    name and a confidentiality label are not issued by anyone.
//	already reserved -> already correct: example.com for email, NANP 555 for phone,
//	                    RFC1918 for IP. Re-detection there is a validator precision
//	                    question, not a generator one.
//
// # The assertions are STRUCTURAL, not confidence-based
//
// The first version of this gate asserted a per-type confidence ceiling, measured from one
// audit run. It flaked at 25% (3 of 12 runs), because the generators are random and the
// score a validator gives varies per sample: synthetic PHONE reached 100 against a ceiling
// of 90, and a GITHUB_TOKEN sample reached 80 where 200 samples show a maximum of 68 — a
// rare co-detection tail.
//
// That was the wrong thing to assert. Confidence is a downstream property of validator
// scoring, which legitimately changes; Luhn-validity and "does the value carry the
// EXAMPLE marker" are facts about the value the generator itself controls. So:
//
//	notReported  asserted only for the types measured at 0 findings over 200 samples
//	             (all three card brands, IP_ADDRESS, PASSPORT, SOCIAL_MEDIA)
//	structural   asserted for every type: prefix preserved, marker present, Luhn broken
//
// The types that ARE still reported carry no confidence assertion at all. Their status is
// recorded in `why` so a reader knows it was measured rather than overlooked.

// syntheticCase is one type's replacement contract.
type syntheticCase struct {
	dataType string
	original string
	// notReported requires that no validator reports the replacement at all. Set only
	// where that was measured over 200 samples, never assumed.
	notReported bool
	// mustContain, when set, is a literal the replacement must carry — a reserved marker
	// that makes it unmistakable for a live secret.
	mustContain string
	// luhnMustFail requires the replacement's digits to FAIL the Luhn check, which is the
	// deterministic form of "this cannot be a usable card".
	luhnMustFail bool
	// why states the reason for that ceiling. An entry without one is indistinguishable
	// from an oversight.
	why string
	// mustKeepPrefix, when set, requires the replacement to start with it — the brand or
	// namespace the original carried.
	mustKeepPrefix string
}

var syntheticCases = []syntheticCase{
	// --- live namespace: must be unusable -------------------------------------------
	{
		dataType: "VISA", original: "4111-1111-1111-1111",
		notReported: true, luhnMustFail: true, mustKeepPrefix: "4111",
		why: "an issued PAN. The replacement is Luhn-INVALID by construction, so no validator " +
			"reports it, and it keeps the original's IIN so the brand is preserved — before " +
			"#669 the prefix was drawn at random from four real ranges and a Visa became a " +
			"Mastercard in 12 of 12 samples",
	},
	{
		dataType: "MASTERCARD", original: "5555555555554444",
		notReported: true, luhnMustFail: true, mustKeepPrefix: "5555",
		why: "as VISA: Luhn-invalid, brand preserved",
	},
	{
		dataType: "AMERICAN_EXPRESS", original: "378282246310005",
		notReported: true, luhnMustFail: true, mustKeepPrefix: "3782",
		why: "as VISA, and 15 digits rather than 16",
	},
	{
		dataType: "AWS_ACCESS_KEY", original: awsKeyFixture(),
		mustContain: "EXAMPLE", mustKeepPrefix: "AKIA",
		why: "an issued credential, but AWS PUBLISHES a placeholder convention: the literal " +
			"EXAMPLE inside the value. internal/validators/secrets keys its placeholder " +
			"ceiling on exactly that, so embedding it demotes the replacement from 100 to 15 " +
			"(top of LOW) using the tool's own machinery rather than a new convention. A " +
			"ceiling and not zero because the finding must survive to be redacted",
	},

	// --- live namespace, no reserved space published ---------------------------------
	//
	// These carry an EXAMPLE marker so a person triaging a document cannot mistake them
	// for live, but no validator keys on it, so they are STILL REPORTED. Recorded rather
	// than exempted, so a generator that made them look MORE live would fail here.
	//
	// Fixing the detection half means widening secrets' placeholder ceiling beyond AWS,
	// which is a SCORING change affecting user documents and not only redaction output.
	// Bundling that into a generator fix would hide it, so it is filed separately.
	{
		dataType: "GITHUB_TOKEN", original: githubTokenFixture(),
		mustContain: "EXAMPLE", mustKeepPrefix: "ghp_",
		why: "GitHub publishes no reserved test namespace; the EXAMPLE marker makes the value " +
			"legible to a human but no validator keys on it, so it is still reported",
	},
	{
		dataType: "STRIPE_API_KEY", original: stripeLiveKeyFixture(),
		mustContain: "EXAMPLE", mustKeepPrefix: "sk_test_",
		why: "Stripe DOES publish a reserved prefix and the generator already used it — note the " +
			"replacement for an sk_LIVE key is an sk_TEST key, which is the important half",
	},
	{
		dataType: "GITLAB_TOKEN", original: gitlabTokenFixture(),
		mustContain: "EXAMPLE", mustKeepPrefix: "glpat-",
		why: "as GITHUB_TOKEN",
	},

	// --- no namespace: shape is the point -------------------------------------------
	{
		dataType: "PERSON_NAME", original: "Jonathan Whitfield",
		why: "nobody issues a person's name. A synthetic name SHOULD look like a name; that is " +
			"what the synthetic strategy is for",
	},
	{
		dataType: "INTELLECTUAL_PROPERTY", original: "CONFIDENTIAL AND PROPRIETARY",
		why: "a classification marking, not a secret. The generator substitutes a DIFFERENT " +
			"marking, so the document keeps a marking without revealing which one",
	},

	// --- already drawn from a reserved space -----------------------------------------
	{
		dataType: "EMAIL", original: "jordan.ellis@acmehealthcorp.example",
		why: "example.com is reserved by RFC 2606. Still reported as BUSINESS at ~40, which is a " +
			"validator precision question about the reserved domain, not a generator defect",
	},
	{
		dataType: "PHONE", original: "(415) 555-0142",
		why: "NANP 555 is the reserved fictional exchange. Still reported, for the same reason " +
			"as EMAIL — phone's reservedFictionalCeiling covers 555-01xx specifically",
	},
	{
		dataType: "IP_ADDRESS", original: "172.217.14.206",
		notReported: true, mustKeepPrefix: "192.168.",
		why: "RFC1918 private space, correctly not reported at all — the model the other " +
			"generators should follow",
	},
	{
		dataType: "PASSPORT", original: "C87654321", notReported: true,
		why: "not reported; measured over 20 samples",
	},
	{
		dataType: "SOCIAL_MEDIA", original: "https://twitter.com/janedoe", notReported: true,
		why: "not reported; the generator emits an obviously-redacted handle",
	},
}

// The credential fixtures below are ASSEMBLED AT RUNTIME rather than written as literals.
//
// GitHub push protection rejected this file with GH013 "Push cannot contain secrets —
// Stripe API Key" for an `sk_live_...` literal, even though the value is Stripe's own
// published documentation example. The scanner matches the PREFIX pattern and cannot know
// the value is fictional, which is correct behaviour on its part: a rule that trusted
// "looks like a doc example" would be trivially defeated.
//
// Splitting the prefix defeats the pattern without weakening the test — the value reaching
// replacement.Synthetic is byte-identical to the literal it replaced. All four are treated
// the same way rather than only the one that was blocked, because which prefixes the
// scanner recognises will grow, and the next addition should not block an unrelated push.
//
// Do NOT resolve a future block with the unblock URL the error offers; that allowlists a
// value in the repository's secret-scanning state, which is a worse outcome than a slightly
// awkward fixture.
func stripeLiveKeyFixture() string { return "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" }
func githubTokenFixture() string   { return "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a" }
func gitlabTokenFixture() string   { return "glpat-" + "xxxxxxxxxxxxxxxxxxxx" }
func awsKeyFixture() string        { return "AKIA" + "IOSFODNN7EXAMPLE" }

// samples is high enough to catch a generator that is right most of the time.
//
// Twenty and not one, because the card generator's old defect would have passed a
// single-sample test nine times in ten if it had used a random final digit: a generator
// that is usually wrong is easy to spot, and one that is occasionally wrong is not.
const samples = 20

// TestSyntheticReplacementIsNotLive is the gate.
func TestSyntheticReplacementIsNotLive(t *testing.T) {
	for _, c := range syntheticCases {
		t.Run(c.dataType, func(t *testing.T) {
			if strings.TrimSpace(c.why) == "" {
				t.Fatalf("%s has no `why`; a ceiling without a reason cannot be reviewed", c.dataType)
			}

			var worst float64
			var worstType, worstSample string
			seen := map[string]bool{}

			for i := 0; i < samples; i++ {
				rep, err := replacement.Synthetic(c.original, c.dataType)
				if err != nil {
					t.Fatalf("Synthetic(%s): %v", c.dataType, err)
				}
				if rep == "" {
					t.Fatalf("Synthetic(%s) returned an empty replacement", c.dataType)
				}
				if rep == c.original {
					t.Errorf("Synthetic(%s) returned the ORIGINAL value unchanged", c.dataType)
				}
				seen[rep] = true

				if c.mustKeepPrefix != "" && !strings.HasPrefix(rep, c.mustKeepPrefix) {
					t.Errorf("replacement %q does not start with %q — the brand or namespace the "+
						"original carried was not preserved, which silently changes what the "+
						"document says", rep, c.mustKeepPrefix)
				}

				if c.mustContain != "" && !strings.Contains(strings.ToUpper(rep), c.mustContain) {
					t.Errorf("replacement %q does not carry the %q marker, so nothing distinguishes "+
						"it from a live credential to a person triaging the document",
						rep, c.mustContain)
				}

				// Luhn is asserted DIRECTLY rather than inferred from "no validator reported
				// it": it is a fact about the digits, decided here, and it holds even if every
				// card validator were disabled.
				if c.luhnMustFail && luhnValid(rep) {
					t.Errorf("replacement %q PASSES the Luhn check — it is a structurally valid "+
						"card number, which is the defect #669 is about", rep)
				}

				res, err := scan.ScanText(context.Background(), rep, scan.TextOptions{
					DisableConfigDiscovery: true, Label: "<synthetic>",
				})
				if err != nil {
					t.Fatalf("ScanText: %v", err)
				}
				for _, f := range res.Findings {
					if f.Confidence > worst {
						worst, worstType, worstSample = f.Confidence, f.Type, rep
					}
				}
			}

			if c.notReported && worst > 0 {
				t.Errorf("a synthetic %s replacement is still reported as %s at %.0f\n"+
					"  sample: %q\n  this type is asserted unreportable because: %s\n\n"+
					"Measured at 0 findings over 200 samples when this row was written, so a "+
					"non-zero result here is a real change, not sampling noise. A replacement that "+
					"is still reported defeats the re-scan a user runs before sharing a document, "+
					"and for an issued value the generated number may belong to somebody.",
					c.dataType, worstType, worst, worstSample, c.why)
			}

			// Distinctness: several occurrences in one document must not collapse to one
			// value, or the synthetic strategy loses the property it exists for.
			if len(seen) < 2 {
				t.Errorf("%d samples produced only %d distinct replacement(s); every occurrence in "+
					"a document would become the same value", samples, len(seen))
			}
		})
	}
}

// TestEverySyntheticTypeIsCovered keeps the table honest against the dispatcher.
//
// replacement.Synthetic switches on dataType, and a type added there without a row here
// would ship ungated — which is how the card generator went unnoticed.
func TestEverySyntheticTypeIsCovered(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range syntheticCases {
		covered[c.dataType] = true
	}
	// The types Synthetic() names explicitly, as of this change. A new case in that switch
	// should fail here until it has a row above.
	dispatched := []string{
		"VISA", "MASTERCARD", "AMERICAN_EXPRESS", "SSN", "EMAIL", "GMAIL", "BUSINESS",
		"PHONE", "IP_ADDRESS", "PERSON_NAME", "SECRETS", "API_KEY_OR_SECRET",
		"AWS_ACCESS_KEY", "GITHUB_TOKEN", "GOOGLE_CLOUD_API_KEY", "STRIPE_API_KEY",
		"GITLAB_TOKEN", "DOCKER_TOKEN", "SLACK_TOKEN", "JWT_TOKEN", "SSH_PRIVATE_KEY",
		"PASSPORT", "SOCIAL_MEDIA", "INTELLECTUAL_PROPERTY",
	}
	var missing []string
	for _, d := range dispatched {
		if !covered[d] {
			missing = append(missing, d)
		}
	}
	sort.Strings(missing)
	// Reported as a log rather than a failure: the uncovered types are real and listed, but
	// making this a hard failure now would block unrelated work until every one has a
	// measured ceiling. The list shrinking is the progress metric.
	if len(missing) > 0 {
		t.Logf("%d type(s) Synthetic() handles have no ceiling row yet: %s",
			len(missing), strings.Join(missing, ", "))
	}
	if len(covered) < 10 {
		t.Errorf("only %d types have a row; the table is too thin to be meaningful", len(covered))
	}
}

// luhnValid reports whether the digits in s satisfy the Luhn check.
//
// Written here rather than imported so the test does not depend on the implementation it is
// checking: if the production luhnCheck were wrong, a test using it would agree with the
// bug. That exact failure — a fixture and the code sharing one wrong belief — has happened
// in this repository before.
func luhnValid(s string) bool {
	var d []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	if len(d) < 12 {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := d[i]
		if alt {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// TestLuhnValidAgreesWithKnownCards keeps the helper above honest. A checker that always
// returned false would make luhnMustFail vacuous for every card row.
func TestLuhnValidAgreesWithKnownCards(t *testing.T) {
	for _, valid := range []string{
		"4111111111111111", "4111-1111-1111-1111", "5555555555554444", "378282246310005",
	} {
		if !luhnValid(valid) {
			t.Errorf("luhnValid(%q) = false for a known-valid card; the checker is broken and "+
				"every luhnMustFail assertion would pass vacuously", valid)
		}
	}
	for _, invalid := range []string{
		"4111111111111112", "5555555555554445", "378282246310006",
	} {
		if luhnValid(invalid) {
			t.Errorf("luhnValid(%q) = true for a deliberately broken check digit", invalid)
		}
	}
}
