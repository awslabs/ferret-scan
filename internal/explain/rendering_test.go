// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #363, the two display defects in this package.
//
// (a) Validators spell the "this value is test data" check four different ways, and
// passedChecks skipped only the bare "not_test". So every validator using a variant leaked its
// raw key name into user-facing prose — measured on HEAD, an IP_ADDRESS explanation read
// "... it passed the not reserved check, the not test ip check, the reasonable use check ..."
// while the identical concept stayed correctly hidden for creditcard.
//
// (b) friendlyType lowercases, and the article was chosen by startsWithVowel on the result —
// i.e. by SPELLING rather than pronunciation. So "SSN" got "a" (it is said "ess-ess-en") and
// "US_STREET_ADDRESS" got "an" (it is said "you-ess"). Both failures land on the first words of
// every explanation, which is what --explain exists to have read.

func synth() *SignalSynthesizer { return &SignalSynthesizer{} }

// mk builds a match with the given type and checks. Confidence is deliberately below the HIGH
// boundary for the verdict tests and irrelevant to the prose tests.
func mkTyped(typ string, conf float64, checks map[string]bool, meta map[string]any) detector.Match {
	m := detector.Match{
		Text:       "value",
		Type:       typ,
		Confidence: conf,
		Filename:   "f.txt",
		LineNumber: 1,
		Metadata:   map[string]any{},
	}
	for k, v := range meta {
		m.Metadata[k] = v
	}
	if checks != nil {
		m.Metadata["validation_checks"] = checks
	}
	return m
}

// TestNoTestCheckKeyLeaksIntoTheProse covers defect (a).
//
// Every spelling in testCheckKeys must be hidden from the "it passed ..." list, because
// verdict() already reports that concept and repeating it as a raw key name is what the bug
// looked like. Driven from testCheckKeys itself, so a validator that adds a new spelling is
// covered without editing this test.
func TestNoTestCheckKeyLeaksIntoTheProse(t *testing.T) {
	if len(testCheckKeys) < 5 {
		t.Fatalf("testCheckKeys has only %d entries; this test drives itself from that list and "+
			"would be near-vacuous", len(testCheckKeys))
	}
	for _, key := range testCheckKeys {
		t.Run(key, func(t *testing.T) {
			// A PASSING variant check, alongside a genuine structural one so the sentence is
			// not empty and the assertion is about exclusion rather than about there being
			// nothing to say.
			m := mkTyped("SSN", 80, map[string]bool{key: true, "format": true}, nil)
			why := synth().rationale(m, validationChecks(m), false)

			leaked := humanizeCheck(key)
			if strings.Contains(why, leaked) {
				t.Errorf("the %q check leaked into user-facing prose as %q:\n  %s\n"+
					"verdict() already reports the test signal; the prose must not repeat it "+
					"as a raw key name (#363).", key, leaked, why)
			}
			// Non-vacuity: the genuine check MUST still be narrated, or this test would pass
			// on a passedChecks that returned nothing at all.
			if !strings.Contains(why, "format") {
				t.Errorf("the genuine 'format' check is missing from %q, so the exclusion above "+
					"proves nothing", why)
			}
		})
	}
}

// TestTheSkipSetIsDerivedFromTestCheckKeys states the property that keeps the two in step.
//
// The original bug was two lists drifting: verdict() was widened to consult all seven spellings
// while passedChecks kept skipping only one. Deriving the skip set is the fix; this asserts the
// derivation rather than the current contents, so it cannot rot.
func TestTheSkipSetIsDerivedFromTestCheckKeys(t *testing.T) {
	// Build a checks map where EVERY test-check spelling passes, plus one real check.
	checks := map[string]bool{"luhn": true}
	for _, k := range testCheckKeys {
		checks[k] = true
	}
	got := passedChecks(checks)

	if len(got) != 1 {
		t.Errorf("passedChecks returned %v, want only the Luhn check.\nEvery testCheckKeys "+
			"spelling must be skipped; anything else here is a key that will surface as raw "+
			"prose.", got)
	}
}

// TestAcronymTypesRenderWithTheRightCaseAndArticle covers defect (b).
//
// Every "want" is the string the issue recorded as correct. The article is stored per entry
// rather than derived, because it depends on how the letters are SAID: "an SSN" and "a SWIFT
// code" differ only in pronunciation, and no rule over spelling can separate them.
func TestAcronymTypesRenderWithTheRightCaseAndArticle(t *testing.T) {
	cases := []struct {
		typ, want string
	}{
		{"SSN", "an SSN"},
		{"VIN", "a VIN"},
		{"IBAN", "an IBAN"},
		{"MRN", "an MRN"},
		{"NPI", "an NPI"},
		{"IP_ADDRESS", "an IP address"},
		{"US_STREET_ADDRESS", "a US street address"},
		{"US_BANK_ACCOUNT", "a US bank account"},
		{"AWS_ARN", "an AWS ARN"},
		{"AWS_ACCESS_KEY", "an AWS access key"},
		{"AWS_SECRET_ACCESS_KEY", "an AWS secret access key"},
		{"MEDICARE_MBI", "a Medicare MBI"},
		{"OTPAUTH_URI", "an otpauth URI"},
		{"SWIFT_BIC", "a SWIFT/BIC code"},
		{"DEA_NUMBER", "a DEA number"},
		{"GCP_RESOURCE_NAME", "a GCP resource name"},
		{"IBM_CRN", "an IBM CRN"},
		{"PO_BOX", "a PO box"},
		{"SSH_PRIVATE_KEY", "an SSH private key"},
		{"PGP_PRIVATE_KEY", "a PGP private key"},

		// Mass and plural nouns take no article at all.
		{"INTELLECTUAL_PROPERTY", "intellectual property"},
		{"RECOVERY_CODES", "recovery codes"},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			if got := describeType(mkTyped(tc.typ, 80, nil, nil)); got != tc.want {
				t.Errorf("describeType(%s) = %q, want %q", tc.typ, got, tc.want)
			}
		})
	}
}

// TestAnUnlistedTypeKeepsTheOldBehaviour bounds the table's blast radius.
//
// The table exists to fix acronyms, not to become a required registry. An ordinary word must
// still render from friendlyType with an article chosen by spelling, which is correct for words
// that are read as words.
func TestAnUnlistedTypeKeepsTheOldBehaviour(t *testing.T) {
	cases := []struct{ typ, want string }{
		{"PERSON_NAME", "a person name"},
		{"DATE_OF_BIRTH", "a date of birth"},
		{"PASSPORT", "a passport"},
		{"CERTIFICATE", "a certificate"},
		{"AUTHOR_INFO", "an author info"},
		{"MADE_UP_FUTURE_TYPE", "a made up future type"},
		{"ORPHAN_THING", "an orphan thing"},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			if _, listed := typeDisplays[tc.typ]; listed {
				t.Skipf("%s is in typeDisplays, so it does not test the fallback", tc.typ)
			}
			if got := describeType(mkTyped(tc.typ, 80, nil, nil)); got != tc.want {
				t.Errorf("describeType(%s) = %q, want %q — the fallback must be unchanged",
					tc.typ, got, tc.want)
			}
		})
	}
}

// TestTheEmailFamilyRendersByFamily.
//
// EMAIL sets Type to the PROVIDER, so "Flagged as a business" and "Flagged as a gmail" were
// bare subtype names with no noun. Handled via Metadata["email_provider"] rather than a row per
// provider, because that list lives in the email validator and grows — a table here would go
// stale silently, which is the failure mode the not_test key drift already demonstrated.
func TestTheEmailFamilyRendersByFamily(t *testing.T) {
	cases := []struct{ provider, want string }{
		{"GMAIL", "a Gmail email address"},
		{"ICLOUD", "an iCloud email address"},
		{"BUSINESS", "a business email address"},
		{"PROTONMAIL", "a ProtonMail email address"},
		{"MICROSOFT_365", "a Microsoft 365 email address"},
		{"AOL", "an AOL email address"},
		{"EMAIL", "an email address"},
		// Unlisted: a provider added tomorrow must still read as a name, not as prose.
		{"SOME_NEW_HOST", "a Some New Host email address"},
		{"YAHOO", "a Yahoo email address"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			m := mkTyped(tc.provider, 80, nil, map[string]any{"email_provider": tc.provider})
			if got := describeType(m); got != tc.want {
				t.Errorf("provider %s rendered %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

// TestTheSocialMediaFamilyRendersByFamily. Same shape as EMAIL: Type is the platform, so
// "Flagged as a twitter" had no noun after it.
func TestTheSocialMediaFamilyRendersByFamily(t *testing.T) {
	cases := []struct{ platform, want string }{
		{"twitter", "a Twitter profile"},
		{"github", "a GitHub profile"},
		{"linkedin", "a LinkedIn profile"},
		{"tiktok", "a TikTok profile"},
		{"instagram", "an Instagram profile"},
		{"youtube", "a YouTube profile"},
		// Unlisted platform.
		{"newnetwork", "a Newnetwork profile"},
	}
	for _, tc := range cases {
		t.Run(tc.platform, func(t *testing.T) {
			m := mkTyped(strings.ToUpper(tc.platform), 80, nil, map[string]any{"platform": tc.platform})
			if got := describeType(m); got != tc.want {
				t.Errorf("platform %s rendered %q, want %q", tc.platform, got, tc.want)
			}
		})
	}
}

// TestAClusterIsNotDescribedAsOneProfile. A cluster stands for several profiles collapsed into
// one synthesized finding, so "a social media profile" understates what the reviewer sees.
func TestAClusterIsNotDescribedAsOneProfile(t *testing.T) {
	got := describeType(mkTyped("SOCIAL_MEDIA_CLUSTER", 80, nil, nil))
	if !strings.Contains(got, "group") {
		t.Errorf("SOCIAL_MEDIA_CLUSTER rendered %q; it represents SEVERAL profiles", got)
	}
}

// TestTheVendorPathIsUnchanged. describeType prefers a vendor when one is present, and the
// acronym table must not have displaced that — "a Visa card" is the existing, correct output.
func TestTheVendorPathIsUnchanged(t *testing.T) {
	m := mkTyped("VISA", 90, nil, map[string]any{"vendor": "Visa", "card_type": "credit"})
	if got := describeType(m); got != "a Visa card" {
		t.Errorf("describeType with a vendor = %q, want %q", got, "a Visa card")
	}
}

// TestTheSuppressionReasonKeepsAcronymCase.
//
// draftSuppressReason lowercased describeType's whole result, which would have undone every
// entry in the table — "an SSN" back to "an ssn". Removing that call is part of the fix, so it
// is asserted rather than left to be re-added by someone tidying up.
func TestTheSuppressionReasonKeepsAcronymCase(t *testing.T) {
	for _, conf := range []float64{20, 70, 95} {
		m := mkTyped("SSN", conf, map[string]bool{"format": true}, nil)
		got := synth().draftSuppressReason(m, validationChecks(m), false)
		if strings.Contains(got, "an ssn") || strings.Contains(got, "a ssn") {
			t.Errorf("confidence %.0f: the suppression reason lowercased the acronym:\n  %s", conf, got)
		}
		if !strings.Contains(got, "SSN") {
			t.Errorf("confidence %.0f: the suppression reason does not name the type at all:\n  %s", conf, got)
		}
	}
}

// TestMod97IsNamedLikeTheOtherChecksums. humanizeCheck spells out "the Luhn checksum"; the
// IBAN proof is the same kind of thing and read as "the mod97 checksum check" without this.
func TestMod97IsNamedLikeTheOtherChecksums(t *testing.T) {
	if got := humanizeCheck("mod97_checksum"); got != "the mod-97 checksum" {
		t.Errorf("humanizeCheck(mod97_checksum) = %q, want %q", got, "the mod-97 checksum")
	}
}

// TestCardBrandsRenderViaTheVendorPath.
//
// This is the coverage a surviving mutation exposed. describeType prefers Metadata["vendor"], and
// creditcard sets vendor == Type for every brand, so the EqualFold branch collapses "a Visa visa"
// to "a Visa card". Adding a brand to typeDisplays breaks that: a "JCB" entry made t = "JCB card",
// which no longer equalled the vendor, and the output became "a JCB JCB card".
//
// So this asserts both directions — the brands render correctly, and no brand is in the table.
func TestCardBrandsRenderViaTheVendorPath(t *testing.T) {
	brands := map[string]string{
		"VISA":             "Visa",
		"MASTERCARD":       "Mastercard",
		"AMERICAN_EXPRESS": "American Express",
		"DISCOVER":         "Discover",
		"DINERS_CLUB":      "Diners Club",
		"JCB":              "JCB",
	}
	for typ, vendor := range brands {
		t.Run(typ, func(t *testing.T) {
			if _, listed := typeDisplays[typ]; listed {
				t.Fatalf("%s is in typeDisplays. Card brands must not be: the vendor path already "+
					"renders them, and a table entry breaks its EqualFold comparison — a JCB entry "+
					"produced \"a JCB JCB card\".", typ)
			}
			m := mkTyped(typ, 90, nil, map[string]any{"vendor": vendor, "card_type": "credit"})
			got := describeType(m)
			want := "a " + vendor + " card"
			if got != want {
				t.Errorf("describeType(%s, vendor=%s) = %q, want %q", typ, vendor, got, want)
			}
			if strings.Count(got, vendor) != 1 {
				t.Errorf("the vendor name appears %d times in %q", strings.Count(got, vendor), got)
			}
		})
	}
}

// TestNoTypeDisplaysEntrySetsAVendor is the structural half: a future entry for a type that also
// carries a vendor would reintroduce the doubling. Asserted over the table itself so it holds for
// entries nobody thought to test.
func TestNoTypeDisplaysEntrySetsAVendor(t *testing.T) {
	// The brands creditcard emits, which are the only types in the repo that set a vendor.
	vendorTypes := map[string]bool{
		"VISA": true, "MASTERCARD": true, "AMERICAN_EXPRESS": true,
		"DISCOVER": true, "DINERS_CLUB": true, "JCB": true,
	}
	for typ := range typeDisplays {
		if vendorTypes[typ] {
			t.Errorf("typeDisplays contains %q, which carries a vendor; describeType's vendor "+
				"branch will double the name", typ)
		}
	}
}
