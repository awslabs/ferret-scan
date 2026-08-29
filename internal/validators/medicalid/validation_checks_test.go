// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #537: medicalid recorded no validation_checks on ANY of its five subtypes, so --explain had
// nothing to narrate for a medical identifier. Measured at HEAD, all five:
//
//	npi  type=NPI                 conf=100 validation_checks=<ABSENT>
//	dea  type=DEA_NUMBER          conf=95  validation_checks=<ABSENT>
//	mbi  type=MEDICARE_MBI        conf=85  validation_checks=<ABSENT>
//	mrn  type=MRN                 conf=90  validation_checks=<ABSENT>
//	ins  type=INSURANCE_MEMBER_ID conf=90  validation_checks=<ABSENT>
//
// An NPI carries a real CMS Luhn-80840 check digit — the single most useful thing to tell a
// reviewer deciding whether a 10-digit number is a provider identifier or a phone number — and the
// explanation never mentioned it. The rationale read "Flagged as an NPI; nearby context raised
// confidence by 20%", which restates the type and a confidence the reviewer was already shown.
//
// It was missed by #363 (which fixed four other validators) because its sentence was not EMPTY, so
// it did not read as "no rationale at all".
//
// THE CONSTRAINT these tests exist to enforce: every recorded check must be a decision the
// validator ALREADY made. A check reported true that was never tested is a false statement to a
// reviewer, which is worse than the missing block. So the varying checks below are asserted to
// actually VARY with input — a constant dressed as a decision would pass a presence-only test.

// checksFor runs the validator and returns the first match's validation_checks.
func checksFor(t *testing.T, content string) (map[string]bool, detector.Match) {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "t.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(ms) == 0 {
		t.Fatalf("no finding for %q, so nothing is being measured", content)
	}
	raw, present := ms[0].Metadata["validation_checks"]
	if !present {
		t.Fatalf("no validation_checks on a %s finding: --explain can only narrate the checks it "+
			"is given, so its rationale collapses to the type and a confidence the reviewer was "+
			"already shown (#537)", ms[0].Type)
	}
	checks, ok := raw.(map[string]bool)
	if !ok {
		t.Fatalf("validation_checks is %T, want map[string]bool — the explain layer reads it with "+
			"that exact type assertion and silently sees nothing otherwise", raw)
	}
	return checks, ms[0]
}

// TestEverySubtypeRecordsItsStructuralCheck is the regression test.
//
// Each subtype must name the check that is its actual structural evidence. Naming a specific key
// rather than asserting "any" is deliberate: a subtype cannot satisfy this by recording one
// throwaway boolean.
func TestEverySubtypeRecordsItsStructuralCheck(t *testing.T) {
	for _, tc := range []struct {
		name, content, wantType, wantKey string
	}{
		{"NPI", "NPI: 1234567893 for the provider\n", "NPI", "npi_checksum"},
		{"DEA", "DEA number: AB1234563 on file\n", "DEA_NUMBER", "dea_checksum"},
		{"MBI", "Medicare MBI: 1EG4-TE5-MK73\n", "MEDICARE_MBI", "mbi_format"},
		{"MRN", "medical record number: 5729183\n", "MRN", "mrn_label"},
		{"INSURANCE", "insurance member id: ABC123456789\n", "INSURANCE_MEMBER_ID", "letters_and_digits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks, m := checksFor(t, tc.content)
			if m.Type != tc.wantType {
				t.Fatalf("got type %s, want %s — the fixture is not exercising this subtype", m.Type, tc.wantType)
			}
			if len(checks) == 0 {
				t.Fatal("validation_checks is empty")
			}
			if _, found := checks[tc.wantKey]; !found {
				t.Errorf("%s records %v but not %q — a subtype must record the substantive "+
					"judgement it made, not merely some boolean", tc.wantType, checks, tc.wantKey)
			}
		})
	}
}

// TestTheCheckThatCarriesAChecksumIsTrue.
//
// NPI and DEA are the costly ones the issue names: both verify a real check digit, and a checksum
// is the strongest thing available to a reviewer. Failing it returns early, so a match that exists
// passed it — asserting the value guards against a future refactor recording it as varying and
// then getting the polarity wrong.
func TestTheCheckThatCarriesAChecksumIsTrue(t *testing.T) {
	for _, tc := range []struct{ name, content, key string }{
		{"NPI", "NPI: 1234567893 for the provider\n", "npi_checksum"},
		{"DEA", "DEA number: AB1234563 on file\n", "dea_checksum"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks, _ := checksFor(t, tc.content)
			if !checks[tc.key] {
				t.Errorf("%s is %v on an emitted match; the value was verified before the match "+
					"was built, so it must be true", tc.key, checks[tc.key])
			}
		})
	}
}

// TestTheVaryingChecksActuallyVary is the honesty test, and the most important one here.
//
// A check recorded as a constant but named like a decision is a false statement dressed as
// evidence. Each pair below differs ONLY in whether the context keyword is present, so the check
// must differ too. A presence-only test would pass on a hardcoded `true`.
func TestTheVaryingChecksActuallyVary(t *testing.T) {
	for _, tc := range []struct {
		name, key, withCtx, withoutCtx string
	}{
		{
			name: "provider_context", key: "provider_context",
			withCtx:    "Provider NPI: 1234567893 at the clinic\n",
			withoutCtx: "reference 1234567893\n",
		},
		{
			name: "prescriber_context", key: "prescriber_context",
			withCtx:    "DEA registration AB1234563 for the prescriber\n",
			withoutCtx: "code AB1234563\n",
		},
		{
			name: "medicare_context", key: "medicare_context",
			withCtx:    "Medicare beneficiary identifier 1EG4TE5MK73\n",
			withoutCtx: "token 1EG4TE5MK73\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			with, _ := checksFor(t, tc.withCtx)
			gotWith, present := with[tc.key]
			if !present {
				t.Fatalf("%q absent from %v", tc.key, with)
			}
			if !gotWith {
				t.Errorf("%s is false on a line that carries the context keyword: %q", tc.key, tc.withCtx)
			}

			// The no-context side may legitimately produce no finding at all for the weaker
			// subtypes; that is not a failure of this property, so it is skipped rather than
			// asserted into a false negative.
			ms, err := NewValidator().ValidateContent(tc.withoutCtx, "t.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Skipf("no finding without context for %q, so the false side cannot be observed "+
					"here — the true side above still shows the key is populated from input", tc.name)
			}
			raw, ok := ms[0].Metadata["validation_checks"].(map[string]bool)
			if !ok {
				t.Fatalf("no validation_checks on the no-context match")
			}
			if raw[tc.key] {
				t.Errorf("%s is TRUE on a line with no such context (%q). It is recorded as a "+
					"decision, so it must reflect one; a constant named like a check tells a "+
					"reviewer something the validator never determined.", tc.key, tc.withoutCtx)
			}
		})
	}
}

// TestTheTestDataCheckFlipsAndIsSpelledForTheVerdict.
//
// not_test_data uses one of internal/explain's testCheckKeys spellings, which does two things: the
// prose HIDES it (the verdict already reports that concept, so repeating it as a check would be
// noise) and the verdict picks it up as likely_test. Verified end to end: adding "Test" and
// "example" to an NPI line flips the verdict and appends "but it matches a known test/placeholder
// pattern".
//
// It is populated from strongNegativeKeywords — the same list analyzeContext already scores on —
// so the boolean and the score cannot disagree.
func TestTheTestDataCheckFlipsAndIsSpelledForTheVerdict(t *testing.T) {
	clean, _ := checksFor(t, "Provider NPI: 1234567893 at the clinic\n")
	if !clean["not_test_data"] {
		t.Errorf("not_test_data is false on a line with no test marker: %v", clean)
	}

	dirty, _ := checksFor(t, "Test NPI example: 1234567893 for the provider\n")
	if dirty["not_test_data"] {
		t.Errorf("not_test_data is TRUE on a line containing \"Test\" and \"example\": %v.\n"+
			"The validator already scores that line down through strongNegativeKeywords, so the "+
			"boolean must agree with the score it is derived from.", dirty)
	}
}

// TestNoCheckIsRecordedForADecisionTheValidatorDidNotMake bounds what may be claimed.
//
// The five subtypes have genuinely different evidence: only NPI and DEA verify a check digit, and
// an MBI has none at all. Recording a checksum for a subtype that cannot compute one would tell a
// reviewer a proof exists that does not.
func TestNoCheckIsRecordedForADecisionTheValidatorDidNotMake(t *testing.T) {
	mbi, _ := checksFor(t, "Medicare MBI: 1EG4-TE5-MK73\n")
	for _, forbidden := range []string{"npi_checksum", "dea_checksum", "luhn", "checksum"} {
		if _, present := mbi[forbidden]; present {
			t.Errorf("MEDICARE_MBI records %q, but an MBI has no check digit — the format is its "+
				"only structural evidence, and claiming a checksum asserts a proof that does not "+
				"exist", forbidden)
		}
	}

	mrn, _ := checksFor(t, "medical record number: 5729183\n")
	for _, forbidden := range []string{"npi_checksum", "dea_checksum", "mbi_format"} {
		if _, present := mrn[forbidden]; present {
			t.Errorf("MRN records %q; an MRN is a bare digit run with no checksum of its own", forbidden)
		}
	}
}
