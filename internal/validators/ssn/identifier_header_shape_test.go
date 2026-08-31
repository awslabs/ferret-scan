// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"testing"
)

// #389: the tabular header was consulted only as a NEGATIVE signal drawn from a fixed
// ~45-word list, so a column header naming a DIFFERENT identifier that nobody had added to
// that list got no demotion at all — a whole column of business IDs was reported at HIGH.
//
// Measured on 500-row, 4-column CSVs of SSN-shaped values, one column each:
//
//	header             before                    after
//	tracking_number    500 @ 55                  unchanged   (already on the negative list)
//	permit_number      500 @ 55                  unchanged   (already on the negative list)
//	parcel_id          500 @ 100 HIGH            500 @ 55
//	meter_number       498 @ 100 HIGH            500 @ 55
//	record_id          495 @ 100 HIGH            497 @ 55    (undashed \d{9})
//	ssn                500 @ 100 HIGH            unchanged
//	employee_id        500 @ 100 HIGH            unchanged
//
// End to end, the reported harm was a pre-commit hook blocked by a column of parcel
// numbers. Measured with --pre-commit-mode and FERRET_PRECOMMIT_EXIT_ON=high:
//
//	                 before   after
//	parcel_id.csv    rc=1     rc=0     <- no longer blocks
//	ssn.csv          rc=1     rc=1     <- still blocks, correctly
//
// Finding COUNTS are unchanged throughout. This CAPS at 55, it never drops: the value stays
// reported and therefore still reaches the redactor. Verified — redacting the capped
// parcel_id column still rewrites all 40 values, 0 cleartext survivors. So nothing leaves
// the sink; what changes is which review surface the value lands on.

// TestIdentifierShapedHeaderIsCapped is the regression test.
//
// None of these headers contains a word from negativeKeywords, which is exactly why they
// were missed: the old rule could only fire on vocabulary somebody had thought to add.
func TestIdentifierShapedHeaderIsCapped(t *testing.T) {
	for _, header := range []string{
		// The three from the issue.
		"parcel_id", "meter_number", "record_id",
		// Same shape, different separators — real exports use all three.
		"parcel id", "parcel-id", "Parcel ID",
		// Other identifier suffixes.
		"asset_no", "device_num", "shipment_ref", "lot_code", "vehicle_key",
		"claim_identifier", "batch_ids", "route_reference",
	} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)
			if n == 0 {
				t.Fatalf("no finding under %q: the value must stay REPORTED. Dropping it "+
					"would put it in cleartext in the redacted output, which is worse than "+
					"scoring it too high.", header)
			}
			if conf > contradictingHeaderCap {
				t.Errorf("confidence %.0f under a %q column, want <= %.0f.\n"+
					"This header names an identifier for something that is not a person, and "+
					"no word in it appears in negativeKeywords — which is why the fixed-list "+
					"arm missed it and a whole column scored HIGH (#389).",
					conf, header, contradictingHeaderCap)
			}
		})
	}
}

// TestIdentityShapedHeaderIsNotCapped is the half that protects recall, and it is the more
// important one: a demotion here is a real SSN pushed off the default review surface.
//
// employee_number is the case that caught a first version of this rule. It ignored the
// qualifier entirely, which demoted employee_number to 55 while employee_id stayed at 100 —
// the same concept judged differently by its suffix, which is the very inconsistency #389
// is about. govt_id was caught by the pre-existing TestSupportingHeaderIsUnaffected for the
// same reason.
func TestIdentityShapedHeaderIsNotCapped(t *testing.T) {
	for _, header := range []string{
		// Spelled-out US vocabulary.
		"ssn_number", "social_security_number", "social_security_no",
		"taxpayer_identification_number", "tax_number", "tax_id_number",
		"employee_number", "employee_id", "payroll_number", "personnel_number",
		"national_id", "federal_id_number", "government_id",
		// Abbreviations and non-US identity documents. These are not invented: the
		// pre-existing TestSupportingHeaderIsUnaffected already requires govt_id, sin,
		// nino, socsec and personnummer to stay HIGH. The single-token ones passed the
		// shape test by accident; these two-token forms are the ones that need the
		// qualifier vocabulary.
		"govt_id", "sin_number", "nino_number", "socsec_no",
		"tin_number", "ein_number", "itin_number",
		// Person-qualified identifiers. The scorecorpus labels c19_honest_member_id and
		// c20_honest_participant_id BandHigh -- US benefits and 401k exports really do
		// key on the SSN -- so these are the corpus's answer, not a guess.
		"member_id", "member_number", "participant_id", "patient_id",
		"beneficiary_id", "subscriber_number", "customer_id",
		// A qualifier made only of identifier words names nothing in particular.
		"id_number", "id_no",
	} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)
			if n == 0 {
				t.Fatalf("no finding under %q", header)
			}
			if conf <= contradictingHeaderCap {
				t.Errorf("confidence %.0f under a %q column, want > %.0f.\n"+
					"This header names a person-identity document, so a value under it is "+
					"exactly what this validator exists to find. Demoting it is lost recall, "+
					"and a value below the default surface is one a reviewer never sees.",
					conf, header, contradictingHeaderCap)
			}
		})
	}
}

// TestABareIdentifierHeaderIsNotCappedOnShapeAlone.
//
// A column called just "id" or "number" names no particular thing, so it is evidence
// neither way — and an export may well use it for an SSN. Capping on shape alone would
// demote it, so the rule requires a qualifier to be present at all.
// "code" is deliberately absent from this list: it is in negativeKeywords, so a bare "code"
// column is capped at 55 by the PRE-EXISTING vocabulary arm. That is unrelated to the shape
// rule and is not a behaviour this change touches — asserting otherwise made the test fail
// against correct code.
func TestABareIdentifierHeaderIsNotCappedOnShapeAlone(t *testing.T) {
	for _, header := range []string{"id", "number", "no", "identifier"} {
		t.Run(header, func(t *testing.T) {
			conf, n := scanCSV(t, header)
			if n == 0 {
				t.Fatalf("no finding under %q", header)
			}
			if conf <= contradictingHeaderCap {
				t.Errorf("confidence %.0f under a bare %q column, want > %.0f: the header "+
					"names nothing in particular, so there is no evidence to demote on",
					conf, header, contradictingHeaderCap)
			}
		})
	}
}

// TestTheShapeRuleIsTabularOnly.
//
// The cap lives inside the isTabular branch, and it has to stay there. In prose the same
// words are just words: "The parcel id 431-29-7468 was recorded" must not be demoted by a
// rule about column headers, because there is no column.
//
// This is asserted rather than assumed because the fix that this issue's own notes rejected
// was a tabular heuristic that leaked into prose and deleted labelled SSNs.
func TestTheShapeRuleIsTabularOnly(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"The parcel id 431-29-7468 was recorded in the county register",
		"Meter number 431-29-7468 replaced on Tuesday",
		"record id 431-29-7468",
	} {
		t.Run(line[:20], func(t *testing.T) {
			ms, err := v.ValidateContent(line+"\n", "prose.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Skipf("prose line produced no finding at all, so there is nothing to "+
					"demote: %q", line)
			}
			// The point is only that the TABULAR cap did not apply. Prose scoring is the
			// pre-existing behaviour and is not what this change touches.
			for _, m := range ms {
				if _, capped := m.Metadata[confidenceCeilingKey]; capped {
					t.Errorf("a prose line published %s, so the tabular header cap reached "+
						"text with no columns: %q", confidenceCeilingKey, line)
				}
			}
		})
	}
}

// TestQualifierVocabularyFollowsPositiveKeywords states the property that keeps the two
// lists in step.
//
// The qualifier test consults positiveKeywords by PREFIX as well as the abbreviation set,
// so a keyword added to positiveKeywords later is honoured without a second edit. Prefix
// and not substring, deliberately: substring matching would let "record" through via
// "employee record" and lose record_id, one of the reported cases.
func TestQualifierVocabularyFollowsPositiveKeywords(t *testing.T) {
	v := NewValidator()

	// Every positive keyword's FIRST word must qualify, since "<firstword>_number" is the
	// same concept the keyword names.
	for _, kw := range v.positiveKeywords {
		first := kw
		if i := indexByte(kw, ' '); i > 0 {
			first = kw[:i]
		}
		if !v.qualifierIsSSNAdjacent(first) {
			t.Errorf("positive keyword %q begins with %q, but %q does not qualify — so a "+
				"%s_number column would be capped while %s_id is not", kw, first, first, first, first)
		}
	}

	// And the substring trap: "record" must NOT qualify via "employee record".
	if v.qualifierIsSSNAdjacent("record") {
		t.Error("\"record\" qualifies as SSN-adjacent, which it must not: it only appears as " +
			"the SECOND word of \"employee record\". Matching it would restore the record_id " +
			"defect this change fixes.")
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
