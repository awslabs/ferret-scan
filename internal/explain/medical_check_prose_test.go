// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"strings"
	"testing"
)

// #537 gave medicalid its validation_checks, and humanizeCheck's fallback renders an unknown key as
// "the <words with underscores replaced> check". For a NEGATED key that produces prose a reviewer
// has to stop and parse:
//
//	not_phone_context      -> "it passed the not phone context check"
//	not_a_more_specific_id -> "it passed the not a more specific id check"
//	npi_checksum           -> "it passed the npi checksum check"   (doubled noun, lower-cased acronym)
//
// The rendered sentence is the entire product of --explain, so each of these has explicit prose.
// This test is the guard: a key added to a validator without a humanizeCheck entry falls back
// silently, and nothing else in the tree would notice.

// medicalCheckKeys are the keys medicalid records. Kept here rather than imported because
// internal/validators/medicalid imports nothing from this package and must not start.
var medicalCheckKeys = []string{
	"npi_checksum", "dea_checksum", "mbi_format",
	"not_phone_context", "not_an_npi", "not_other_number_type",
	"not_a_more_specific_id", "not_other_id_shape",
	"letters_and_digits", "mrn_label", "insurance_label",
	"provider_context", "prescriber_context", "medicare_context", "medical_context",
}

// TestEveryMedicalCheckRendersAsProse.
//
// The fallback is detectable: it always ends in " check" and contains the key's own words with
// underscores turned into spaces. A key that round-trips that way has no explicit prose.
func TestEveryMedicalCheckRendersAsProse(t *testing.T) {
	for _, key := range medicalCheckKeys {
		t.Run(key, func(t *testing.T) {
			got := humanizeCheck(key)
			fallback := "the " + strings.ReplaceAll(key, "_", " ") + " check"

			// A negated key must never reach the fallback: "the not phone context check" is the
			// prose this test exists to prevent.
			if strings.HasPrefix(key, "not_") && got == fallback {
				t.Errorf("humanizeCheck(%q) = %q — the fallback rendering of a negated key. Give "+
					"it explicit prose naming it as an EXCLUSION, which reads correctly in the "+
					"\"it passed ...\" frame the caller builds.", key, got)
			}
			// No key should render an acronym or a proper noun in lower case. "medicare" is
			// included because the fallback rendered "the medicare context check" in the same
			// sentence that spelled "Medicare MBI" correctly.
			for _, word := range []string{"npi", "dea", "mbi", "medicare"} {
				if strings.Contains(key, word) && strings.Contains(got, " "+word+" ") {
					t.Errorf("humanizeCheck(%q) = %q, which lower-cases %q — a proper noun or "+
						"acronym the rest of the sentence capitalises", key, got, word)
				}
			}
			if got == "" {
				t.Errorf("humanizeCheck(%q) is empty", key)
			}
		})
	}
}

// TestTheChecksumProseDoesNotClaimAChecksumAnMBILacks.
//
// An MBI has no check digit — its positional format is all the structural evidence there is. The
// prose must not imply otherwise, because a reviewer reading "checksum" concludes the value was
// arithmetically verified.
func TestTheChecksumProseDoesNotClaimAChecksumAnMBILacks(t *testing.T) {
	got := humanizeCheck("mbi_format")
	if strings.Contains(strings.ToLower(got), "checksum") || strings.Contains(strings.ToLower(got), "check digit") {
		t.Errorf("humanizeCheck(mbi_format) = %q, which claims an arithmetic proof. An MBI has no "+
			"check digit; the format is its only structural evidence.", got)
	}
	if !strings.Contains(strings.ToLower(got), "format") {
		t.Errorf("humanizeCheck(mbi_format) = %q, which does not say what was actually checked", got)
	}
}

// TestTheMedicalTestDataKeyIsOneOfTheHiddenSpellings.
//
// medicalid records "not_test_data". It must be in testCheckKeys, which does two things at once:
// the prose HIDES it (verdict() already reports that concept, and repeating it as a raw check name
// is the defect #363 fixed) and the verdict reads it to reach likely_test.
func TestTheMedicalTestDataKeyIsOneOfTheHiddenSpellings(t *testing.T) {
	const key = "not_test_data"
	var found bool
	for _, k := range testCheckKeys {
		if k == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("%q is not in testCheckKeys %v, so medicalid's test-data signal neither reaches "+
			"the verdict nor gets hidden from the prose", key, testCheckKeys)
	}
	// And it must actually be excluded from the narrated list.
	checks := map[string]bool{key: true, "npi_checksum": true}
	if got := passedChecks(checks); len(got) != 1 {
		t.Errorf("passedChecks(%v) = %v, want only the checksum: the test-data key must not be "+
			"narrated as a check", checks, got)
	}
}
