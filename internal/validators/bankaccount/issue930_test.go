// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"testing"
)

// #930: the published fictitious example IBAN read IBAN 100 HIGH, alone on a line, on main @
// 2fb4719. These tests use only ValidateContent and symbols the parent commit has, so they run
// unchanged against it, where the example rows fail and the controls pass.

// wantPublishedCeiling is publishedExampleCeiling, written out so this file compiles against the
// parent commit; TestPublishedExampleCeilingIsLow pins the two together.
const wantPublishedCeiling = 15.0

func publishedIBANFindings(t *testing.T, content string) []float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range matches {
		if m.Type == "IBAN" {
			got = append(got, m.Confidence)
		}
	}
	return got
}

// TestThePublishedExampleIBANIsHeldAtLow: every spelling of the value, still reported.
func TestThePublishedExampleIBANIsHeldAtLow(t *testing.T) {
	for _, line := range []string{
		"IBAN: GB82 WEST 1234 5698 7654 32",
		"IBAN: GB82WEST12345698765432",
		"iban gb82west12345698765432",
		"Pay to IBAN GB82-WEST-1234-5698-7654-32 by Friday",
		"bank account IBAN: GB82WEST12345698765432 for wire transfers", // positive keywords do not lift it
	} {
		got := publishedIBANFindings(t, line)
		if len(got) != 1 {
			t.Errorf("%q: %d IBAN findings (%v), want 1: a published example is capped, never dropped", line, len(got), got)
			continue
		}
		if got[0] > wantPublishedCeiling {
			t.Errorf("%q: IBAN at %v, want at most %v", line, got[0], wantPublishedCeiling)
		}
	}
}

// TestThePublishedExampleCeilingIsPublished: the bridge adds a document-level adjustment after this
// validator returns, so the cap holds only when the ceiling is in the metadata.
func TestThePublishedExampleCeilingIsPublished(t *testing.T) {
	for _, line := range []string{"IBAN: GB82WEST12345698765432", "IBAN: GB82 WEST 1234 5698 7654 32"} {
		matches, err := NewValidator().ValidateContent(line, "probe.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		if len(matches) != 1 {
			t.Fatalf("%q: %d matches, want 1", line, len(matches))
		}
		if c, ok := matches[0].Metadata[confidenceCeilingKey].(float64); !ok || c != wantPublishedCeiling {
			t.Errorf("%q: %s = %v, want float64 %v", line, confidenceCeilingKey, matches[0].Metadata[confidenceCeilingKey], wantPublishedCeiling)
		}
	}
}

// TestAnIBANOneDigitAwayKeepsItsScore is the control #930 asks for: a mod-97-valid value one
// account digit away from the example is a different IBAN and is not demoted, and neither is the
// German example #930 also names, which this change does not list (see publishedExampleIBANs).
func TestAnIBANOneDigitAwayKeepsItsScore(t *testing.T) {
	for _, line := range []string{
		"IBAN: GB55WEST12345698765433",
		"IBAN: GB55 WEST 1234 5698 7654 33",
		"IBAN: GB12WEST12345698765431",
		"IBAN: DE89370400440532013000",
	} {
		got := publishedIBANFindings(t, line)
		if len(got) != 1 || got[0] < 90 {
			t.Errorf("%q: IBAN %v, want one finding at HIGH", line, got)
		}
		matches, _ := NewValidator().ValidateContent(line, "probe.txt")
		for _, m := range matches {
			if _, ok := m.Metadata[confidenceCeilingKey]; ok {
				t.Errorf("%q: an unlisted IBAN published a confidence ceiling", line)
			}
		}
	}
}
