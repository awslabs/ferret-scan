// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// The surname list holds ~2.3K entries against an unbounded population, so it will
// always be incomplete, and PR #282's gate makes an absent surname unreportable at
// EVERY confidence level — which means never redacted. Extending the data closes the
// names we know about; this arm bounds the ones we do not.
//
// A title or a generational suffix states that the following tokens are a person's
// name, independently of any database. Measured before this, with a surname absent from
// the list:
//
//	Dr. Elena Brightwater reviewed the chart.   not reported
//	Ms. Priya Thorncastle filed the report.     not reported
//	Thomas Vellamore Jr. signed today.          not reported
//
// The cap is the point. An unverified surname must never present as HIGH, so the
// ceiling is applied after context rather than as a penalty context can out-vote —
// the same shape as the reserved-value ceilings in PR #365.

func topFor(t *testing.T, line string) (float64, bool) {
	t.Helper()
	v := NewValidator()
	ms, err := v.ValidateContent(line, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	best, found := 0.0, false
	for _, m := range ms {
		found = true
		if m.Confidence > best {
			best = m.Confidence
		}
	}
	return best, found
}

// An explicit marker admits an off-list surname, at the ceiling and no higher.
func TestExplicitMarkerAdmitsAnOffListSurnameAtTheCeiling(t *testing.T) {
	for _, line := range []string{
		"Dr. Elena Brightwater reviewed the chart.",
		"Ms. Priya Thorncastle filed the report.",
		"Mr. Alan Vellamore approved it.",
		"Thomas Vellamore Jr. signed today.",
	} {
		got, found := topFor(t, line)
		if !found {
			t.Errorf("%q reported nothing. An unreported name is never redacted, and the "+
				"surname list cannot be complete.", line)
			continue
		}
		if got > unverifiedSurnameCeiling {
			t.Errorf("%q scored %.0f, above the ceiling %.0f. A surname the database cannot "+
				"confirm must not present as HIGH; the ceiling is applied after context so "+
				"context cannot lift it.", line, got, unverifiedSurnameCeiling)
		}
	}
}

// Without a marker, an off-list surname stays rejected. This is the boundary that keeps
// PR #282's false-positive fix intact: a bare two-token Title-Case shape is exactly
// what "Rich Text" and "The Grace Period" are.
func TestNoMarkerMeansStillRejected(t *testing.T) {
	for _, line := range []string{
		"Marcus Brightwater signed the contract.",
		"Please review the Rich Text format.",
		"The Grace Period expires Friday.",
		"Frank Discussion about the Art Director role.",
	} {
		if got, found := topFor(t, line); found {
			t.Errorf("%q reported at %.0f. Admitting a bare two-token shape without database "+
				"confirmation reinstates the false-positive class PR #282 removed (14 of 20 "+
				"decoy phrases).", line, got)
		}
	}
}

// Comma forms are excluded from the escape, and the exclusion is measured rather than
// assumed: document structure imitates "Surname, Given" exactly.
func TestCommaFormIsNotAnExplicitMarker(t *testing.T) {
	v := NewValidator()
	for _, p := range []string{"last_comma_first", "last_comma_first_middle", "last_comma_first_initial"} {
		if v.hasExplicitNameMarker(p) {
			t.Errorf("hasExplicitNameMarker(%q) = true. A comma is punctuation, not evidence of "+
				"personhood: \"Overview, Introduction\" and \"Appendix, Summary\" have the same "+
				"shape and are rejected today only because those words are not surnames.", p)
		}
		// isFormalNamePattern DOES include them; the escape is a strict subset.
		if !v.isFormalNamePattern(p) {
			t.Errorf("isFormalNamePattern(%q) = false; the subset relationship this test "+
				"documents no longer holds", p)
		}
	}

	for _, line := range []string{
		"Brightwater, Elena approved the request.",
		"Overview, Introduction follows on page two.",
		"Appendix, Summary is attached.",
	} {
		if got, found := topFor(t, line); found {
			t.Errorf("%q reported at %.0f — the comma-form escape is admitting document "+
				"structure as a person", line, got)
		}
	}
}

// A database-confirmed name must still outrank an unverified one, otherwise the ceiling
// has flattened the signal it exists to preserve.
func TestConfirmedSurnameOutranksUnverified(t *testing.T) {
	confirmed, ok1 := topFor(t, "Dr. Elena Papadopoulos reviewed the chart.")
	unverified, ok2 := topFor(t, "Dr. Elena Brightwater reviewed the chart.")
	if !ok1 || !ok2 {
		t.Fatalf("expected both to report; confirmed=%v unverified=%v", ok1, ok2)
	}
	if confirmed <= unverified {
		t.Errorf("a database-confirmed surname scored %.0f, no higher than an unverified one "+
			"at %.0f — the ceiling must bound the unverified case, not erase the difference",
			confirmed, unverified)
	}
}

// The ceiling must survive heavy positive context. Against a fixed penalty instead of a
// ceiling, the sparse case passes and the loaded one does not.
func TestContextCannotLiftTheUnverifiedCeiling(t *testing.T) {
	base := "Dr. Elena Brightwater"
	for i, line := range []string{
		base,
		"Employee " + base,
		"Employee contact name: " + base,
		"Patient employee customer contact name for the record: " + base + ", signatory",
	} {
		got, found := topFor(t, line)
		if !found {
			t.Fatalf("case %d: %q reported nothing", i, line)
		}
		if got > unverifiedSurnameCeiling {
			t.Errorf("case %d: with more context %q reached %.0f (> %.0f). The ceiling is "+
				"being applied as a penalty context can out-vote.", i, strings.TrimSpace(line), got, unverifiedSurnameCeiling)
		}
	}
}
