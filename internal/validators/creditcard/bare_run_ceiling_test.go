// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// #802: a bare digit run that passes Luhn reached VISA 95 HIGH with no card word anywhere,
// because calculateConfidence scores the digits alone (60 + 15 known vendor + 10 non-repeating
// + 10 entropy) and nothing in the scan required card context for HIGH. One random run in ten
// passes Luhn, so request counters and row counts were reported as confirmed cards.
//
// The fix is a ceiling, not a veto: a bare run whose line carries no keyword at all, and which
// no identifier or column header names as a card, is held to MEDIUM 75 and stays reported, so
// redaction still covers it. The ceiling is published as the bridge's confidence_ceiling key so
// a document-level adjustment cannot lift it back to HIGH.
//
// Everything here is written against values main also produces, with no reference to new
// symbols, so this file compiles against main and fails there by assertion.

// heldTo is bareRunCeiling, spelled out so the expectation does not move with the constant.
const heldTo = 75.0

// ceilingOf returns the ceiling a match publishes under the bridge's key, and whether it
// publishes one the bridge would honour (a positive float64; validators.clampToCeiling ignores
// anything else).
func ceilingOf(m detector.Match) (float64, bool) {
	raw, ok := m.Metadata[validators.ConfidenceCeilingKey]
	if !ok {
		return 0, false
	}
	c, ok := raw.(float64)
	return c, ok && c > 0
}

// onlyMatch scans content and returns the single match whose text is want.
func onlyMatch(t *testing.T, v *Validator, content, want string) detector.Match {
	t.Helper()
	matches, err := v.ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	var found []detector.Match
	for _, m := range matches {
		if m.Text == want {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("ValidateContent(%q): want exactly one match for %q, got %d of %d matches",
			content, want, len(found), len(matches))
	}
	return found[0]
}

// assertHeld checks that m is held at the ceiling: confidence exactly want, a ceiling the bridge
// can read, and that ceiling inside MEDIUM.
func assertHeld(t *testing.T, m detector.Match, want float64) {
	t.Helper()
	if m.Confidence != want {
		t.Errorf("%s %q: confidence %.1f, want %.1f (a bare run with no card label must not "+
			"score HIGH on its digits alone)", m.Type, m.Text, m.Confidence, want)
	}
	c, ok := ceilingOf(m)
	if !ok {
		t.Errorf("%s %q: no usable %q in metadata (%v); without it the document bridge's "+
			"context adjustment lifts the value straight back past the ceiling",
			m.Type, m.Text, validators.ConfidenceCeilingKey, m.Metadata[validators.ConfidenceCeilingKey])
		return
	}
	if c != heldTo {
		t.Errorf("%s %q: published ceiling %.1f, want %.1f", m.Type, m.Text, c, heldTo)
	}
	if c < 60 || c >= 90 {
		t.Errorf("published ceiling %.1f is outside MEDIUM [60, 90): the rule is MEDIUM, "+
			"not a demotion to LOW and not a cosmetic cap inside HIGH", c)
	}
}

// assertUntouched checks that m keeps its score and carries no ceiling.
func assertUntouched(t *testing.T, m detector.Match, want float64) {
	t.Helper()
	if m.Confidence != want {
		t.Errorf("%s %q: confidence %.1f, want today's %.1f", m.Type, m.Text, m.Confidence, want)
	}
	if c, ok := ceilingOf(m); ok {
		t.Errorf("%s %q: carries a %.1f ceiling it must not have", m.Type, m.Text, c)
	}
}

// TestBareRunWithNoCardLabelIsHeldToMedium is the issue's reproducer and the lengths it
// generalises to. Measured on main, every held value below was VISA/MASTERCARD 95 HIGH.
func TestBareRunWithNoCardLabelIsHeldToMedium(t *testing.T) {
	v := NewValidator()

	// The reproducer from #802, verbatim. Line 2 is the HIGH 95 the issue reports. Line 1's two
	// values are NOT held: "test" in "load test window" is a negative word, which already scores
	// them to the intrinsic floor, so they stay 15 LOW with no ceiling (see bareRunCeiling).
	issue := "Requests served: 46761402970530 and 538797521336000 during the load test window.\n" +
		"Row counter reached 4145723220667500 by the end of the run.\n"
	assertHeld(t, onlyMatch(t, v, issue, "4145723220667500"), heldTo)
	assertUntouched(t, onlyMatch(t, v, issue, "46761402970530"), intrinsicValueFloor)
	assertUntouched(t, onlyMatch(t, v, issue, "538797521336000"), intrinsicValueFloor)

	// The same counters on lines with no negative word: every PAN length the pattern accepts.
	for _, tc := range []struct{ line, value string }{
		{"Requests served: 46761402970530 during the window.", "46761402970530"},   // 14 digits
		{"Requests served: 538797521336000 during the window.", "538797521336000"}, // 15 digits
		{"Row counter reached 4145723220667500 by the end of the run.", "4145723220667500"},
		{"Batch size 4917364820515 rows.", "4917364820515"},           // 13 digits
		{"Trace 4917364820519473617 closed.", "4917364820519473617"},  // 19 digits
		{"4145723220667500", "4145723220667500"},                      // alone on its line
		{`{"rowCount": "4145723220667500"}`, "4145723220667500"},      // camelCase key, no card word
		{"<RowCount>4145723220667500</RowCount>", "4145723220667500"}, // PascalCase element
		{"rows_read=4145723220667500", "4145723220667500"},            // snake_case key
		{"Alice\t4145723220667500\tus-east-1", "4145723220667500"},    // tabular +10 still held
	} {
		t.Run(tc.line, func(t *testing.T) {
			assertHeld(t, onlyMatch(t, v, tc.line, tc.value), heldTo)
		})
	}

	// A CSV export whose column header names something other than a card. Measured on main the
	// row scored 100 here (95 plus the tabular +10, clamped).
	counters := "id,host,requests\n1,web-01,4145723220667500\n2,web-02,4532015112830366\n"
	assertHeld(t, onlyMatch(t, v, counters, "4145723220667500"), heldTo)
	assertHeld(t, onlyMatch(t, v, counters, "4532015112830366"), heldTo)
}

// TestACardLabelClearsTheBareRunCeiling is the scope proof, and each case is paired with a twin
// that differs only in the label, so the case cannot pass by every value scoring the same. The
// labelled side keeps exactly main's score with no ceiling; the twin without the label is held.
func TestACardLabelClearsTheBareRunCeiling(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct {
		name               string
		labelled, labelVal string
		want               float64 // main's score for the labelled side
		twin, twinVal      string
	}{
		// The two controls from the issue's acceptance criteria. The issue says "today's 95" for
		// the first; main scores it 100 (95 plus the +15 card-word boost, clamped).
		{"card word on the line", "card: 4145723220667500", "4145723220667500", 100,
			"row: 4145723220667500", "4145723220667500"},
		{"space-separated groups", "4145 7232 2066 7500", "4145 7232 2066 7500", 95,
			"4145723220667500", "4145723220667500"},
		{"dash-separated groups", "4145-7232-2066-7500", "4145-7232-2066-7500", 95,
			"4145723220667500", "4145723220667500"},
		// The existing golden positives (creditcard_brands): a brand word on the line.
		{"visa brand word", "visa 4532015112830366", "4532015112830366", 100,
			"rows 4532015112830366", "4532015112830366"},
		{"amex brand word", "amex 374245455400126", "374245455400126", 100,
			"rows 374245455400126", "374245455400126"},
		// A card word inside an identifier, the shape JSON and XML write.
		{"camelCase JSON key", `{"cardNumber": "4532015112830366"}`, "4532015112830366", 95,
			`{"rowNumber": "4532015112830366"}`, "4532015112830366"},
		{"PascalCase XML element", "<CreditCard>4532015112830366</CreditCard>", "4532015112830366", 95,
			"<RowCount>4532015112830366</RowCount>", "4532015112830366"},
		{"snake_case key", "card_number=4532015112830366", "4532015112830366", 100,
			"row_number=4532015112830366", "4532015112830366"},
		// The card word lives only in the header row of a delimited export.
		{"CSV header names the column", "id,name,card_number\n1,Alice,4532015112830366\n", "4532015112830366", 100,
			"id,name,row_number\n1,Alice,4532015112830366\n", "4532015112830366"},
		{"camelCase CSV header", "id,name,cardNumber\n1,Alice,4532015112830366\n", "4532015112830366", 100,
			"id,name,rowNumber\n1,Alice,4532015112830366\n", "4532015112830366"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertUntouched(t, onlyMatch(t, v, tc.labelled, tc.labelVal), tc.want)
			assertHeld(t, onlyMatch(t, v, tc.twin, tc.twinVal), heldTo)
		})
	}

	// The label is per column: in the same row, only the value under the card header is cleared.
	mixed := "id,requests,card\n1,4145723220667500,4532015112830366\n"
	assertHeld(t, onlyMatch(t, v, mixed, "4145723220667500"), heldTo)
	assertUntouched(t, onlyMatch(t, v, mixed, "4532015112830366"), 100)
}

// TestTheBareRunCeilingSurvivesTheBridge replays what the document bridge does after this
// validator returns: add the document-context adjustment, then clamp to the published ceiling.
//
// Measured with the CLI on main: an unknown-vendor bare run in a CSV data row scored 70 here,
// already under the ceiling, and was reported at 90 HIGH after the bridge's +20 tabular boost.
// A ceiling published only when it lowered the score would have left that value unbounded.
func TestTheBareRunCeilingSurvivesTheBridge(t *testing.T) {
	v := NewValidator()
	const value = "9173648205194739" // Luhn-valid, prefix 917364 is outside every BIN range

	m := onlyMatch(t, v, "id,host,requests\n1,web-01,"+value+"\n", value)
	if m.Confidence != 70 {
		t.Fatalf("precondition: want the validator's own 70 for an unknown-vendor tabular run, got %.1f", m.Confidence)
	}
	c, ok := ceilingOf(m)
	if !ok {
		t.Fatalf("a held value under the ceiling must still publish %q for the bridge; metadata %v",
			validators.ConfidenceCeilingKey, m.Metadata)
	}

	// The bridge: += adjustment (tabular_boost is +20 for a CSV document), then clamp.
	reported := m.Confidence + 20
	if reported > c {
		reported = c
	}
	if reported >= 90 {
		t.Errorf("after the bridge's +20 and the clamp, reported %.1f is HIGH; want at most %.1f", reported, c)
	}
}

// TestANegativeWordKeepsItsFloorAndGetsNoCeiling locks the boundary bareRunCeiling draws. A
// negative word on the line already scores a bare run to the intrinsic floor, and the bridge's
// largest adjustment (+50) cannot take that past 65, so a published ceiling there could never
// bind: those values keep main's score and metadata. Each is paired with its twin minus the
// negative word, which IS held, so the line's word is shown to be what decides it.
func TestANegativeWordKeepsItsFloorAndGetsNoCeiling(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct{ line, twin, value string }{
		{"order id: 4532015112830366 catalog", "catalog: 4532015112830366", "4532015112830366"}, // soft negative
		{"imei 490154203237518 on the handset", "490154203237518 on the handset", "490154203237518"},
		{"account_number_test: 4012888888881881", "number: 4012888888881881", "4012888888881881"}, // hard, snake_case
		{"md5 hash 4532015112830366", "4532015112830366", "4532015112830366"},                     // hard negative
	} {
		t.Run(tc.line, func(t *testing.T) {
			assertUntouched(t, onlyMatch(t, v, tc.line, tc.value), intrinsicValueFloor)
			assertHeld(t, onlyMatch(t, v, tc.twin, tc.value), heldTo)
		})
	}
}
