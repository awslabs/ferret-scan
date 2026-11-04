// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// #883: card numbers that payment processors publish for their sandboxes were scored like real
// cards. Measured with the CLI on main, on "Card number: <value>" lines: 386 of the 492 values
// the six vendor pages in published_test_pans.go print scored 100 HIGH, and the test-pattern list
// matched 4 of the 492. The precommit profile exited 1 on a JSON fixture, a Jest test, a Java
// test class and a testing guide that held nothing but published test numbers.
//
// Everything in this file uses only symbols and helpers main also has, so it compiles against
// main and fails there by assertion. published_test_pans_test.go holds the tests that need the
// list itself.

// publishedSample is the issue's reproducer, the five values from the "Cards by brand" table of
// docs.stripe.com/testing, and one value from each other vendor block.
var publishedSample = []struct{ source, value string }{
	{"Stripe, 1st American Express", "378282246310005"},
	{"Stripe, JCB", "3566002020360505"},
	{"Stripe, Visa (shape-capped on main already)", "4242424242424242"},
	{"Stripe, 2nd Discover", "6011000990139424"},
	{"Stripe, Mastercard (prepaid)", "5105105105105100"},
	{"Adyen", "5555341244441115"},
	{"Authorize.net", "6011000000000012"},
	{"Braintree", "4012888888881881"},
	{"Checkout.com", "4276038578596818"},
	{"Square", "5248480000210026"},
}

// syntheticControl is Luhn-valid, Visa-prefixed and on no vendor page: the issue's control.
const syntheticControl = "4000123456789017"

// checksOf returns a match's validation checks.
func checksOf(t *testing.T, m detector.Match) map[string]bool {
	t.Helper()
	c, ok := m.Metadata["validation_checks"].(map[string]bool)
	if !ok {
		t.Fatalf("%s %q: no validation_checks in metadata %v", m.Type, m.Text, m.Metadata)
	}
	return c
}

// assertTestValue checks that m is reported as a test value: at most 15, not_test=false, and
// the 15 published as the ceiling the document bridge applies after its own adjustment.
func assertTestValue(t *testing.T, m detector.Match) {
	t.Helper()
	if m.Confidence > 15 {
		t.Errorf("%s %q on %q: confidence %.1f, want at most 15 (a published test number is LOW)",
			m.Type, m.Text, m.Context.FullLine, m.Confidence)
	}
	if checksOf(t, m)["not_test"] {
		t.Errorf("%s %q on %q: not_test=true, want false", m.Type, m.Text, m.Context.FullLine)
	}
	if c, ok := ceilingOf(m); !ok || c != 15 {
		t.Errorf("%s %q on %q: published ceiling %v (present=%v), want 15: without it the bridge "+
			"lifts the value again", m.Type, m.Text, m.Context.FullLine, c, ok)
	}
}

// TestPublishedTestNumbersAreCappedAtLow is the issue's reproducer: each published value in the
// line shapes the issue measured is reported, with its text unchanged, at LOW 15.
func TestPublishedTestNumbersAreCappedAtLow(t *testing.T) {
	v := NewValidator()
	for _, s := range publishedSample {
		for _, line := range []string{
			s.value,
			"Card number: " + s.value,
			`{"number": "` + s.value + `", "exp_month": 12, "exp_year": 2030, "cvc": "123"}`,
			`card_number = "` + s.value + `"`,
			"Sandbox card: " + s.value,
		} {
			t.Run(s.source+"/"+line, func(t *testing.T) {
				assertTestValue(t, onlyMatch(t, v, line, s.value))
			})
		}
	}

	// The cap is per value: on the same line, the control keeps main's score and no ceiling.
	line := "Card number: 378282246310005 " + syntheticControl
	assertTestValue(t, onlyMatch(t, v, line, "378282246310005"))
	assertUntouched(t, onlyMatch(t, v, line, syntheticControl), 100)
}

// TestCalculateConfidenceCapsPublishedTestNumbers: --explain and any caller that scores a value
// alone must agree with the scan.
func TestCalculateConfidenceCapsPublishedTestNumbers(t *testing.T) {
	v := NewValidator()
	for _, s := range publishedSample {
		for _, form := range []string{s.value, groupDigits(s.value, " "), groupDigits(s.value, "-")} {
			conf, checks := v.CalculateConfidence(form)
			if conf > 15 || checks["not_test"] {
				t.Errorf("%s: CalculateConfidence(%q) = %.1f, not_test=%v; want at most 15 and false",
					s.source, form, conf, checks["not_test"])
			}
		}
	}
	if conf, checks := v.CalculateConfidence(syntheticControl); conf != 95 || !checks["not_test"] {
		t.Errorf("control: CalculateConfidence(%q) = %.1f, not_test=%v; want main's 95 and true",
			syntheticControl, conf, checks["not_test"])
	}
}

// TestAPublishedValueOnAFlooredLineKeepsItsFifteen: the cap is the last step, so a value a
// negative word floored at 15 stays at 15. Sending it through the test-pattern clamp instead
// (the forced-5 path) took it to 1, which ranked it below every other floored value.
func TestAPublishedValueOnAFlooredLineKeepsItsFifteen(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct{ line, value string }{
		{"account_number_test: 4012888888881881", "4012888888881881"}, // goldencorpus context_keywords_snake_case
		{"Test card: 378282246310005", "378282246310005"},
		{"md5 hash 378282246310005", "378282246310005"},
	} {
		m := onlyMatch(t, v, tc.line, tc.value)
		if m.Confidence != 15 {
			t.Errorf("%q: confidence %.1f, want the floor's 15", tc.line, m.Confidence)
		}
		assertTestValue(t, m)
	}
}

// TestTheKeywordFloorStillPublishesNoCeiling is a control that passes on main too: the floor is
// a minimum the line's author chose, not a bound on the value, so an unlisted value it holds
// keeps main's score and metadata.
func TestTheKeywordFloorStillPublishesNoCeiling(t *testing.T) {
	v := NewValidator()
	assertUntouched(t, onlyMatch(t, v, "Test card: "+syntheticControl, syntheticControl), intrinsicValueFloor)
	m := onlyMatch(t, v, "name,card_number,exp\nTest card,"+syntheticControl+",12/30\n", syntheticControl)
	assertUntouched(t, m, 5) // main's 5; the CLI reports 25 after the CSV boost
}

// TestATestValueStaysLowThroughTheBridge runs the document bridge the scanner runs, on the CSV
// rows the issue measured. Its tabular boost (+20) lifted every shape-capped value from 15 to 35
// because the cap was never published; a published test number scored 100.
func TestATestValueStaysLowThroughTheBridge(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		max         float64 // the most the scan may report
		exact       bool    // max is the exact expected score
		ceiling     bool    // a ceiling must be published
	}{
		{"published Amex (main: 100)", "378282246310005", 15, false, true},
		{"published, shape-capped Stripe Visa (main: 35)", "4242424242424242", 15, false, true},
		{"unlisted test-pattern literal (main: 35)", "4444444444444448", 15, false, true},
		{"unlisted repeating shape (main: 35)", "4100000000000001", 15, false, true},
		{"control (main: 100)", syntheticControl, 100, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := bridgeOnlyMatch(t, NewValidator(), "name,card_number,exp\nJordan Q,"+tc.value+",12/30\n", "cards.csv", tc.value)
			checkBridged(t, m, tc.max, tc.exact, tc.ceiling)
		})
	}
	// The keyword floor's row: main's 25, and no ceiling.
	m := bridgeOnlyMatch(t, NewValidator(), "name,card_number,exp\nTest card,"+syntheticControl+",12/30\n", "cards.csv", syntheticControl)
	checkBridged(t, m, 25, true, false)
}

func checkBridged(t *testing.T, m detector.Match, limit float64, exact, ceiling bool) {
	t.Helper()
	if exact && m.Confidence != limit || !exact && m.Confidence > limit {
		t.Errorf("%s %q: reported %.1f after the bridge, want %s %.1f", m.Type, m.Text, m.Confidence,
			map[bool]string{true: "exactly", false: "at most"}[exact], limit)
	}
	if _, ok := ceilingOf(m); ok != ceiling {
		t.Errorf("%s %q: ceiling published = %v, want %v", m.Type, m.Text, ok, ceiling)
	}
}

// bridgeOnlyMatch scans content through the document bridge (validators.Detector, as
// core.ScanContent wires it) with v as the only validator, and returns the single match whose
// text is want.
func bridgeOnlyMatch(t *testing.T, v *Validator, content, filename, want string) detector.Match {
	t.Helper()
	var found []detector.Match
	for _, m := range bridgeScan(t, v, content, filename) {
		if m.Text == want {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("bridge scan of %q: want exactly one match for %q, got %d", content, want, len(found))
	}
	return found[0]
}

// bridgeScan runs content through the document bridge with v as the only validator.
func bridgeScan(t *testing.T, v *Validator, content, filename string) []detector.Match {
	t.Helper()
	d := validators.NewDetector(nil)
	if err := d.SetupValidators(map[string]detector.Validator{"CREDIT_CARD": v}); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}
	matches, err := d.ValidateProcessedContent(&preprocessors.ProcessedContent{
		OriginalPath:  filename,
		Filename:      filename,
		Text:          content,
		Format:        "Plain Text",
		ProcessorType: "plaintext",
		Success:       true,
	})
	if err != nil {
		t.Fatalf("ValidateProcessedContent: %v", err)
	}
	return matches
}

// TestTheTwoDeletedTestPatternsFailLuhn pins why #883 could delete them: the list is read after
// the Luhn check, and neither literal passes it, so neither could ever match.
func TestTheTwoDeletedTestPatternsFailLuhn(t *testing.T) {
	v := NewValidator()
	for _, n := range []string{"1234567890123456", "1212121212121212"} {
		if v.luhnCheck(n) {
			t.Errorf("luhnCheck(%s) = true; the entry was not dead", n)
		}
		if ms, _ := v.ValidateContent("Card number: "+n, "probe.txt"); len(ms) != 0 {
			t.Errorf("%s: reported %d matches, want none", n, len(ms))
		}
	}
}

// groupDigits writes a digits-only value in the grouping cards are printed in.
func groupDigits(n, sep string) string {
	cuts := map[int][]int{13: {4, 8, 12}, 14: {4, 10}, 15: {4, 10}, 16: {4, 8, 12}, 19: {4, 8, 12, 16}}[len(n)]
	out, prev := "", 0
	for _, c := range append(cuts, len(n)) {
		if out != "" {
			out += sep
		}
		out += n[prev:c]
		prev = c
	}
	return out
}
