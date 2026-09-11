package bankaccount

import (
	"strings"
	"testing"
)

// theFormerDenylist is the exact contents of the testRoutingNumbers map deleted
// in #628, with the property that made each entry either harmless or a leak.
//
// Kept verbatim as data rather than deleted with the map, because the map's
// failure was not a typo — it was a category error that any future
// "known test values" list will repeat. Two real bank routing numbers sat in a
// list of obvious placeholders and nothing distinguished them, so a reviewer
// scanning fourteen nine-digit literals had no way to see that twelve were
// synthetic and two were live. The tests below re-derive that split from the ABA
// spec instead of trusting a comment.
var theFormerDenylist = []struct {
	value string
	real  bool // passes the ABA prefix range AND the checksum: a live routing number
	why   string
}{
	{"011000015", true, "Federal Reserve Bank of Boston"},
	{"021000021", true, "JPMorgan Chase"},
	{"000000000", false, "prefix 00 is outside every assigned ABA range"},
	{"123456789", false, "checksum fails (and the digits are a consecutive run)"},
	{"111111111", false, "checksum fails"},
	{"222222222", false, "checksum fails"},
	{"333333333", false, "prefix 33 is outside every assigned ABA range"},
	{"444444444", false, "prefix 44 is outside every assigned ABA range"},
	{"555555555", false, "prefix 55 is outside every assigned ABA range"},
	{"666666666", false, "checksum fails"},
	{"777777777", false, "prefix 77 is outside every assigned ABA range"},
	{"888888888", false, "prefix 88 is outside every assigned ABA range"},
	{"999999999", false, "prefix 99 is outside every assigned ABA range"},
	{"987654321", false, "prefix 98 is outside every assigned ABA range"},
}

// TestEveryFormerDenylistEntryIsRejectedOnItsOwnMerits proves the denylist was
// removable without losing a single false-positive defence.
//
// The arithmetic, not the intent, is the claim: for each entry, isValidABA's
// verdict must match the `real` column. Twelve are rejected by the ABA spec
// alone, so the denylist never got to see them and deleting it changes nothing
// about them. Two pass, so the denylist's entire net effect was to suppress
// those two.
//
// This is also the guard the deletion comment in scanABA points at. isValidABA's
// prefix table is the thing keeping the twelve out; widen it and some of them
// become findings. 000000000 is the near miss — its checksum is 0, which is
// congruent to 0 mod 10, so ONLY the prefix test stands between it and a HIGH
// confidence report. This test fails the moment that changes.
func TestEveryFormerDenylistEntryIsRejectedOnItsOwnMerits(t *testing.T) {
	v := NewValidator()
	realCount := 0
	for _, e := range theFormerDenylist {
		got := v.isValidABA(e.value)
		if got != e.real {
			t.Errorf("isValidABA(%s) = %v, want %v (%s)", e.value, got, e.real, e.why)
		}
		if e.real {
			realCount++
		}
	}
	if realCount != 2 {
		t.Errorf("expected exactly 2 real routing numbers in the former denylist, got %d", realCount)
	}
}

// TestRealRoutingNumbersAreReported is the sink-rule half of #628.
//
// Only reported findings reach the redactor, so a suppressed routing number is
// not a quiet scoring choice — it is cleartext in a document the user was told
// was redacted. Every entry the ABA spec accepts must therefore survive the
// whole scan path, not just isValidABA.
func TestRealRoutingNumbersAreReported(t *testing.T) {
	v := NewValidator()
	for _, e := range theFormerDenylist {
		if !e.real {
			continue
		}
		content := "Routing number: " + e.value + "\n"
		matches, err := v.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%s) error = %v", e.value, err)
		}
		found := false
		for _, m := range matches {
			if m.Type == "ABA_ROUTING" && strings.Contains(m.Text, e.value) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s (%s) not reported as ABA_ROUTING: got %v — a suppressed routing "+
				"number is left in the cleartext of redacted output", e.value, e.why, matchTypes(matches))
		}
	}
}

// TestRealRoutingNumbersAreNotCalledTestValues covers the second, separate path.
//
// CalculateConfidence carries its own copy of the decision and fed the same map,
// so --explain reported a live JPMorgan Chase routing number with a failed
// not_test check and a likely_test verdict. Fixing scanABA alone would have left
// that in place: two call sites, two fixes.
func TestRealRoutingNumbersAreNotCalledTestValues(t *testing.T) {
	v := NewValidator()
	for _, e := range theFormerDenylist {
		conf, checks := v.CalculateConfidence(e.value)
		if e.real {
			if !checks["not_test"] {
				t.Errorf("CalculateConfidence(%s): not_test=false for a real routing number (%s)", e.value, e.why)
			}
			if !checks["checksum"] {
				t.Errorf("CalculateConfidence(%s): checksum=false, but it passes the ABA checksum", e.value)
			}
			if conf < 60 {
				t.Errorf("CalculateConfidence(%s) = %.1f, want >= 60 for a checksum-valid routing number", e.value, conf)
			}
			continue
		}
		// The twelve synthetic values keep the demotion they always had; the shape
		// rule has to reproduce the map's verdict on all of them or the fix traded
		// one accuracy bug for another.
		if conf > 30 {
			t.Errorf("CalculateConfidence(%s) = %.1f, want <= 30 for a synthetic value (%s)", e.value, conf, e.why)
		}
	}
}

// TestIsTestPatternDigits pins the predicate that replaced the map.
//
// The two columns that matter are the last two: real routing numbers whose digits
// are unremarkable must not be caught by a shape rule, or the fix has merely
// moved the false suppression from a map lookup into a predicate.
func TestIsTestPatternDigits(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		{"000000000", true, "all zeros"},
		{"111111111", true, "all same"},
		{"999999999", true, "all same"},
		{"123456789", true, "ascending run"},
		{"987654321", true, "descending run"},
		{"1234", true, "shortest ascending run the rule accepts"},
		{"0000", true, "shortest all-same run the rule accepts"},
		{"111", false, "under the 4-digit floor: too short for the shape to mean anything"},
		{"12", false, "under the 4-digit floor"},
		{"", false, "empty"},
		{"011000015", false, "REAL: Federal Reserve Bank of Boston"},
		{"021000021", false, "REAL: JPMorgan Chase"},
		{"021000089", false, "REAL: a routing number the suite already expects to detect"},
		{"011401533", false, "REAL: a routing number the suite already expects to detect"},
		{"071000013", false, "REAL: a routing number the suite already expects to detect"},
		{"123456780", false, "ascending but broken at the last digit"},
		{"1234567890", false, "9 wraps to 0, which is not a consecutive step"},
	}
	for _, c := range cases {
		if got := isTestPatternDigits(c.in); got != c.want {
			t.Errorf("isTestPatternDigits(%q) = %v, want %v (%s)", c.in, got, c.want, c.why)
		}
	}
}
