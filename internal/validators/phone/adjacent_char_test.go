// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "testing"

// TestLabelWithoutSpaceIsNotEmbedding covers the worst polarity in the
// validator: the phone LABEL was itself the veto.
//
// isEmbeddedInIdentifierAt rejected any match whose preceding character was
// ':', and that arm ran BEFORE the label vocabulary that distinguishes "Tel:"
// from "session:". So writing a label without a space after the colon -- the way
// directory listings, vCards and CSV exports routinely do -- deleted the
// finding, and because only reported findings reach the redactor, the number
// survived in cleartext.
func TestLabelWithoutSpaceIsNotEmbedding(t *testing.T) {
	v := NewValidator()

	for _, label := range []string{"Tel", "Phone", "Fax", "Mobile", "Cell", "Telephone", "Contact"} {
		line := "Branch line " + label + ":415-267-1234"
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "directory.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("a phone label with no space after the colon deleted the finding: %s", line)
			}
		})
	}
}

// TestIdentifierLabelWithoutSpaceStillSuppresses is the other side of the same
// arm: handing the colon case to the label vocabulary must not turn it into a
// blanket rescue.
func TestIdentifierLabelWithoutSpaceStillSuppresses(t *testing.T) {
	v := NewValidator()

	for _, label := range []string{"session", "token", "request", "hash", "uuid", "build"} {
		line := label + ":415-267-1234"
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "app.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("an identifier label was reported as a phone: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestWordEndingInLabelIsNotALabel pins the HasSuffix defect.
//
// The label test was `word == label || strings.HasSuffix(word, label)`, so
// "madrid" matched the identifier label "id" and "Escalation contact Madrid:
// +34 91 496 0345" reported nothing. Any word ending in a label triggered it,
// in both vocabularies.
func TestWordEndingInLabelIsNotALabel(t *testing.T) {
	v := NewValidator()

	// Places and names that merely end in "id".
	for _, word := range []string{"Madrid", "Cupid", "Enid", "Sid", "Valladolid"} {
		line := "Escalation contact " + word + ": +34 91 496 0345"
		t.Run(word, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "oncall.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("a word merely ENDING in an identifier label deleted the finding: %s", line)
			}
		})
	}
}

// TestSeparatedCompoundLabelsStillMatch is the non-vacuity partner of the test
// above: replacing HasSuffix with exact matching alone would have broken the
// compound labels people really write. The replacement allows a
// separator-delimited tail, so these must keep working.
func TestSeparatedCompoundLabelsStillMatch(t *testing.T) {
	v := NewValidator()

	// Identifier side: must still suppress.
	for _, line := range []string{
		"trace_id: 4152671234",
		"x.session: 4152671234",
		"req-token: 4152671234",
	} {
		t.Run("suppress/"+line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "app.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("compound identifier label was reported: %s (got %d)", line, len(matches))
			}
		})
	}

	// Phone side: must still report.
	for _, line := range []string{
		"work-mobile: 415-267-1234",
		"emergency_phone: 415-267-1234",
	} {
		t.Run("report/"+line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "hr.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("compound phone label was dropped: %s", line)
			}
		})
	}
}

// TestNANPLongDistanceIsNotAResourcePrefix covers the leading "1-" form.
//
// A '-' before the match normally means a resource identifier
// (ami-050451375729), which is correct and must stay. But "1-415-267-1234" is
// how North American numbers are dictated and printed, and that shape was being
// swallowed by the same rule.
func TestNANPLongDistanceIsNotAResourcePrefix(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"Dial 1-415-267-1234 for the after-hours desk",
		"Call 1-800-555-0199 for support",
		"(1-415-267-1234)",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "notes.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("NANP long-distance notation was read as a resource prefix: %s", line)
			}
		})
	}
}

// TestResourcePrefixesStillSuppressed is the precision guard the rescue above
// must not break. sku-401-... is the case that proves the rescue requires a
// STANDALONE "1" rather than any digit before the dash.
func TestResourcePrefixesStillSuppressed(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"ami-415-267-1234 resource",
		"sku-401-415-267-1234 part",
		"i-057034242931 running",
		"instance i-057034242931 running",
		"vpc-415-267-1234 created",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "infra.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a resource identifier was reported as a phone: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestGoverningWordOverrulesTheNANPRescue is the FP class the rescue introduced
// and this closes: "version 1-415-267-1234" is a release string, not a phone.
// It cannot be caught by the label arm, because that arm only runs when the
// match is preceded by a space and the "1-" prefix prevents that.
func TestGoverningWordOverrulesTheNANPRescue(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"version 1-415-267-1234: shipped",
		"build 1-415-267-1234: green",
		"revision 1-415-267-1234 tagged",
	} {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "release.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a release string was reported as a phone: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestTrailingColonStaysSuppressed documents a deliberate NON-fix, so a future
// reader does not "fix" it back.
//
// "Reception 415-267-1234: ask for Dana" is a real phone that the trailing-colon
// arm drops. Allowing a trailing colon was implemented and then measured out: it
// recovered that 1 finding and admitted 4 false positives -- "ratio
// 415-267-1234: 1", "error 415-267-1234: connection refused", "key
// 415-267-1234: value", "range 100-200-3000: allowed". Gating on
// hasPhonePunctuation does not separate them (the log keys are punctuated
// identically), and all five scored LOW 5.00%, so confidence cannot triage them
// apart either.
//
// A LEADING colon is rescued because the preceding word says which kind of value
// follows. Nothing AFTER the match carries equivalent information.
func TestTrailingColonStaysSuppressed(t *testing.T) {
	v := NewValidator()

	logKeys := []string{
		"ratio 415-267-1234: 1",
		"error 415-267-1234: connection refused",
		"key 415-267-1234: value",
		"range 100-200-3000: allowed",
	}
	for _, line := range logKeys {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "app.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a log key was reported as a phone: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestLabelBeforeColon covers the extracted helper directly, including the
// boundary cases the callers reach it with.
func TestLabelBeforeColon(t *testing.T) {
	cases := []struct {
		line    string
		colonAt int
		want    string
		ok      bool
	}{
		{"Tel:415-267-1234", 3, "tel", true},
		{"Branch line Tel:415", 15, "tel", true},
		{"work-mobile: 415", 11, "work-mobile", true},
		{"  :415", 2, "", false},   // no word before the colon
		{":415", 0, "", false},     // colon at index 0
		{"Tel:415", 99, "", false}, // out of range
		{"Tel 415", 3, "", false},  // not a colon
	}

	for _, c := range cases {
		got, ok := labelBeforeColon(c.line, c.colonAt)
		if got != c.want || ok != c.ok {
			t.Errorf("labelBeforeColon(%q, %d) = (%q, %v), want (%q, %v)",
				c.line, c.colonAt, got, ok, c.want, c.ok)
		}
	}
}

// TestLabelMatchesWord pins the word-boundary rule that replaced HasSuffix.
func TestLabelMatchesWord(t *testing.T) {
	cases := []struct {
		label, want string
		expect      bool
	}{
		{"id", "id", true},
		{"trace_id", "id", true},
		{"x.session", "session", true},
		{"work-mobile", "mobile", true},
		{"madrid", "id", false}, // the defect
		{"cupid", "id", false},
		{"overcall", "call", false},
		{"homework", "work", false},
		{"", "id", false},
		{"i", "id", false},
	}

	for _, c := range cases {
		if got := labelMatchesWord(c.label, c.want); got != c.expect {
			t.Errorf("labelMatchesWord(%q, %q) = %v, want %v", c.label, c.want, got, c.expect)
		}
	}
}

// TestIsNANPCountryCodePrefix covers the helper's boundaries directly.
func TestIsNANPCountryCodePrefix(t *testing.T) {
	cases := []struct {
		line   string
		dashAt int
		want   bool
	}{
		{"1-415-267-1234", 1, true},        // start of line
		{"Dial 1-415-267-1234", 6, true},   // after a space
		{"+1-415-267-1234", 2, true},       // after a plus
		{"(1-415-267-1234)", 2, true},      // after a paren
		{"sku-401-415-267-1234", 7, false}, // the 1 is part of "401"
		{"ami-050451375729", 3, false},     // alphabetic prefix
		{"x1-415-267-1234", 2, false},      // the 1 is part of "x1"
		{"1-415", 0, false},                // index 0 is not a dash
		{"1-415", 99, false},               // out of range
		{"a-415-267-1234", 1, false},       // no 1 before the dash
	}

	for _, c := range cases {
		if got := isNANPCountryCodePrefix(c.line, c.dashAt); got != c.want {
			t.Errorf("isNANPCountryCodePrefix(%q, %d) = %v, want %v", c.line, c.dashAt, got, c.want)
		}
	}
}

// TestWordGoverningBounds feeds degenerate offsets, since the caller derives
// them from match arithmetic.
func TestWordGoverningBounds(t *testing.T) {
	if _, ok := wordGoverning("1-415-267-1234", 1); ok {
		t.Error("a token at the start of the line has no governing word")
	}
	if got, ok := wordGoverning("version 1-415-267-1234", 8); !ok || got != "version" {
		t.Errorf("wordGoverning = (%q, %v), want (\"version\", true)", got, ok)
	}
	if _, ok := wordGoverning("", 0); ok {
		t.Error("empty line must not yield a governing word")
	}
}
