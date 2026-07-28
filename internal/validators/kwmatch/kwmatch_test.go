package kwmatch

import (
	"strings"
	"testing"
)

func TestContainsWholeWord(t *testing.T) {
	cases := []struct {
		name string
		text string
		kw   string
		want bool
	}{
		{"exact", "ssn", "ssn", true},
		{"space delimited", "the ssn field", "ssn", true},
		{"punctuation delimited", "ssn: 123-45-6789", "ssn", true},
		{"dot delimited", "example.ssn", "ssn", true},
		{"leading substring rejected", "assn", "ssn", false},
		{"trailing substring rejected", "ssnx", "ssn", false},
		{"interior substring rejected", "Christopher", "hr", false},
		{"interior substring rejected 2", "Einstein", "ein", false},
		{"interior substring rejected 3", "parking", "park", false},
		{"interior substring rejected 4", "learn", "arn", false},
		{"interior substring rejected 5", "barcode", "code", false},
		{"phrase match", "date of birth: 1985", "date of birth", true},
		{"phrase substring rejected", "update of birthday", "date of birth", false},
		{"keyword with non-word edges", "form w-2 attached", "w-2", true},
		{"case insensitive text", "Customer SSN Here", "ssn", true},
		{"case insensitive keyword", "customer ssn here", "SSN", true},
		{"empty keyword never matches", "anything at all", "", false},
		{"empty text", "", "ssn", false},
		{"keyword longer than text", "ss", "ssn", false},
		{"second occurrence matches", "assn and ssn", "ssn", true},
		{"hyphen is a boundary", "test-ssn", "ssn", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Contains(tc.text, tc.kw); got != tc.want {
				t.Errorf("Contains(%q, %q) = %v, want %v", tc.text, tc.kw, got, tc.want)
			}
		})
	}
}

// TestUnderscoreIsABoundary pins the single most consequential property of the
// matcher: '_' is a boundary, not a word byte, so a keyword is found inside a
// snake_case or SCREAMING_SNAKE identifier exactly as it is between spaces.
//
// The per-validator copies this package replaced disagreed on precisely this
// byte, and the ones treating '_' as a word byte were wrong in both directions:
// positive keywords in "customer_ssn" never boosted real findings, and fixture
// markers in "TEST_CARD_NUMBER" / "account_number_test" never suppressed false
// ones — in code and config, where those identifiers are how labels are spelled.
func TestUnderscoreIsABoundary(t *testing.T) {
	cases := []struct{ text, kw string }{
		{"test_ssn = 123-45-6789", "test"},
		{"ssn_value: 123-45-6789", "ssn"},
		{"SAMPLE_SSN=123-45-6789", "sample"},
		{"my_dob_field", "dob"},
		{"customer_ssn", "ssn"},
		{"FAKE_CARD_NUMBER", "fake"},
		{"account_number_test", "test"},
		{"_ssn", "ssn"},
		{"ssn_", "ssn"},
	}
	for _, tc := range cases {
		t.Run(tc.text+"/"+tc.kw, func(t *testing.T) {
			if !Contains(tc.text, tc.kw) {
				t.Errorf("Contains(%q, %q) = false, want true ('_' must be a boundary)", tc.text, tc.kw)
			}
		})
	}

	// The boundary rule must not degrade into plain substring matching: an
	// alphanumeric neighbor still blocks the match even next to underscores.
	for _, tc := range []struct{ text, kw string }{
		{"latest_value", "test"},
		{"my_attestation_field", "test"},
		{"_assn_", "ssn"},
	} {
		if Contains(tc.text, tc.kw) {
			t.Errorf("Contains(%q, %q) = true, want false (alphanumeric neighbor must block)", tc.text, tc.kw)
		}
	}
}

// TestUppercaseInputIsNotSilentlyMatched documents that the dropped 'A'-'Z'
// word-byte arm is unreachable for lowercased input: ContainsLower callers must
// lowercase, and Contains does it for them.
func TestUppercaseInputIsNotSilentlyMatched(t *testing.T) {
	// ContainsLower with un-lowercased text simply does not match; it must not
	// panic or match partially.
	if ContainsLower("Customer SSN", "ssn") {
		t.Error("ContainsLower must not match uppercase text (caller contract is lowercased input)")
	}
	// Contains lowercases internally, so the same input matches.
	if !Contains("Customer SSN", "ssn") {
		t.Error("Contains must lowercase its arguments")
	}
}

// TestBoundaryAdjacentToUppercaseNeighbor guards the removed uppercase arm: a
// keyword next to an uppercase letter in *lowercased* text cannot occur, but if
// a caller passes mixed case the neighbor must still be treated as a word byte
// after lowercasing by Contains.
func TestBoundaryAdjacentToUppercaseNeighbor(t *testing.T) {
	if Contains("XSSN", "ssn") {
		t.Error(`Contains("XSSN", "ssn") must be false: 'x' is a word byte after lowercasing`)
	}
	if Contains("SSNX", "ssn") {
		t.Error(`Contains("SSNX", "ssn") must be false: 'x' is a word byte after lowercasing`)
	}
}

func TestContainsFuncAcceptFilter(t *testing.T) {
	const text = "ssn alpha ssn"

	if !ContainsFunc(text, "ssn", nil) {
		t.Error("nil accept must accept any occurrence")
	}

	// Accept only the occurrence at or past offset 5 — i.e. skip the first.
	if !ContainsFunc(text, "ssn", func(start, end int) bool { return start >= 5 }) {
		t.Error("accept must keep scanning past a rejected occurrence")
	}

	// Reject everything: scanning must terminate and report false.
	if ContainsFunc(text, "ssn", func(start, end int) bool { return false }) {
		t.Error("accept returning false for every occurrence must yield false")
	}

	// The reported range must delimit the keyword exactly.
	var gotStart, gotEnd int
	ContainsFunc("xx ssn yy", "ssn", func(start, end int) bool {
		gotStart, gotEnd = start, end
		return true
	})
	if gotStart != 3 || gotEnd != 6 {
		t.Errorf("accept got range [%d,%d), want [3,6)", gotStart, gotEnd)
	}
}

// TestContainsFuncSkipsNonWholeWordBeforeAccept verifies accept is only
// consulted for whole-word occurrences, so a caller's range filter never has to
// re-check boundaries.
func TestContainsFuncSkipsNonWholeWordBeforeAccept(t *testing.T) {
	var calls int
	// "assn" contains "ssn" as a substring but not as a whole word.
	ContainsFunc("assn", "ssn", func(start, end int) bool {
		calls++
		return true
	})
	if calls != 0 {
		t.Errorf("accept called %d times for a non-whole-word occurrence, want 0", calls)
	}
}

func TestContainsAny(t *testing.T) {
	kws := []string{"test", "example", "sample"}

	if !ContainsAny("see the example below", kws) {
		t.Error("ContainsAny must match a keyword present as a whole word")
	}
	if ContainsAny("company-templates bucket", kws) {
		t.Error(`ContainsAny must not match "template" inside "templates" for keyword "test"/"sample"`)
	}
	if ContainsAny("attestation of latest", kws) {
		t.Error(`ContainsAny must not match "test" inside "attestation"/"latest"`)
	}
	if ContainsAny("nothing here", nil) {
		t.Error("ContainsAny over an empty list must be false")
	}
	// '_' is a boundary, so a keyword inside a snake_case identifier matches.
	if !ContainsAny("run_test_case", kws) {
		t.Error(`ContainsAny must match "test" inside "run_test_case" ('_' is a boundary)`)
	}
}

// TestNoOverlappingMatchMissed guards the from = i + 1 advance: a keyword whose
// occurrences overlap must still be found when a later one is whole-word.
func TestNoOverlappingMatchMissed(t *testing.T) {
	// "aaa" inside "aaaa" is never whole-word; inside "aaaa aaa" the second is.
	if !Contains("aaaa aaa", "aaa") {
		t.Error("overlapping-prefix scan must still find the later whole-word occurrence")
	}
	if Contains("aaaa", "aaa") {
		t.Error(`"aaa" must not match inside "aaaa"`)
	}
}

// TestLongTextTerminates is a cheap guard that the scan is linear in text
// length and always terminates (the loop advance must make progress).
func TestLongTextTerminates(t *testing.T) {
	text := strings.Repeat("ssnx ", 20000)
	if Contains(text, "ssn") {
		t.Error(`"ssn" must not match inside repeated "ssnx"`)
	}
	if !Contains(text+" ssn", "ssn") {
		t.Error("whole-word occurrence at the end of a long text must be found")
	}
}

func BenchmarkContainsLowerMiss(b *testing.B) {
	text := strings.Repeat("some ordinary log line with no keyword at all ", 20)
	for i := 0; i < b.N; i++ {
		ContainsLower(text, "ssn")
	}
}

func BenchmarkContainsLowerHit(b *testing.B) {
	text := strings.Repeat("some ordinary log line with no keyword at all ", 20) + "ssn"
	for i := 0; i < b.N; i++ {
		ContainsLower(text, "ssn")
	}
}
