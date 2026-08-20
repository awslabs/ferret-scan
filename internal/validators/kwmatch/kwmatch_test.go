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

// A keyword space may match ZERO separators, so a concatenated or camelCase label counts as
// context. Text is lowercased before matching, so "memberId" and "memberid" are the same
// string here — which is why one rule covers both.
//
// Before this, "member id" could never match either, and camelCase is the default key style
// of JSON, REST payloads and ORM exports. Measured on a file of camelCase/snake_case pairs of
// the same shape, all four camelCase halves scored 0 while their twins scored 75, 80, 90 and
// 100; in a two-key object one member ID sat in cleartext beside its redacted twin. See #372.
func TestConcatenatedKeywordMatches(t *testing.T) {
	for _, c := range []struct{ text, keyword string }{
		{`"memberid": "xq4839271"`, "member id"},
		{`"memberid":"xq4839271"`, "member id"},
		{"memberid: w9998887779", "member id"},
		{"medicalrecordnumber 4839272", "medical record number"},
		{"driverslicense d1234562", "drivers license"},
		{"routingnumber 026009593", "routing number"},
		{"taxid 123456789", "tax id"},
		// The separator forms must all keep working.
		{"member id: x", "member id"},
		{"member_id: x", "member id"},
		{"member-id: x", "member id"},
		{"member\tid: x", "member id"},
		{"member  id: x", "member id"},
	} {
		if !ContainsLower(c.text, c.keyword) {
			t.Errorf("ContainsLower(%q, %q) = false, want true", c.text, c.keyword)
		}
	}
}

// The outer word-boundary rule is what makes zero separators safe, and these are the cases
// that would break first if it were lost. A keyword must not match inside a longer word at
// either end.
func TestConcatenatedKeywordStillRespectsWordBoundaries(t *testing.T) {
	for _, c := range []struct {
		text, keyword, why string
	}{
		{"remembering things", "member id", "the anchor is inside a longer word on the left"},
		{"teammemberid: x", "member id", "the anchor is preceded by a word byte"},
		{"memberidentification: x", "member id", "the match is followed by a word byte"},
		{"memberids: x", "member id", "a trailing 's' is still a word byte"},
		// The '.' and '/' exclusions are a RECORDED MEASURED decision (isSepByte) and this
		// change must not touch them: they cross sentence and URL boundaries where the two
		// words are unrelated.
		{"see member.id in the schema docs", "member id", "'.' is not a separator, by measurement"},
		{"https://example.com/member/id/lookup", "member id", "'/' is not a separator, by measurement"},
	} {
		if ContainsLower(c.text, c.keyword) {
			t.Errorf("ContainsLower(%q, %q) = true, want false: %s", c.text, c.keyword, c.why)
		}
	}
}

// ContainsPhrase keeps the old behaviour for a keyword that is PROSE, and it exists for a
// measured reason.
//
// Checked against the system dictionary (234,456 lowercased entries), exactly 2 of the 457
// multi-word
// keywords in this tree concatenate into an English word: "one time" -> "onetime" and
// "call us" -> "callus". The first is a positive OTP keyword where matching "oneTime" is the
// point. The second is a phone-context SUPPRESSOR in bankaccount, so "callus" would silence a
// real account number on any line that mentions one — measured: with plain Contains, a
// "callus debridement, bank account 4432198765" line LOSES its US_BANK_ACCOUNT finding.
func TestContainsPhraseStillRequiresASeparator(t *testing.T) {
	for _, c := range []struct {
		text, keyword string
		want          bool
	}{
		{"callus debridement", "call us", false},
		{"please call us today", "call us", true},
		{"please call-us today", "call us", true},
		{"please call_us today", "call us", true},
		{"recall using the form", "call us", false}, // a plain substring test would match here
		// A single-word keyword has no space, so the phrase form is just Contains.
		{"phone: 415-555-0142", "phone", true},
		{"telephones", "phone", false},
	} {
		if got := ContainsPhraseLower(c.text, c.keyword); got != c.want {
			t.Errorf("ContainsPhraseLower(%q, %q) = %v, want %v", c.text, c.keyword, got, c.want)
		}
	}

	// And the two forms must genuinely differ on the concatenation, or the phrase API is
	// decorative.
	if !ContainsLower("callus debridement", "call us") {
		t.Error("ContainsLower no longer matches the concatenated form, so ContainsPhrase " +
			"protects nothing and this whole distinction is dead weight")
	}
}
