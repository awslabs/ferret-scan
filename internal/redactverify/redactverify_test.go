// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// m is a Match carrying just the fields this package reads.
func m(text, typ string) detector.Match { return detector.Match{Text: text, Type: typ} }

// mask returns a replacement of the same byte length, which is what a format-preserving strategy does.
func mask(v string) string { return strings.Repeat("*", len(v)) }

func maskFor(x detector.Match) (string, error) { return mask(x.Text), nil }

// TestSweepSparesAValueEmbeddedInALongerToken is the regression test for the case the repo's own golden
// corpus already proved: a blind substring sweep corrupts data it was never asked to touch.
//
// internal/goldencorpus reports the 11-byte INSURANCE_MEMBER_ID `BEEF1234567` on one line, and a
// separate decoy line reads `cache blob 0xDEADBEEF12345678 evicted`, which the fixture exists to keep
// clean. The value occurs inside that hex constant. Before the standalone rule, TestGoldenRedact was RED
// on both simple and format_preserving — silently, at exit 0.
//
// A length floor cannot protect this: the value is 11 bytes, far above any plausible minimum.
func TestSweepSparesAValueEmbeddedInALongerToken(t *testing.T) {
	const decoy = "cache blob 0xDEADBEEF12345678 evicted\n"
	got, swept, err := SweepRemaining(decoy, []detector.Match{m("BEEF1234567", "INSURANCE_MEMBER_ID")}, maskFor)
	if err != nil {
		t.Fatalf("SweepRemaining: %v", err)
	}
	if got != decoy {
		t.Errorf("the sweep rewrote a value embedded in a longer token.\n got: %q\nwant: %q\n"+
			"Those bytes are part of a hex constant, not the reported value. Rewriting them corrupts a "+
			"document the tool was asked to redact, not to edit.", got, decoy)
	}
	if len(swept) != 0 {
		t.Errorf("reported %d swept value(s) while changing nothing: %v", len(swept), swept)
	}
}

// TestSweepStillRemovesAStandaloneOccurrence is the other half. The standalone rule must not become "any
// value that appears embedded anywhere is untouchable" — the copy that IS the value still has to go.
func TestSweepStillRemovesAStandaloneOccurrence(t *testing.T) {
	const doc = "member id: BEEF1234567\ncache blob 0xDEADBEEF12345678 evicted\n"
	got, swept, err := SweepRemaining(doc, []detector.Match{m("BEEF1234567", "INSURANCE_MEMBER_ID")}, maskFor)
	if err != nil {
		t.Fatalf("SweepRemaining: %v", err)
	}
	if strings.Contains(got, "member id: BEEF1234567") {
		t.Errorf("the standalone occurrence survived:\n%s", got)
	}
	if !strings.Contains(got, "0xDEADBEEF12345678") {
		t.Errorf("the embedded occurrence was rewritten as collateral:\n%s", got)
	}
	if len(swept) != 1 {
		t.Errorf("swept = %v, want exactly the one value", swept)
	}
}

// TestPredicateAndEnforcerAgreeOnScope is the property that makes the floor safe to refuse on.
//
// If the predicate counts something as residue that the enforcer is forbidden to remove, the artifact
// becomes permanently unobtainable and there is no flag to override it. Measured: one real file's only
// remaining refusal was a 3-byte HIGH IP_ADDRESS of shape `#::` that the sweep declines by design.
func TestPredicateAndEnforcerAgreeOnScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
		val  string
	}{
		{"shorter than the sweep floor", "route via 1:: today\n", "1::"},
		{"embedded only", "cache 0xDEADBEEF12345678 evicted\n", "BEEF1234567"},
		{"standalone", "member id: BEEF1234567\n", "BEEF1234567"},
		{"standalone and embedded", "id BEEF1234567 and 0xDEADBEEF12345678\n", "BEEF1234567"},
		{"exactly at the floor", "code ABCD here\n", "ABCD"},
		{"one below the floor", "code ABC here\n", "ABC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := []detector.Match{m(tc.val, "TEST_TYPE")}
			predicateSaysResidue := len(ResidualTypes([]byte(tc.doc), ms)) > 0

			out, swept, err := SweepRemaining(tc.doc, ms, maskFor)
			if err != nil {
				t.Fatalf("SweepRemaining: %v", err)
			}
			enforcerActed := len(swept) > 0 || out != tc.doc

			if predicateSaysResidue != enforcerActed {
				t.Errorf("predicate says residue=%v but enforcer acted=%v for %q in %q.\n"+
					"When the predicate is the stricter of the two, the floor refuses a file the sweep "+
					"is not allowed to clean and the operator can never obtain an artifact.",
					predicateSaysResidue, enforcerActed, tc.val, tc.doc)
			}
			// And whatever the enforcer did, the predicate must be satisfied by the result.
			if r := ResidualTypes([]byte(out), ms); len(r) > 0 {
				t.Errorf("after the sweep the predicate still reports %v; the floor would refuse this "+
					"output even though the enforcer reported success", r)
			}
		})
	}
}

// TestSweepDeclinesOneValueNotTheDocument pins the per-value skip.
//
// A replacement that still contains the value cannot remove it. Aborting the whole document meant a
// single self-masking value — a run of asterisks typed as an API key, which #522's guard exists for —
// produced NO artifact for the entire file, turning a disclosed per-match no-op into total failure.
func TestSweepDeclinesOneValueNotTheDocument(t *testing.T) {
	doc := "key = ******** and member id: BEEF1234567\n"
	ms := []detector.Match{
		m("********", "API_KEY_OR_SECRET"), // mask() of this is itself
		m("BEEF1234567", "INSURANCE_MEMBER_ID"),
	}
	out, swept, err := SweepRemaining(doc, ms, maskFor)
	if err != nil {
		t.Fatalf("one self-masking value must not fail the sweep for the whole document: %v", err)
	}
	if strings.Contains(out, "BEEF1234567") {
		t.Errorf("the other value was not swept because a self-masking value was present:\n%s", out)
	}
	if len(swept) != 1 {
		t.Errorf("swept = %v, want only the removable value", swept)
	}
}

// TestSurvivesRecognisesTheWideSpellings covers the arms that exist so the enforcer can cover the
// predicate. Wide leaks are NOT common — every residual value across a 480-file corpus was a literal,
// and only 1 of 235 text-extension files carried NUL bytes at all — but a file with a UTF-16 region is
// real, and a narrow search reads a wide copy as absent.
func TestSurvivesRecognisesTheWideSpellings(t *testing.T) {
	const val = "Jeff Carpenter"
	for _, tc := range []struct {
		name string
		doc  []byte
		want bool
	}{
		{"literal", []byte("author: " + val + "\n"), true},
		{"utf16LE", append([]byte("x "), utf16LE(val)...), true},
		{"utf16BE", append([]byte("x "), utf16BE(val)...), true},
		{"absent", []byte("author: somebody else\n"), false},
		{"named entity", []byte("<a>O&apos;Connor</a>"), false}, // different value entirely
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Survives(tc.doc, val); got != tc.want {
				t.Errorf("Survives = %v, want %v", got, tc.want)
			}
		})
	}
	// A NAMED entity spelling of a value containing an apostrophe must be recognised.
	if !Survives([]byte("<a>O&apos;Connor</a>"), "O'Connor") {
		t.Error("the named-entity spelling was not recognised; an .xlsx storing O&apos;Connor holds the " +
			"same value a reader sees, and a raw search cannot see it")
	}
	// Numeric character references are deliberately NOT covered; pin it so the gap is explicit rather
	// than discovered.
	if Survives([]byte("<v>452-11-93&#56;4</v>"), "452-11-9384") {
		t.Log("numeric character references are now recognised; update the package doc, which states " +
			"they are not, and drop this case")
	}
}

// TestEmptyValueIsNeverResidue guards the trap that would turn a safety check into a denial of service
// against the tool's own output: bytes.Contains with an empty needle is always true, so counting it
// would make every redaction refuse.
func TestEmptyValueIsNeverResidue(t *testing.T) {
	if Survives([]byte("anything at all"), "") {
		t.Error("an empty value was reported as surviving")
	}
	if r := ResidualTypes([]byte("anything at all"), []detector.Match{m("", "SSN")}); len(r) > 0 {
		t.Errorf("an empty match text produced residue %v", r)
	}
	if _, swept, _ := SweepRemaining("anything at all", []detector.Match{m("", "SSN")}, maskFor); len(swept) > 0 {
		t.Errorf("an empty match text was swept: %v", swept)
	}
}

// TestResidualTypesNamesTypesNotValues: a refusal message must say WHAT leaked without reprinting the
// secret, the same rule that keeps a matched value out of every log line in this tree.
func TestResidualTypesNamesTypesNotValues(t *testing.T) {
	doc := []byte("ssn 452-11-9384 and card 4111111111111111\n")
	got := ResidualTypes(doc, []detector.Match{
		m("452-11-9384", "SSN"),
		m("4111111111111111", "CREDIT_CARD"),
	})
	if len(got) != 2 {
		t.Fatalf("got %v, want both types", got)
	}
	for _, s := range got {
		if strings.ContainsAny(s, "0123456789") {
			t.Errorf("a returned type %q contains digits; it must name the type, never the value", s)
		}
	}
	// Sorted, so a refusal message is deterministic.
	if got[0] != "CREDIT_CARD" || got[1] != "SSN" {
		t.Errorf("got %v, want a sorted list", got)
	}
}

// TestResidualTypesDeduplicatesByValue is the perf property, asserted by behaviour rather than by a
// timing threshold that would flake. One real file has 6,924 matches over 1,285 distinct values;
// probing per match measured 406ms and 48.8MB against 10.8ms and 1.5MB deduplicated.
func TestResidualTypesDeduplicatesByValue(t *testing.T) {
	doc := []byte("member id: BEEF1234567\n")
	ms := make([]detector.Match, 0, 500)
	for i := 0; i < 500; i++ {
		ms = append(ms, m("BEEF1234567", "INSURANCE_MEMBER_ID"))
	}
	got := ResidualTypes(doc, ms)
	if len(got) != 1 {
		t.Errorf("500 copies of one match produced %v; the result must be deduplicated", got)
	}
}

// TestOccurrenceKindsCountsOverlapping: a repeated value must not be undercounted, or a partially-swept
// document could report clean.
func TestOccurrenceKindsCountsOverlapping(t *testing.T) {
	for _, tc := range []struct {
		hay, needle          string
		wantClean, wantEmbed int
	}{
		{"aa aa aa", "aa", 3, 0},
		{"xaax aa", "aa", 1, 1},
		{"aaaa", "aa", 0, 3}, // every position abuts a word byte
		{"", "aa", 0, 0},
		{"aa", "", 0, 0},
		{"id: v1 v1", "v1", 2, 0},
	} {
		c, e := occurrenceKinds([]byte(tc.hay), []byte(tc.needle))
		if c != tc.wantClean || e != tc.wantEmbed {
			t.Errorf("occurrenceKinds(%q, %q) = (%d, %d), want (%d, %d)",
				tc.hay, tc.needle, c, e, tc.wantClean, tc.wantEmbed)
		}
	}
}
