// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The admission gate must not judge a part by a spelling of the value it happens to expect.
//
// #475: an embedded part whose reported value is written with an XML character reference was
// judged clean and SKIPPED, leaving the value recoverable at exit 0 with no warning. Measured on
// merged main at 6c05562, with an outer .docx carrying word/embeddings/inner.docx whose
// document.xml held `Patient SSN 449-87-410&#48;` — the final 0 as a decimal reference:
//
//	embedded part, escaped   -> parser reads 449-87-4100 out of the "redacted" file   LEAK
//	embedded part, plain     -> clean
//	same escaped value at TOP level, no embedding -> clean
//
// Both controls redacting correctly is what localises the defect: the redactor was always able to
// handle the part, because office.rewritePartText matches character data on its DECODED form and
// re-emits it escaped. The gate was the whole bug. After the fix the value is fully REDACTED, not
// merely refused — the inner text node becomes `Patient SSN ***-**-4100` and the reference is gone.

// encSSN is the value used by the encoded-spelling fixtures.
//
// Deliberately different from embSSN so a failure names which family of tests broke.
const encSSN = "449-87-4100"

// encMatches is the reported finding these tests hand the redactor.
func encMatches() []detector.Match {
	return []detector.Match{{Text: encSSN, Type: "SSN", Confidence: 100}}
}

// buildEncodedInnerDocx builds an inner .docx whose body spells the SSN as given.
//
// buildPkg interpolates the body into the XML without escaping, so a reference passed here lands
// in document.xml as a real reference rather than as literal text.
func buildEncodedInnerDocx(t *testing.T, spelling string) []byte {
	t.Helper()
	child := buildPkg(t, "Inner document. Patient SSN "+spelling, nil)

	// Two non-vacuity guards on the fixture itself, both of which have mattered in this package.
	//
	// The value must not be present in the raw container bytes, or the gate would find it without
	// any decoding and the test would pass while proving nothing. It must also be COMPRESSED, or
	// the gate would find it without any zip descent — the single most common way a leak in this
	// area gets certified as fixed.
	if bytes.Contains(child, []byte(encSSN)) {
		t.Fatalf("fixture holds %q in raw bytes, so the decode path is not what this test exercises",
			encSSN)
	}
	if bytes.Contains(child, []byte(spelling)) {
		t.Fatalf("fixture is not compressed (found %q verbatim), so this test would pass without "+
			"any zip descent and prove nothing about it", spelling)
	}
	return child
}

// TestEncodedValueInAnEmbeddedPartIsDispatched is the reported defect, asserted at the gate.
//
// The gate's output is a DECISION, so the assertion is on the decision: was the part handed to the
// embedded redactor at all. Before the fix this list was empty and the container was written as
// though the part were clean.
func TestEncodedValueInAnEmbeddedPartIsDispatched(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/inner.docx": buildEncodedInnerDocx(t, "449-87-410&#48;"),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("redacted child with nothing left in it")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, encMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	if len(spy.calls) == 0 {
		t.Fatal("the embedded part was never dispatched. Its document.xml holds the reported SSN " +
			"with the final digit written as `&#48;`, so a raw byte search cannot see it and the " +
			"gate skipped it — the container is then written as if clean and the value is " +
			"recoverable by any XML parser at exit 0.")
	}
	if !strings.Contains(strings.Join(spy.calls, ","), "inner.docx") {
		t.Errorf("dispatched parts %v do not include the part holding the encoded value", spy.calls)
	}
}

// TestEveryReferenceSpellingIsDispatched is why the fix decodes instead of enumerating.
//
// Each of these is the same SSN. A value is not respelled once and uniformly: a writer may respell
// only the last digit, only the separators, or every character, in decimal or hex, with arbitrary
// leading zeros. The spellings are combinatorial, so a list of escaped forms cannot cover them —
// embedded.XMLEscapeVariants offers five substitutions and produces none of these.
func TestEveryReferenceSpellingIsDispatched(t *testing.T) {
	for _, spelling := range []string{
		"449-87-410&#48;",            // only the final digit — the case measured in #475
		"&#52;49-87-4100",            // only the first
		"449&#45;87&#45;4100",        // both separators
		"&#x34;&#x34;&#x39;-87-4100", // hex
		"&#0000000052;49-87-4100",    // decimal with a long run of leading zeros
	} {
		t.Run(spelling, func(t *testing.T) {
			dir := t.TempDir()
			in := writeOuter(t, dir, "outer.docx", map[string][]byte{
				"word/embeddings/inner.docx": buildEncodedInnerDocx(t, spelling),
			})

			or := NewOfficeRedactor(nil, nil)
			spy := &fakeDispatcher{out: []byte("clean child")}
			or.SetEmbeddedRedactor(spy)

			out := filepath.Join(dir, "out.docx")
			if _, err := or.RedactDocument(in, out, encMatches(), redactors.RedactionFormatPreserving); err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}
			if len(spy.calls) == 0 {
				t.Errorf("a part spelling the SSN as %q was judged clean and skipped", spelling)
			}
		})
	}
}

// TestAPartHoldingNoSpellingOfTheValueIsStillSkipped is the direction that must not break, and it
// is not cosmetic.
//
// Dispatching costs the part its fidelity: the image redactor decodes, re-encodes and strips all
// metadata, so handing over a part that holds none of the reported values silently degrades content
// that was never implicated. Measured before the gate existed: an unrelated 706-byte photo came back
// re-encoded to 664 bytes with a different hash and its caption removed.
//
// The part here is full of ampersands and legal references, so the decode path definitely RUNS —
// it just must not find anything. A decoder that invented values would fire here.
func TestAPartHoldingNoSpellingOfTheValueIsStillSkipped(t *testing.T) {
	dir := t.TempDir()
	innocuous := buildPkg(t, "Quarterly notes &amp; figures. Ref &#65;&#66;&#67; and &sect; 4. "+
		"Contact 555-01-0000 &lt;desk&gt;.", nil)
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/inner.docx": innocuous,
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("should never be called")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, encMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("a part holding no spelling of the reported value was dispatched (%v). Dispatch is "+
			"lossy, so widening the gate must not reach parts that were never implicated.", spy.calls)
	}
}

// TestPartHoldsValueSeesAnEncodedValue pins the predicate directly, both directions.
//
// The end-to-end tests above go through RedactDocument, which is the behaviour that matters; this
// one names the function so a failure points at the right place.
func TestPartHoldsValueSeesAnEncodedValue(t *testing.T) {
	values := [][]byte{[]byte(encSSN)}

	encoded := []byte(`<w:t>Patient SSN 449-87-410&#48;</w:t>`)
	if bytes.Contains(encoded, []byte(encSSN)) {
		t.Fatal("fixture contains the raw value, so it does not test decoding")
	}
	if !partHoldsValue(encoded, values, 0) {
		t.Error("partHoldsValue missed a value spelled with a character reference; the caller " +
			"treats false as permission to skip the part, so this is a leak and not a miss")
	}

	// A reference that does not decode to the value must not match, and neither must a
	// near-miss. Otherwise the gate degrades clean parts.
	for _, clean := range []string{
		`<w:t>Patient SSN 449-87-410</w:t>`,      // truncated, no reference
		`<w:t>Ref &#65;&#66; and &sect; 4</w:t>`, // references, unrelated
		`<w:t>449-87-410&#4;8</w:t>`,             // malformed: reference does not close before 8
		`<w:t>449-87-410&#48</w:t>`,              // unterminated reference
	} {
		if partHoldsValue([]byte(clean), values, 0) {
			t.Errorf("partHoldsValue matched %q, which does not hold the value in any spelling", clean)
		}
	}
}

// TestValuesPresentInStillReturnsEveryValue guards the loop restructure.
//
// The decode view was added by turning the single byte search into a loop over views. The other
// caller of this traversal wants "exactly what survived", not "is there anything", so a
// restructure that accidentally returned after the first hit would silently shrink the refusal
// message that names surviving parts.
func TestValuesPresentInStillReturnsEveryValue(t *testing.T) {
	content := []byte(`<w:t>a 449-87-4100 b 452-11-9384 c</w:t>`)
	got := valuesPresentIn(content, [][]byte{[]byte(encSSN), []byte(embSSN)}, 0, false)
	if len(got) != 2 {
		t.Errorf("valuesPresentIn returned %v, want both values. stopAtFirst=false must not "+
			"short-circuit, or the unredacted-part report loses entries.", got)
	}
}
