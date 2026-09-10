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

// The admission gate must not judge a part by a spelling of the value it happens to expect — and a
// value SPLIT ACROSS RUNS is a spelling.
//
// #652: an embedded part whose reported value is written across two adjacent <w:t> elements was judged
// clean and SKIPPED, so the container was written with the value in cleartext, at rc=0 even with
// --fail-on-incomplete, and with no diagnostic at all. Measured on main at 68171af with an outer .docx
// carrying word/embeddings/inner.docx whose document.xml held the SSN split as
// `<w:t>...456-78</w:t></w:r><w:r><w:t>-1234</w:t>`:
//
//	embedded, split    -> both halves recoverable from the "redacted" file, rc=0, silent   LEAK
//	embedded, unsplit  -> redacted correctly, mask present
//	same split at TOP level (depth 1) -> DISCLOSED REFUSAL (#627/#630)
//
// Both controls localising the defect is what matters: the nested inflate/rewrite/repackage path works,
// and depth 1 already refuses this exact shape. Nesting was converting that refusal into a silent leak.
//
// This is the same failure family as #475's `&#48;` spelling, which the residue scan's second view
// fixed. The scan's own comment says why blindness here is worse than a missed optimisation: the caller
// treats "nothing found" as permission to skip. A run-joined third view closes it.
//
// After the fix the container is REFUSED with the chain named — the value is still not rewritten across
// runs, which is #627 and needs a source span map — so the end state is a disclosed refusal rather than
// a silent leak, which is what this repo asks of a redactor that cannot finish.

// splitSSN is the value used by the run-split fixtures.
//
// Deliberately different from embSSN and encSSN so a failure names which family broke.
const splitSSN = "456-78-1234"

func splitMatches() []detector.Match {
	return []detector.Match{{Text: splitSSN, Type: "SSN", Confidence: 100}}
}

// buildRunSplitInnerDocx builds an inner .docx whose body splits the SSN across two adjacent runs.
//
// buildPkg wraps its argument in <w:p><w:r><w:t>...</w:t></w:r></w:p> and interpolates without
// escaping, so closing and reopening the run inside the body produces two real adjacent runs:
//
//	<w:p><w:r><w:t>Inner document. SSN: 456-78</w:t></w:r><w:r><w:t>-1234</w:t></w:r></w:p>
func buildRunSplitInnerDocx(t *testing.T) []byte {
	t.Helper()
	child := buildPkg(t, "Inner document. SSN: 456-78</w:t></w:r><w:r><w:t>-1234", nil)

	// Three non-vacuity guards on the fixture itself, each of which has certified a false fix in this
	// package before.
	//
	// The value must not appear contiguously in the raw container bytes, or the gate's FIRST view finds
	// it and the run-joined view is not what is being tested.
	if bytes.Contains(child, []byte(splitSSN)) {
		t.Fatalf("fixture holds %q contiguously in raw bytes, so the run-joined view is not what this "+
			"test exercises", splitSSN)
	}
	// It must be COMPRESSED, or the gate finds the halves without any zip descent — the single most
	// common way a leak in this area gets certified as fixed.
	if bytes.Contains(child, []byte("456-78")) {
		t.Fatal("fixture is not compressed (found a half verbatim), so this test would pass without any " +
			"zip descent and prove nothing about it")
	}
	return child
}

// TestRunSplitValueInAnEmbeddedPartIsDispatched is the reported defect, asserted at the gate.
//
// The gate's output is a DECISION, so the assertion is on the decision: was the part handed to the
// embedded redactor at all. Before the fix this list was empty and the container was written as though
// the part were clean.
func TestRunSplitValueInAnEmbeddedPartIsDispatched(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/inner.docx": buildRunSplitInnerDocx(t),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("redacted child with nothing left in it")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, splitMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	if len(spy.calls) == 0 {
		t.Fatal("the embedded part was never dispatched. Its document.xml holds the reported SSN split " +
			"across two adjacent <w:t> runs, so no contiguous byte search can see it and the gate " +
			"skipped it — the container is then written as if clean, and both halves are recoverable " +
			"from the output at rc=0 with nothing said.")
	}
	if !strings.Contains(strings.Join(spy.calls, ","), "inner.docx") {
		t.Errorf("dispatched parts %v do not include the part holding the run-split value", spy.calls)
	}
}

// TestUnsplitValueInAnEmbeddedPartIsStillDispatched is the control that localises the defect.
//
// If this failed too, the bug would be somewhere in the nested path rather than in the gate's view of a
// spelling, and the fix above would be aimed at the wrong thing.
func TestUnsplitValueInAnEmbeddedPartIsStillDispatched(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/inner.docx": buildPkg(t, "Inner document. SSN: "+splitSSN, nil),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("redacted child with nothing left in it")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, splitMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(spy.calls) == 0 {
		t.Fatal("the unsplit control was not dispatched either, so the defect is not the gate's view of " +
			"a spelling and this whole test file is aimed at the wrong layer")
	}
}

// TestAnXMLPartWithNoReportedValueIsStillSkipped is the must-NOT-fire half, and it is the assertion that
// keeps the third view from making the gate useless.
//
// The gate exists to SKIP parts that hold nothing, so that a container full of images is not
// re-extracted and re-packaged part by part. A run-joined view that made every XML part look like it
// held a value would dispatch everything: the leak would be gone and so would the optimisation, and no
// other test in this package would notice.
func TestAnXMLPartWithNoReportedValueIsStillSkipped(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		// A real XML part, split across runs, holding a value that is NOT the reported one.
		"word/embeddings/inner.docx": buildPkg(t, "Inner document. Order 998-11</w:t></w:r><w:r><w:t>-2277", nil),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("should never be called")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, splitMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(spy.calls) != 0 {
		t.Errorf("a part holding no reported value was dispatched anyway (%v). The run-joined view must "+
			"not make every XML part look occupied, or the gate stops being a gate", spy.calls)
	}
}

// TestLooksLikeXMLKeepsBinaryPartsOutOfTheTokeniser pins the sniff, which is a cost control rather than
// a correctness control — but a wrong answer in either direction matters.
//
// A false NEGATIVE restores exactly the blindness #652 is about. A false positive costs one tokenisation
// that fails on its first token, which is why the function errs toward looking.
func TestLooksLikeXMLKeepsBinaryPartsOutOfTheTokeniser(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"plain xml", []byte(`<?xml version="1.0"?><a/>`), true},
		{"element only", []byte(`<w:t>x</w:t>`), true},
		{"leading whitespace", []byte("\n\t  <a/>"), true},
		{"utf-8 BOM", append([]byte{0xEF, 0xBB, 0xBF}, []byte(`<a/>`)...), true},
		{"BOM then whitespace", append([]byte{0xEF, 0xBB, 0xBF}, []byte("\n<a/>")...), true},
		{"png", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, false},
		{"zip", []byte("PK\x03\x04rest"), false},
		{"empty", nil, false},
		{"whitespace only", []byte("   \n\t"), false},
		{"text that is not markup", []byte("Employee SSN: 456-78-1234"), false},
	}
	for _, c := range cases {
		if got := looksLikeXML(c.in); got != c.want {
			t.Errorf("%s: looksLikeXML = %v, want %v", c.name, got, c.want)
		}
	}
}
