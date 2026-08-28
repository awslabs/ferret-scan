// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #517: a container carrying an embedded part that is NOT a readable archive was written as
// "redacted" with that part copied through verbatim, at exit 0.
//
// The chain, measured end to end on a real .docx:
//
//	the SCAN cannot parse the part          -> the value inside is never REPORTED
//	the value is absent from `values`       -> the residue scan is not looking for it
//	the residue scan finds nothing          -> the gate reads that as "holds nothing"
//	the part is skipped                     -> copied into the output verbatim
//	the container is written, rc 0          -> cleartext in a file named "redacted"
//
// The write side was behaving correctly given its inputs; the premise it rests on is that a
// zip-backed part's members can be INFLATED, which AdmittedExts' own doc comment states. An
// unopenable archive breaks that premise silently, so such a part now takes the opaque path.

// unparseableInner has the zip magic and is not a readable archive — a truncated or corrupt
// attachment.
//
// It must NOT contain the reported value in its raw bytes, and that is the whole point of the
// fixture. With the value in the clear, partHoldsValue finds it by a plain byte search and the part
// is dispatched whether the gate consults the content or only the name — so the test passes on the
// unfixed code and proves nothing. Reverting the gate to the name-only ResidueInspectable survived
// exactly that way before this was corrected.
//
// Absent-from-the-bytes is also the REAL case. The scan could not parse the part either, so nothing
// inside it was ever REPORTED; the reported values all come from elsewhere in the container, and the
// residue scan is therefore not looking for anything this part holds. "Nothing found" then means
// "we could not look", and that is what the gate has to stop treating as "holds nothing".
func unparseableInner() []byte {
	return append(append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 24)...),
		[]byte("compressed-looking bytes no reader can open")...)
}

// assertFixtureHidesTheValue is the non-vacuity guard the fixture above depends on.
func assertFixtureHidesTheValue(t *testing.T, content []byte) {
	t.Helper()
	if bytes.Contains(content, []byte(embSSN)) {
		t.Fatalf("the fixture holds %q in its raw bytes, so partHoldsValue finds it without any "+
			"archive descent and this test would pass on the unfixed gate", embSSN)
	}
}

// TestAnUnparseableEmbeddedPartIsDispatched is the regression test for #517, asserted at the GATE.
//
// The gate's output is a DECISION — was the part offered to a redactor at all — so that is what is
// asserted, the same way TestEncodedValueInAnEmbeddedPartIsDispatched does for #475. Before the fix
// this list was empty: the residue scan could not inflate the unopenable archive, found nothing, and
// the gate read that as "holds none of the reported values".
//
// Dispatching rather than refusing outright is deliberate, and an earlier version of this fix got it
// wrong. The opaque policy this follows says such a part is ALWAYS DISPATCHED and refused only if no
// redactor can rewrite it — refusing at the gate threw away a capability that exists, and broke
// TestEveryAdmittedChildIsDispatched, whose oleObject1.docx fixture holds its value in the clear and
// can therefore be redacted despite not being an archive.
func TestAnUnparseableEmbeddedPartIsDispatched(t *testing.T) {
	dir := t.TempDir()
	assertFixtureHidesTheValue(t, unparseableInner())
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/attach.docx": unparseableInner(),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("clean child")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	if len(spy.calls) == 0 {
		t.Fatal("the unopenable embedded part was never dispatched. The residue scan cannot inflate " +
			"it, so 'nothing found' means 'we could not look' — and the part is copied into the " +
			"output verbatim while the container is written as clean (#517).")
	}
	if !strings.Contains(strings.Join(spy.calls, ","), "attach.docx") {
		t.Errorf("dispatched parts %v do not include the unopenable one", spy.calls)
	}
	// A dispatcher that CAN rewrite it means the container is legitimately written.
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("no output written even though the dispatcher succeeded: %v", statErr)
	}
}

// TestAnUnparseableEmbeddedPartRefusesWhenItCannotBeRewritten is the other half.
//
// Dispatching is only useful if a failure then stops the container. This is what the REAL office
// redactor does with an unopenable archive, measured end to end: the parent wrote a file containing
// the cleartext, and this branch writes nothing and says why.
func TestAnUnparseableEmbeddedPartRefusesWhenItCannotBeRewritten(t *testing.T) {
	dir := t.TempDir()
	assertFixtureHidesTheValue(t, unparseableInner())
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/attach.docx": unparseableInner(),
	})

	or := NewOfficeRedactor(nil, nil)
	// What the real dispatcher does with bytes that are not an archive.
	or.SetEmbeddedRedactor(&fakeDispatcher{err: errors.New("not a valid zip archive")})

	out := filepath.Join(dir, "out.docx")
	_, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("the container was written even though the part could not be rewritten")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an output file was written alongside the refusal; the artefact a user forwards must " +
			"not exist when the tool could not establish that it is clean")
	}
	if !strings.Contains(err.Error(), "attach.docx") {
		t.Errorf("the refusal does not name the part: %v", err)
	}
	// The summary must not claim the part CONTAINS a reported value: for the #517 case nothing was
	// ever reported from it, precisely because it could not be read.
	if strings.Contains(err.Error(), "still contain reported values") {
		t.Errorf("the refusal claims the part contains a reported value, which was never "+
			"established: %v", err)
	}
	if !strings.Contains(err.Error(), "could not be shown free of reported values") {
		t.Errorf("the refusal does not use the wording that covers both causes: %v", err)
	}
}

// TestAReadableEmbeddedPartHoldingNothingStillWrites is the control that bounds the blast radius.
//
// A container with a legitimate embedded document that holds none of the reported values must still
// be written. Without this the fix would refuse every document carrying an attachment, and the
// change would be a capability regression rather than a leak fix.
//
// This control is REQUIRED rather than nice to have: measured across 372 real Office files from this
// host, NOT ONE carries a zip-backed embedded part, so the real-file corpus cannot demonstrate this
// direction at all.
func TestAReadableEmbeddedPartHoldingNothingStillWrites(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		// A real, readable inner .docx whose body holds no reported value.
		"word/embeddings/inner.docx": buildPkg(t, "Inner document with nothing sensitive.", nil),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("clean child")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("a readable embedded part holding nothing refused the container: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("no output was written: %v", statErr)
	}
	// And it must still be SKIPPED rather than dispatched — the gate's optimisation is intact, so
	// a lossy redactor is not run over a part that was never implicated.
	if len(spy.calls) != 0 {
		t.Errorf("a readable part holding nothing was dispatched anyway (%v); every redactor here is "+
			"lossy, so dispatching an unimplicated part degrades content for no reason", spy.calls)
	}
}

// TestAReadableEmbeddedPartHoldingTheValueIsStillRedacted: the ordinary path must be untouched.
func TestAReadableEmbeddedPartHoldingTheValueIsStillRedacted(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/inner.docx": buildInnerDocx(t, embSSN),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("child with the value gone")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(spy.calls) == 0 {
		t.Fatal("a readable part holding the reported value was not dispatched")
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("no output was written: %v", statErr)
	}
}

// TestANonZipBackedPartIsUnaffectedByTheArchiveTest.
//
// Images, audio and legacy OLE store their text uncompressed, so the flat byte scan is sound for
// them whatever their bytes look like. A .jpg that is not a valid JPEG must NOT refuse its container
// on that basis — only zip-backed types depend on an archive opening.
func TestANonZipBackedPartIsUnaffectedByTheArchiveTest(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		// Deliberately not a valid image, and holding none of the reported values.
		"word/media/image1.jpg": []byte("this is not a JPEG at all"),
	})

	or := NewOfficeRedactor(nil, nil)
	spy := &fakeDispatcher{out: []byte("clean child")}
	or.SetEmbeddedRedactor(spy)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("an undecodable IMAGE refused the container, which the archive test must not do: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("no output was written: %v", statErr)
	}
}
