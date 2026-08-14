// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

const embSSN = "452-11-9384"

// fakeDispatcher stands in for the RedactionManager so these tests can drive the
// container's decision-making directly, including the cases a real redactor will not
// produce on demand: claiming success while leaving the value behind, and failing on
// a part whose content is compressed.
type fakeDispatcher struct {
	// out, when non-nil, is returned as the redacted bytes.
	out []byte
	// err, when non-nil, is returned instead of a result.
	err error
	// calls records the parts it was asked about.
	calls []string
}

func (f *fakeDispatcher) RedactEmbedded(req redactors.EmbeddedRedactionRequest) (*redactors.EmbeddedRedactionResult, error) {
	f.calls = append(f.calls, req.PartName)
	if f.err != nil {
		return nil, f.err
	}
	return &redactors.EmbeddedRedactionResult{
		Content:  f.out,
		PartName: req.PartName,
		RedactionMap: []redactors.RedactionMapping{
			{RedactedText: "[REDACTED]", DataType: "SSN"},
		},
	}, nil
}

// TestChildRedactorClaimingSuccessIsVerifiedNotTrusted.
//
// A redactor returning Success with a non-empty RedactionMap is exactly the evidence
// that has been wrong before in this codebase — a RedactionCount of 1 has been
// reported on an output byte-identical to its input. So the container checks the
// bytes it is about to write rather than the child's self-report.
func TestChildRedactorClaimingSuccessIsVerifiedNotTrusted(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/media/image1.jpg": []byte("EXIF holding " + embSSN),
	})

	or := NewOfficeRedactor(nil, nil)
	// The lie: success, a redaction map, and content that still holds the value.
	or.SetEmbeddedRedactor(&fakeDispatcher{out: []byte("EXIF still holding " + embSSN)})

	out := filepath.Join(dir, "out.docx")
	_, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("RedactDocument accepted a child redactor's success claim even though the " +
			"returned bytes still contain the reported value")
	}
	if !strings.Contains(err.Error(), "still present") {
		t.Errorf("error %q should say the value is still present after redaction", err.Error())
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an output file was written despite the value surviving; a file that exists " +
			"and is unredacted is worse than no file, because the caller can ship it")
	}
}

// TestFailedZipChildHoldingTheValueFailsClosed.
//
// The residue scan MUST descend into a nested archive and decompress it. Searching a
// .docx's raw bytes finds nothing, because the text is deflated — which is
// indistinguishable from a clean part and is the single most common way a leak in
// this area gets certified as fixed.
func TestFailedZipChildHoldingTheValueFailsClosed(t *testing.T) {
	dir := t.TempDir()

	// A child package whose body holds the value, DEFLATED so a raw byte search
	// cannot see it. Assert that up front, so the test cannot pass for the wrong
	// reason if the fixture stops compressing.
	child := buildInnerDocx(t, embSSN)
	if bytes.Contains(child, []byte(embSSN)) {
		t.Fatal("fixture child is not compressed, so this test would pass without any " +
			"zip descent and prove nothing about it")
	}

	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/oleObject1.docx": child,
	})

	or := NewOfficeRedactor(nil, nil)
	or.SetEmbeddedRedactor(&fakeDispatcher{err: errors.New("simulated child failure")})

	out := filepath.Join(dir, "out.docx")
	_, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("RedactDocument wrote the container even though a child it could not " +
			"redact holds the reported value in a compressed member")
	}
	if !strings.Contains(err.Error(), "oleObject1.docx") {
		t.Errorf("error %q does not name the offending part", err.Error())
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("an output file was written despite the unredacted child")
	}
}

// TestNoDispatcherStillDisclosesRatherThanSkipping.
//
// nil is a supported state — the redactor is usable standalone — but it must not
// quietly mean "this document has no embedded content".
func TestNoDispatcherStillDisclosesRatherThanSkipping(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/media/image1.jpg": []byte("EXIF holding " + embSSN),
	})

	or := NewOfficeRedactor(nil, nil) // no SetEmbeddedRedactor call
	out := filepath.Join(dir, "out.docx")
	_, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving)
	if err == nil {
		t.Fatal("with no dispatcher configured, a part holding the reported value was " +
			"passed over and the container written as if clean")
	}
	if !strings.Contains(err.Error(), "dispatcher") {
		t.Errorf("error %q should say a dispatcher is missing so the cause is actionable",
			err.Error())
	}
}

// TestChildIsDispatchedOnlyWhenThereIsSomethingToRedact.
//
// Dispatching every embedded image in a document with no findings would be pure cost
// on the redaction path, which is already the slowest part of a scan.
func TestChildIsDispatchedOnlyWhenThereIsSomethingToRedact(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		"word/media/image1.jpg": []byte("harmless EXIF"),
	})

	fd := &fakeDispatcher{out: []byte("unused")}
	or := NewOfficeRedactor(nil, nil)
	or.SetEmbeddedRedactor(fd)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, nil, redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument with no matches: %v", err)
	}
	if len(fd.calls) != 0 {
		t.Errorf("dispatched %v with an empty match list; there is nothing to redact",
			fd.calls)
	}
}

// TestEveryAdmittedChildIsDispatched — the container must not pick and choose.
//
// A part the read side scanned but the write side never offers to a redactor is the
// original bug in a new place.
func TestEveryAdmittedChildIsDispatched(t *testing.T) {
	dir := t.TempDir()
	in := writeOuter(t, dir, "outer.docx", map[string][]byte{
		// Each child must actually HOLD the reported value: a part that provably holds
		// none of them is deliberately left untouched, so filler bytes would make this
		// test assert the opposite of the intended behaviour.
		"word/media/image1.jpg":           []byte("EXIF " + embSSN),
		"word/media/image2.png":           []byte("tEXt " + embSSN),
		"word/embeddings/oleObject1.docx": []byte("stream " + embSSN),
		"word/embeddings/legacy.doc":      []byte("ole " + embSSN),
		// Not an embedded part: must NOT be dispatched.
		"word/document2.xml": []byte("<x/>"),
	})

	fd := &fakeDispatcher{out: []byte("clean")}
	or := NewOfficeRedactor(nil, nil)
	or.SetEmbeddedRedactor(fd)

	out := filepath.Join(dir, "out.docx")
	if _, err := or.RedactDocument(in, out, embMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	want := []string{
		"word/embeddings/legacy.doc",
		"word/embeddings/oleObject1.docx",
		"word/media/image1.jpg",
		"word/media/image2.png",
	}
	got := append([]string{}, fd.calls...)
	sortStrings(got)
	if len(got) != len(want) {
		t.Fatalf("dispatched %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dispatched[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

// ---------- helpers ----------

func embMatches() []detector.Match {
	return []detector.Match{{Text: embSSN, Type: "SSN", Confidence: 100}}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func writeOuter(t *testing.T, dir, name string, extras map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buildPkg(t, "Container body text.", extras), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

func buildInnerDocx(t *testing.T, ssn string) []byte {
	t.Helper()
	return buildPkg(t, "Inner document. Employee SSN: "+ssn, nil)
}

func buildPkg(t *testing.T, body string, extras map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) {
		// Deflate explicitly: the compression is load-bearing for the residue test.
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	add("[Content_Types].xml", []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="xml" ContentType="application/xml"/>`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`</Types>`))
	add("word/document.xml", []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`+
		`<w:body><w:p><w:r><w:t>`+body+`</w:t></w:r></w:p></w:body></w:document>`))
	names := make([]string, 0, len(extras))
	for k := range extras {
		names = append(names, k)
	}
	sortStrings(names)
	for _, n := range names {
		add(n, extras[n])
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}
