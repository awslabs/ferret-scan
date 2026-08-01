// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// iterations is high enough that a randomized Go map order over the seven-part
// package below is overwhelmingly unlikely to reproduce the source order every
// time by chance.
const iterations = 40

// partOrder is the entry order the fixture package is written in. It is
// deliberately not alphabetical, so a fix that sorted the names instead of
// replaying the original order would fail this test.
var partOrder = []string{
	"[Content_Types].xml",
	"_rels/.rels",
	"word/document.xml",
	"word/_rels/document.xml.rels",
	"word/styles.xml",
	"word/settings.xml",
	"docProps/core.xml",
}

// writeFixtureDocx writes a minimal but structurally real .docx containing one
// SSN and one credit card number in the document body.
//
// The path is relative to the test's working directory rather than under
// t.TempDir(): the Office preprocessors reject absolute paths below /tmp, /var
// and /home, and a fixture that lands there silently exercises a different code
// path.
func writeFixtureDocx(t *testing.T) string {
	t.Helper()

	dir := filepath.Join("testdata", "tmp-emit-order")
	// The output subdirectory is created up front: these tests construct the
	// redactor without an OutputStructureManager, and repackaging only creates
	// directories when one is wired in.
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(filepath.Join("testdata", "tmp-emit-order")) })

	parts := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			`<w:p><w:r><w:t>Employee SSN: 449-87-4100</w:t></w:r></w:p>` +
			`<w:p><w:r><w:t>Card on file: 4532-0151-1283-0366</w:t></w:r></w:p>` +
			`</w:body></w:document>`,
		"word/_rels/document.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`,
		"word/styles.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`,
		"word/settings.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`,
		"docProps/core.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"/>`,
	}

	path := filepath.Join(dir, "probe.docx")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range partOrder {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(parts[name])); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func fixtureMatches(filename string) []detector.Match {
	return []detector.Match{
		{Text: "449-87-4100", LineNumber: 1, Type: "SSN", Confidence: 100, Filename: filename, Validator: "ssn"},
		{Text: "4532-0151-1283-0366", LineNumber: 2, Type: "CREDIT_CARD", Confidence: 100, Filename: filename, Validator: "creditcard"},
	}
}

// zipEntryNames returns the entry names of a ZIP file in central-directory order.
func zipEntryNames(t *testing.T, path string) []string {
	t.Helper()
	r, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open redacted package %s: %v", path, err)
	}
	defer r.Close()

	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return names
}

// TestRepackage_PreservesSourceEntryOrder is the regression guard for the
// repackaging bug: repackageOfficeDocument wrote the redacted package by ranging
// the contents map, so the parts came out in a random order on every run. Two
// consequences, both real: the redacted .docx was not byte reproducible for the
// same input, and [Content_Types].xml — which OPC requires to be the first entry
// — frequently ended up somewhere in the middle.
func TestRepackage_PreservesSourceEntryOrder(t *testing.T) {
	src := writeFixtureDocx(t)
	outDir := filepath.Join("testdata", "tmp-emit-order", "out")

	r := NewOfficeRedactor(nil, nil)
	for i := 0; i < iterations; i++ {
		out := filepath.Join(outDir, "redacted.docx")
		if _, err := r.RedactDocument(src, out, fixtureMatches(src), redactors.RedactionSimple); err != nil {
			t.Fatalf("iteration %d: RedactDocument: %v", i, err)
		}

		got := zipEntryNames(t, out)
		if len(got) != len(partOrder) {
			t.Fatalf("iteration %d: got %d entries, want %d: %v", i, len(got), len(partOrder), got)
		}
		for j := range partOrder {
			if got[j] != partOrder[j] {
				t.Fatalf("iteration %d: entry %d = %q, want %q\nfull order: %v",
					i, j, got[j], partOrder[j], got)
			}
		}
		if got[0] != "[Content_Types].xml" {
			t.Fatalf("iteration %d: [Content_Types].xml must be the first package entry, got %q", i, got[0])
		}
		os.Remove(out)
	}
}

// TestRepackage_ByteReproducible checks the stronger property the order fix
// buys: redacting one unchanged input twice produces identical bytes. Simple
// strategy only — synthetic replacements are randomized by design.
func TestRepackage_ByteReproducible(t *testing.T) {
	src := writeFixtureDocx(t)
	outDir := filepath.Join("testdata", "tmp-emit-order", "out")

	r := NewOfficeRedactor(nil, nil)
	hashes := make(map[string]int)
	for i := 0; i < iterations; i++ {
		out := filepath.Join(outDir, "reproducible.docx")
		if _, err := r.RedactDocument(src, out, fixtureMatches(src), redactors.RedactionSimple); err != nil {
			t.Fatalf("iteration %d: RedactDocument: %v", i, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("iteration %d: read output: %v", i, err)
		}
		sum := sha256.Sum256(data)
		hashes[hex.EncodeToString(sum[:])]++
		os.Remove(out)
	}

	if len(hashes) != 1 {
		t.Fatalf("redacting one unchanged input %d times produced %d distinct outputs, want 1: %v",
			iterations, len(hashes), hashes)
	}
}

// TestRepackage_RedactsSensitiveValues guards the fix against the trivially
// wrong version of itself: an entry order that is stable but drops or fails to
// redact content. The raw SSN and card number must not survive anywhere in the
// package.
func TestRepackage_RedactsSensitiveValues(t *testing.T) {
	src := writeFixtureDocx(t)
	out := filepath.Join("testdata", "tmp-emit-order", "out", "checked.docx")

	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, fixtureMatches(src), redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	// The parts are stored deflated, so scan the decompressed entries rather
	// than the container bytes.
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open output as zip: %v", err)
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		for _, secret := range []string{"449-87-4100", "4532-0151-1283-0366"} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("entry %s still contains the raw value", f.Name)
			}
		}
	}
}

// TestRepackage_MetadataMatchDoesNotSuppressBodyRedaction covers the gap that
// let a real leak through: TestRepackage_RedactsSensitiveValues passes matches
// with no Context.FullLine, so every match is position-unresolvable and the
// overlap-containment path is never entered at all.
//
// Here the matches carry FullLine the way the scanner really populates it. The
// metadata match comes from docProps/core.xml and the body match from
// word/document.xml, and both are reported as line 1 because line numbers are
// counted per part. Their offsets are measured against different strings, so
// treating one as "contained" in the other is a coordinate-system error — and
// it silently dropped the body SSN before redaction was attempted.
func TestRepackage_MetadataMatchDoesNotSuppressBodyRedaction(t *testing.T) {
	src := writeFixtureDocx(t)
	out := filepath.Join("testdata", "tmp-emit-order", "out", "metaline.docx")

	const (
		ssn        = "449-87-4100"
		bodyLine   = "Employee SSN: 449-87-4100"
		author     = "Jane Quincy Analyst-Smith"
		authorLine = "Creator: Jane Quincy Analyst-Smith"
	)

	// Guard against this test quietly becoming vacuous: it is only meaningful
	// while the author's span numerically contains the SSN's span and is wider.
	// If someone edits the strings so containment no longer holds, the test
	// would pass without exercising anything.
	ssnStart := strings.Index(bodyLine, ssn)
	ssnEnd := ssnStart + len(ssn)
	authorStart := strings.Index(authorLine, author)
	authorEnd := authorStart + len(author)
	if ssnStart < 0 || authorStart < 0 {
		t.Fatalf("fixture strings are inconsistent: ssnStart=%d authorStart=%d", ssnStart, authorStart)
	}
	if !(authorStart <= ssnStart && ssnEnd <= authorEnd && (authorEnd-authorStart) > (ssnEnd-ssnStart)) {
		t.Fatalf("precondition lost: author span [%d,%d) must strictly contain SSN span [%d,%d), else this test proves nothing",
			authorStart, authorEnd, ssnStart, ssnEnd)
	}

	matches := []detector.Match{
		{
			Text: ssn, LineNumber: 1, Type: "SSN", Confidence: 100,
			Filename: src, Validator: "ssn",
			Context: detector.ContextInfo{FullLine: bodyLine},
		},
		{
			Text: author, LineNumber: 1, Type: "AUTHOR_INFO", Confidence: 80,
			Filename: src, Validator: "metadata",
			Context: detector.ContextInfo{FullLine: authorLine},
		},
	}

	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("open output as zip: %v", err)
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		if bytes.Contains(content, []byte(ssn)) {
			t.Errorf("entry %s still contains the raw SSN: a metadata match on the same line NUMBER must not suppress body redaction", f.Name)
		}
	}
}
