// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package embedded

import (
	"archive/zip"
	"bytes"
	"testing"
)

// validZip builds a small, genuinely readable archive.
func validZip(t *testing.T, entry, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entry)
	if err != nil {
		t.Fatalf("create entry: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("write entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// unopenableZip has the zip magic and is not a readable archive — the shape a truncated or
// corrupt attachment has, and the one that reproduced #517.
func unopenableZip() []byte {
	return append([]byte("PK\x03\x04"), bytes.Repeat([]byte{0}, 512)...)
}

// TestAnUnopenableOOXMLPartIsNotInspectable is the regression test for #517.
//
// The residue scan treats "nothing found" as "holds none of the reported values", and for a
// zip-backed type that reading rests on the scan being able to INFLATE the archive's members
// (stated in AdmittedExts' own doc comment: "OOXML — deflated, but the scan inflates archive
// members"). When the archive will not open, the premise fails: the scan reads compressed bytes,
// finds nothing, and the part is skipped and copied through verbatim.
//
// Measured on a real .docx carrying word/embeddings/attach.docx whose bytes begin with the zip
// magic but are not a readable archive: the value inside was never REPORTED — so it was absent
// from the redaction value set, so the residue scan was not looking for it — and the "redacted"
// document shipped it in cleartext at exit 0.
func TestAnUnopenableOOXMLPartIsNotInspectable(t *testing.T) {
	for _, name := range []string{"word/embeddings/attach.docx", "x.xlsx", "deck.pptx", "UPPER.DOCX"} {
		t.Run(name, func(t *testing.T) {
			// Non-vacuity: the NAME alone must still say inspectable, or this test would pass
			// for the wrong reason — it is the CONTENT that changes the answer.
			if !ResidueInspectable(name) {
				t.Fatalf("%s is already opaque by name, so this test proves nothing about content", name)
			}
			if ContentInspectable(name, unopenableZip()) {
				t.Errorf("%s with unopenable bytes was reported inspectable; the residue scan cannot "+
					"see inside it, so 'nothing found' would be read as 'holds nothing' (#517)", name)
			}
		})
	}
}

// TestAReadableOOXMLPartIsInspectable is the control that keeps the fix from refusing every
// container with an embedded document.
//
// Measured on 372 real Office files: NONE carries a zip-backed embedded part, so the corpus cannot
// demonstrate this direction and a purpose-built control is required.
func TestAReadableOOXMLPartIsInspectable(t *testing.T) {
	content := validZip(t, "word/document.xml", "<w:t>hello</w:t>")
	for _, name := range []string{"inner.docx", "book.xlsx", "deck.pptx"} {
		if !ContentInspectable(name, content) {
			t.Errorf("%s with a readable archive was reported uninspectable, which would refuse "+
				"every container holding a legitimate embedded document", name)
		}
	}
}

// TestANonZipBackedTypeIgnoresItsContent.
//
// Images, audio and legacy OLE store their text uncompressed, so a flat byte scan IS sound for them
// whatever the bytes look like. Extending the archive test to those types would refuse parts the
// scan can read perfectly well.
func TestANonZipBackedTypeIgnoresItsContent(t *testing.T) {
	for _, name := range []string{"photo.jpg", "clip.mp3", "legacy.doc", "sheet.xls", "unknown.xyz"} {
		for label, content := range map[string][]byte{
			"garbage":      unopenableZip(),
			"empty":        nil,
			"readable zip": validZip(t, "a", "b"),
			"plain text":   []byte("just some bytes"),
		} {
			if !ContentInspectable(name, content) {
				t.Errorf("%s with %s content was reported uninspectable; only zip-backed types "+
					"depend on the archive opening", name, label)
			}
		}
	}
}

// TestPDFStaysOpaqueWhateverItsBytes: PDF is opaque by NAME because its text is compressed in a way
// the scan cannot read at all. The content test must not upgrade it to inspectable.
func TestPDFStaysOpaqueWhateverItsBytes(t *testing.T) {
	for label, content := range map[string][]byte{
		"a readable zip": validZip(t, "a", "b"),
		"a real-ish PDF": []byte("%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"),
		"empty":          nil,
	} {
		if ContentInspectable("attachment.pdf", content) {
			t.Errorf("attachment.pdf with %s was reported inspectable; PDF text lives in FlateDecode "+
				"streams the scan cannot read, so it must stay always-dispatched", label)
		}
	}
}

// TestAnEmptyOOXMLPartIsNotInspectable: a zero-length part is not an archive either, and treating
// it as inspectable would let a truncated attachment be skipped on an empty scan.
func TestAnEmptyOOXMLPartIsNotInspectable(t *testing.T) {
	for label, content := range map[string][]byte{"nil": nil, "empty": {}, "two bytes": []byte("PK")} {
		if ContentInspectable("inner.docx", content) {
			t.Errorf("inner.docx with %s content was reported inspectable", label)
		}
	}
}

// TestContentInspectableAgreesWithResidueInspectableWhereItMust.
//
// The two must not drift. For every admitted extension, a READABLE archive as content has to give
// the same answer as the name-only test — otherwise the content test is silently narrowing the
// admission set rather than only catching unreadable archives.
func TestContentInspectableAgreesWithResidueInspectableWhereItMust(t *testing.T) {
	content := validZip(t, "word/document.xml", "<w:t>x</w:t>")
	for _, ext := range AdmittedExts() {
		name := "part" + ext
		byName := ResidueInspectable(name)
		byContent := ContentInspectable(name, content)
		if byName != byContent {
			t.Errorf("%s: ResidueInspectable=%v but ContentInspectable=%v with a readable archive; "+
				"the content test must only ever catch an archive that will not open",
				ext, byName, byContent)
		}
	}
}
