// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// A value inside a file inside a file must be REDACTED, not merely reported.
//
// The read side already descends into embedded parts, so these values are found.
// The write side did not, so they were reported and then shipped in cleartext.
// Measured on the parent commit, with the container's OWN SSN correctly redacted
// in every row:
//
//	outer.docx -> word/embeddings/oleObject1.docx   SSN in cleartext, exit 0, no warning
//	outer.docx -> word/media/image1.jpg (EXIF)      SSN in cleartext, exit 0, no warning
//	both of the above in one document               2 values in cleartext
//
// Only reported findings are redacted, so a value the redactor cannot reach is a
// leak that reports as success — a file sitting in a directory named "redacted"
// with the SSN still in it. See #305.
//
// These tests are the SINK test for that. They assert on the bytes actually
// written, descending into every nested archive member, because grepping a .docx
// searches COMPRESSED bytes and finds nothing — which is indistinguishable from a
// clean file and is the most common way a leak in this area gets certified fixed.

const (
	// childSSN lives only inside the embedded part.
	childSSN = "452-11-9384"
	// outerSSN lives in the container's own body. It is the control: it was already
	// redacted correctly before this change, so a test that stops finding it has
	// broken the pre-existing behaviour rather than proving the fix.
	outerSSN = "536-90-4271"
)

func TestEmbeddedDocumentValuesAreRedacted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, dir string) string
	}{
		{"office document embedded in a document", func(t *testing.T, dir string) string {
			return writeDocx(t, dir, "outer_docx.docx", map[string][]byte{
				"word/embeddings/oleObject1.docx": buildChildDocx(t, childSSN),
			})
		}},
		{"image EXIF embedded in a document", func(t *testing.T, dir string) string {
			return writeDocx(t, dir, "outer_img.docx", map[string][]byte{
				"word/media/image1.jpg": buildJPEGWithEXIF(t, "Contact SSN "+childSSN),
			})
		}},
		{"both kinds of child in one document", func(t *testing.T, dir string) string {
			return writeDocx(t, dir, "outer_both.docx", map[string][]byte{
				"word/embeddings/oleObject1.docx": buildChildDocx(t, childSSN),
				"word/media/image1.jpg":           buildJPEGWithEXIF(t, "Contact SSN "+childSSN),
			})
		}},
		{"child nested two levels deep", func(t *testing.T, dir string) string {
			// A .docx inside a .docx inside a .docx. Well within embedded.MaxDepth,
			// so nothing may be skipped and nothing may leak.
			inner := buildChildDocx(t, childSSN)
			mid := buildDocxBytes(t, "middle document", map[string][]byte{
				"word/embeddings/inner.docx": inner,
			})
			return writeDocx(t, dir, "outer_deep.docx", map[string][]byte{
				"word/embeddings/mid.docx": mid,
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := tc.build(t, dir)
			outDir := filepath.Join(dir, "redacted")

			res, err := RedactFile(RedactConfig{
				FilePath:  in,
				OutputDir: outDir,
				Checks:    []string{"SSN"},
				Config:    config.LoadConfigOrDefault(""),
			})
			if err != nil {
				t.Fatalf("RedactFile: %v", err)
			}
			if res.RedactionCount == 0 {
				t.Fatalf("RedactionCount is 0; the fixture produced no redactions at all, "+
					"so this test cannot show anything about nested content (path %s)", in)
			}

			written := findOneFile(t, outDir)

			// The child's value must be gone from EVERY nested member.
			if hits := cleartextHits(t, written, childSSN); len(hits) > 0 {
				t.Errorf("the embedded value survived redaction in %d place(s):\n  %s\n"+
					"This file is in a directory named \"redacted\" and the run reported "+
					"%d redactions, so a caller would forward it.",
					len(hits), strings.Join(hits, "\n  "), res.RedactionCount)
			}

			// The container's own value must STILL be gone — the control.
			if hits := cleartextHits(t, written, outerSSN); len(hits) > 0 {
				t.Errorf("the container's own value is no longer redacted (%v); the change "+
					"broke pre-existing behaviour rather than adding to it", hits)
			}
		})
	}
}

// TestUnredactableEmbeddedPartFailsLoudly is the other half, and the one that keeps
// the fix honest.
//
// Two shapes reach it, and both must refuse to write:
//
//   - a part whose bytes demonstrably hold a reported value and whose redactor cannot
//     process them (an undecodable image carrying the same SSN as the body);
//   - an embedded PDF, which is scanned -- so its values ARE reported -- but which no
//     redactor can rewrite, and whose FlateDecode streams mean a byte scan cannot
//     prove it clean either.
//
// The same policy already applies one level up: a standalone PDF or an undecodable
// image with findings produces NO file and the run says "redaction incomplete ... the
// original values remain in cleartext". Nesting must not change the guarantee.
func TestUnredactableEmbeddedPartFailsLoudly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		extras   map[string][]byte
		wantPart string
	}{
		{
			name: "undecodable image holding the body's value",
			body: "Employee SSN: " + childSSN,
			extras: map[string][]byte{
				"word/media/image1.jpg": []byte("\xff\xd8\xff\xe1\x00\x20Exif\x00\x00 ref " +
					childSSN + " \xff\xd9"),
			},
			wantPart: "image1.jpg",
		},
		{
			name: "embedded PDF, scanned but not redactable",
			body: "Outer body. Outer SSN: " + outerSSN,
			extras: map[string][]byte{
				"word/embeddings/attachment.pdf": buildPDFWithText(t, "Employee SSN: "+childSSN),
			},
			wantPart: "attachment.pdf",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := writeDocxBody(t, dir, "outer.docx", tc.body, tc.extras)
			outDir := filepath.Join(dir, "redacted")

			_, err := RedactFile(RedactConfig{
				FilePath:  in,
				OutputDir: outDir,
				Checks:    []string{"SSN"},
				Config:    config.LoadConfigOrDefault(""),
			})
			if err == nil {
				for _, f := range allFiles(outDir) {
					if hits := cleartextHits(t, f, childSSN); len(hits) > 0 {
						t.Fatalf("RedactFile reported success and wrote %s with the value "+
							"still present at %v", f, hits)
					}
				}
				t.Fatal("RedactFile returned nil error for a document with an embedded part " +
					"it could not redact; the caller has nothing to branch on")
			}
			if !strings.Contains(err.Error(), tc.wantPart) {
				t.Errorf("error %q does not name the offending part %q", err.Error(), tc.wantPart)
			}
			for _, f := range allFiles(outDir) {
				if hits := cleartextHits(t, f, childSSN); len(hits) > 0 {
					t.Errorf("a file was written at %s containing the cleartext value %v "+
						"despite the failure", f, hits)
				}
			}
		})
	}
}

// TestCleanEmbeddedPartIsLeftByteIdentical is the over-redaction guard, and it caught a
// real defect in the first version of this change.
//
// Every redactor here is lossy in some way: the image redactor DECODES and re-encodes
// and strips all metadata. So a part holding none of the reported values must not be
// handed to one merely because the DOCUMENT has findings elsewhere. Measured before the
// fix, on a document whose body held an SSN and which also carried an unrelated photo:
// the photo came back re-encoded from 706 to 664 bytes, with a different hash and its
// caption removed. Nothing in it had ever been reported.
func TestCleanEmbeddedPartIsLeftByteIdentical(t *testing.T) {
	dir := t.TempDir()

	photo := buildJPEGWithEXIF(t, "Holiday photo by the sea")
	in := writeDocxBody(t, dir, "outer_clean_photo.docx",
		"Body SSN: "+outerSSN,
		map[string][]byte{"word/media/photo.jpg": photo})
	outDir := filepath.Join(dir, "redacted")

	res, err := RedactFile(RedactConfig{
		FilePath:  in,
		OutputDir: outDir,
		Checks:    []string{"SSN"},
		Config:    config.LoadConfigOrDefault(""),
	})
	if err != nil {
		t.Fatalf("RedactFile: %v", err)
	}
	if res.RedactionCount == 0 {
		t.Fatal("no redactions performed; the fixture is broken and this test would be vacuous")
	}

	written := findOneFile(t, outDir)
	if hits := cleartextHits(t, written, outerSSN); len(hits) > 0 {
		t.Errorf("the body value was not redacted: %v", hits)
	}

	got := readEntry(t, written, "word/media/photo.jpg")
	if !bytes.Equal(got, photo) {
		t.Errorf("an embedded part holding NONE of the reported values was rewritten: "+
			"%d bytes in, %d bytes out.\nThe image redactor decodes and re-encodes and "+
			"strips metadata, so dispatching a clean part silently degrades content that "+
			"was never implicated.", len(photo), len(got))
	}
	if !bytes.Contains(got, []byte("Holiday photo by the sea")) {
		t.Error("the innocent photo's caption was stripped")
	}
}

// TestContainerWithHarmlessUndecodableChildStillRedacts bounds the blast radius of
// failing closed.
//
// An embedded image that holds NONE of the reported values must not stop the
// container from being written, even if the image redactor cannot process it. The
// naive "any child failure fails the document" rule would mean one odd JPEG blocks
// a 50-redaction document — a regression dressed as safety.
func TestContainerWithHarmlessUndecodableChildStillRedacts(t *testing.T) {
	dir := t.TempDir()
	// Bytes that are not a decodable image and contain none of the values.
	junk := []byte("\xff\xd8\xff\xe0 this is not a decodable jpeg at all \x00\x01\x02")
	in := writeDocx(t, dir, "outer_junk.docx", map[string][]byte{
		"word/media/image1.jpg": junk,
	})
	outDir := filepath.Join(dir, "redacted")

	res, err := RedactFile(RedactConfig{
		FilePath:  in,
		OutputDir: outDir,
		Checks:    []string{"SSN"},
		Config:    config.LoadConfigOrDefault(""),
	})
	if err != nil {
		t.Fatalf("an embedded part holding no reported value blocked the whole document: %v\n"+
			"Failing closed must be driven by residue, not by any child error.", err)
	}
	if res.RedactionCount == 0 {
		t.Fatal("no redactions performed; the fixture is broken")
	}
	written := findOneFile(t, outDir)
	if hits := cleartextHits(t, written, outerSSN); len(hits) > 0 {
		t.Errorf("the container's own value was not redacted: %v", hits)
	}
}

// TestRedactedContainerStaysAValidPackage — a redacted document must still open.
//
// Storing new bytes at an existing entry is only safe if the package's structure
// survives: OPC requires [Content_Types].xml in the FIRST entry slot, and the
// repackager preserves source order specifically because ranging a map had been
// moving it.
func TestRedactedContainerStaysAValidPackage(t *testing.T) {
	dir := t.TempDir()
	in := writeDocx(t, dir, "outer.docx", map[string][]byte{
		"word/embeddings/oleObject1.docx": buildChildDocx(t, childSSN),
		"word/media/image1.jpg":           buildJPEGWithEXIF(t, "Contact SSN "+childSSN),
	})
	outDir := filepath.Join(dir, "redacted")

	if _, err := RedactFile(RedactConfig{
		FilePath:  in,
		OutputDir: outDir,
		Checks:    []string{"SSN"},
		Config:    config.LoadConfigOrDefault(""),
	}); err != nil {
		t.Fatalf("RedactFile: %v", err)
	}

	written := findOneFile(t, outDir)
	zr, err := zip.OpenReader(written)
	if err != nil {
		t.Fatalf("the redacted document is not a readable package: %v", err)
	}
	defer zr.Close()

	if len(zr.File) == 0 {
		t.Fatal("the redacted package has no entries")
	}
	if got := zr.File[0].Name; got != "[Content_Types].xml" {
		t.Errorf("first entry is %q, want [Content_Types].xml — OPC requires it in the "+
			"first slot and Word refuses the file otherwise", got)
	}

	// Compare the entry NAME LIST with the input's: storing redacted bytes must not
	// add, drop or reorder entries.
	if want, got := entryNames(t, in), entryNames(t, written); !equalStrings(want, got) {
		t.Errorf("entry list changed.\n input: %v\noutput: %v", want, got)
	}

	// The embedded child must still be a well-formed package of its own.
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".docx") {
			continue
		}
		b := readZipEntry(t, f)
		if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
			t.Errorf("embedded child %s is no longer a readable package after redaction: %v",
				f.Name, err)
		}
	}
}

// ---------- helpers ----------

// cleartextHits reports every place needle appears in the file, DESCENDING into
// nested archive members so a deflated value is found decompressed.
func cleartextHits(t *testing.T, path, needle string) []string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var hits []string
	scanForNeedle(t, filepath.Base(path), b, needle, 0, &hits)
	return hits
}

func scanForNeedle(t *testing.T, label string, data []byte, needle string, depth int, hits *[]string) {
	t.Helper()
	if depth > 6 {
		return
	}
	if bytes.Contains(data, []byte(needle)) {
		*hits = append(*hits, label)
	}
	if !bytes.HasPrefix(data, []byte("PK")) {
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		inner, err := io.ReadAll(io.LimitReader(rc, 64<<20))
		_ = rc.Close()
		if err != nil {
			continue
		}
		scanForNeedle(t, label+"!"+f.Name, inner, needle, depth+1, hits)
	}
}

func allFiles(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi != nil && !fi.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func findOneFile(t *testing.T, dir string) string {
	t.Helper()
	files := allFiles(dir)
	if len(files) != 1 {
		t.Fatalf("expected exactly one written file under %s, got %d: %v", dir, len(files), files)
	}
	return files[0]
}

func entryNames(t *testing.T, path string) []string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer zr.Close()
	names := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	return names
}

func readZipEntry(t *testing.T, f *zip.File) []byte {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatalf("opening entry %s: %v", f.Name, err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("reading entry %s: %v", f.Name, err)
	}
	return b
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const ctHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Default Extension="jpg" ContentType="image/jpeg"/>` +
	`<Default Extension="pdf" ContentType="application/pdf"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

func documentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`
}

// buildDocxBytes builds a minimal but valid OOXML package in memory.
func buildDocxBytes(t *testing.T, body string, extras map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, data []byte) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	// [Content_Types].xml first, as OPC requires.
	write("[Content_Types].xml", []byte(ctHeader))
	write("_rels/.rels", []byte(relsXML))
	write("word/document.xml", []byte(documentXML(body)))
	// Sorted so the fixture is byte-reproducible regardless of map order.
	for _, name := range sortedKeys(extras) {
		write(name, extras[name])
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// insertion sort keeps this dependency-free and the maps are tiny
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// writeDocx writes a container whose own body holds outerSSN, so every fixture has
// a control value that was already being redacted before this change.
func writeDocx(t *testing.T, dir, name string, extras map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := buildDocxBytes(t, "Outer body. Outer SSN: "+outerSSN, extras)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// writeDocxBody writes a container with a caller-chosen body, for fixtures where the
// body's own value is the one that matters.
func writeDocxBody(t *testing.T, dir, name, body string, extras map[string][]byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buildDocxBytes(t, body, extras), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// readEntry returns one archive member's bytes.
func readEntry(t *testing.T, archive, entry string) []byte {
	t.Helper()
	zr, err := zip.OpenReader(archive)
	if err != nil {
		t.Fatalf("opening %s: %v", archive, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name == entry {
			return readZipEntry(t, f)
		}
	}
	t.Fatalf("entry %q not found in %s", entry, archive)
	return nil
}

func buildChildDocx(t *testing.T, ssn string) []byte {
	t.Helper()
	return buildDocxBytes(t, "Embedded child document. Employee SSN: "+ssn, nil)
}

// buildJPEGWithEXIF encodes a REAL image and splices in an EXIF APP1 segment
// carrying desc in ImageDescription.
//
// The image is encoded by the standard library rather than hand-rolled, because the
// image redactor DECODES before re-encoding: a hand-built JPEG without Huffman
// tables fails with "uninitialized Huffman table", which would make this fixture
// exercise the error path instead of the redaction path.
func buildJPEGWithEXIF(t *testing.T, desc string) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 32), G: uint8(y * 32), B: 128, A: 255})
		}
	}
	var base bytes.Buffer
	if err := jpeg.Encode(&base, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encoding jpeg: %v", err)
	}
	b := base.Bytes()

	d := append([]byte(desc), 0)
	var tiff bytes.Buffer
	tiff.WriteString("MM")
	_ = binary.Write(&tiff, binary.BigEndian, uint16(42))
	_ = binary.Write(&tiff, binary.BigEndian, uint32(8))
	_ = binary.Write(&tiff, binary.BigEndian, uint16(1))
	_ = binary.Write(&tiff, binary.BigEndian, uint16(0x010E)) // ImageDescription
	_ = binary.Write(&tiff, binary.BigEndian, uint16(2))      // ASCII
	_ = binary.Write(&tiff, binary.BigEndian, uint32(len(d)))
	_ = binary.Write(&tiff, binary.BigEndian, uint32(26)) // value offset
	_ = binary.Write(&tiff, binary.BigEndian, uint32(0))  // no next IFD
	tiff.Write(d)

	payload := append([]byte("Exif\x00\x00"), tiff.Bytes()...)
	app1 := []byte{0xFF, 0xE1}
	app1 = binary.BigEndian.AppendUint16(app1, uint16(len(payload)+2))
	app1 = append(app1, payload...)

	out := make([]byte, 0, len(b)+len(app1))
	out = append(out, b[:2]...) // SOI
	out = append(out, app1...)
	out = append(out, b[2:]...)

	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("fixture jpeg does not decode after the EXIF splice: %v", err)
	}
	if !bytes.Contains(out, []byte(desc)) {
		t.Fatal("fixture jpeg does not contain the description; EXIF splice failed")
	}
	return out
}

// buildPDFWithText builds a structurally valid PDF with a correct xref AND
// startxref. Both are required — without startxref the extractor errors instead of
// parsing, which would silently redirect this test onto a different code path.
func buildPDFWithText(t *testing.T, text string) []byte {
	t.Helper()
	content := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET\n"
	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R " +
			"/Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
		"4 0 obj\n<< /Length " + itoaTest(len(content)) + " >>\nstream\n" + content + "endstream\nendobj\n",
		"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
	}
	var sb strings.Builder
	sb.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objs))
	for _, o := range objs {
		offsets = append(offsets, sb.Len())
		sb.WriteString(o)
	}
	xref := sb.Len()
	sb.WriteString("xref\n0 " + itoaTest(len(objs)+1) + "\n0000000000 65535 f \n")
	for _, off := range offsets {
		sb.WriteString(pad10Test(off) + " 00000 n \n")
	}
	sb.WriteString("trailer\n<< /Size " + itoaTest(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" +
		itoaTest(xref) + "\n%%EOF\n")
	return []byte(sb.String())
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func pad10Test(n int) string {
	s := itoaTest(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}
