// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #514: no redactor claimed .odt/.ods/.odp, so every ODF finding was reported and then left in
// cleartext — "no redactor registered for file type: .odt", 7 reported values, no copy written.
//
// Disclosed rather than silent, and that is why it sat below the silent-miss issues; but a
// reported value that is never removed is still a value left in cleartext. #528 widened it by
// making the .ott/.ots/.otp templates scannable, so the count of reported-and-abandoned values
// grew before anything could remove them.
//
// Two things make this more than "register the extension". The office redactor is written against
// OOXML part names (word/document.xml, xl/sharedStrings.xml) and OOXML text elements (w:t), none of
// which exist in ODF — registering .odt against it unchanged would open the package, match no part,
// and write an output byte-identical to the input while reporting success. And the package itself
// has a structural rule: ODF 1.2 §3.3 requires `mimetype` first and STORED.

// odfPart is one entry in a built ODF package.
type odfPart struct {
	name   string
	body   string
	stored bool
}

// buildODF writes a minimal but VALID OpenDocument package.
//
// mimetype is written first and STORED, because that is what a conforming producer does and the
// point of these tests is what the redactor does to a conforming file. META-INF/manifest.xml is
// included for the same reason.
func buildODF(t *testing.T, path, mime string, extra ...odfPart) string {
	t.Helper()

	manifest := `<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="` + mime + `"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
</manifest:manifest>`

	parts := append([]odfPart{
		{name: "mimetype", body: mime, stored: true},
		{name: "META-INF/manifest.xml", body: manifest},
	}, extra...)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		var w interface{ Write([]byte) (int, error) }
		var err error
		if p.stored {
			w, err = zw.CreateHeader(&zip.FileHeader{Name: p.name, Method: zip.Store})
		} else {
			w, err = zw.Create(p.name)
		}
		if err != nil {
			t.Fatalf("zip entry %s: %v", p.name, err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			t.Fatalf("write %s: %v", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

const (
	odfSSN    = "452-11-9384"
	odfAuthor = "Marcus Delacroix"
	odfEditor = "Priya Raghunathan"
)

func odfContentXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.3">
 <office:body><office:text>
  <text:h>Patient file</text:h>
  <text:p>Patient SSN: ` + odfSSN + `</text:p>
  <text:p>Note <text:span>` + odfSSN + `</text:span> repeated inline</text:p>
 </office:text></office:body>
</office:document-content>`
}

func odfMetaXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/" office:version="1.3">
 <office:meta>
  <meta:initial-creator>` + odfAuthor + `</meta:initial-creator>
  <dc:creator>` + odfEditor + `</dc:creator>
  <meta:user-defined meta:name="Matter">` + odfSSN + `</meta:user-defined>
 </office:meta>
</office:document-meta>`
}

// matchFor builds the finding the scanner would report for value, in the given part.
func matchFor(value, typ string) detector.Match {
	return detector.Match{
		Text:       value,
		Type:       typ,
		Confidence: 95,
		Validator:  "test",
		LineNumber: 1,
	}
}

// readPartsInsideZip returns every entry's decompressed bytes.
//
// This exists because the ONLY honest way to check an Office redaction is to read the part INSIDE
// the container. Grepping the package's bytes for a value returns zero on a deflated part whether
// or not the value is still there, so a byte scan of the file looks like a pass on a redaction that
// did nothing. The repository has a note about exactly this.
func readPartsInsideZip(t *testing.T, path string) map[string][]byte {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open %s as zip: %v", path, err)
	}
	defer zr.Close()

	out := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open part %s: %v", f.Name, err)
		}
		var b bytes.Buffer
		if _, err := b.ReadFrom(rc); err != nil {
			_ = rc.Close()
			t.Fatalf("read part %s: %v", f.Name, err)
		}
		_ = rc.Close()
		out[f.Name] = b.Bytes()
	}
	return out
}

// redactODF runs the office redactor over path and returns the written copy's path, or "" when
// the redactor declined to write one.
func redactODF(t *testing.T, path string, matches []detector.Match) (string, *redactors.RedactionResult) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "redacted"+filepath.Ext(path))
	res, err := NewOfficeRedactor(nil, nil).RedactDocument(path, out, matches, redactors.RedactionSimple)
	if err != nil {
		// A refusal is a legitimate outcome the caller asserts on, not a test failure: the
		// residue guard declines to write when a reported value could not be removed.
		t.Logf("RedactDocument returned: %v", err)
		return "", res
	}
	if _, statErr := os.Stat(out); statErr != nil {
		return "", res
	}
	return out, res
}

// TestODFBodyAndMetadataAreRedacted is the regression test.
//
// Every reported value must be gone from the part it lived in, checked INSIDE the zip. The three
// values deliberately sit in three different places — a paragraph, an inline span, and a meta.xml
// property — because the part map and the element vocabulary are separate decisions and a fix to
// one does not imply the other.
func TestODFBodyAndMetadataAreRedacted(t *testing.T) {
	for _, tc := range []struct{ ext, mime string }{
		{".odt", "application/vnd.oasis.opendocument.text"},
		{".ods", "application/vnd.oasis.opendocument.spreadsheet"},
		{".odp", "application/vnd.oasis.opendocument.presentation"},
		{".ott", "application/vnd.oasis.opendocument.text-template"},
		{".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
		{".otp", "application/vnd.oasis.opendocument.presentation-template"},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			src := buildODF(t, filepath.Join(t.TempDir(), "doc"+tc.ext), tc.mime,
				odfPart{name: "content.xml", body: odfContentXML()},
				odfPart{name: "meta.xml", body: odfMetaXML()},
			)

			written, res := redactODF(t, src, []detector.Match{
				matchFor(odfSSN, "SSN"),
				matchFor(odfAuthor, "AUTHOR_INFO"),
				matchFor(odfEditor, "LAST_MODIFIED_BY"),
			})
			if written == "" {
				t.Fatalf("no redacted copy was written; result=%+v\n"+
					"Before this change the redactor refused every ODF package with "+
					"\"no redactor registered for file type: %s\", leaving each reported value in "+
					"cleartext (#514).", res, tc.ext)
			}

			parts := readPartsInsideZip(t, written)
			for _, value := range []string{odfSSN, odfAuthor, odfEditor} {
				for name, body := range parts {
					if bytes.Contains(body, []byte(value)) {
						t.Errorf("reported value %q survives INSIDE %s of the redacted copy.\n"+
							"A reported value that is not removed is a value left in cleartext, and "+
							"the copy claims to be redacted.", value, name)
					}
				}
			}
			// Non-vacuity: the values must have been in the source to begin with, or the loop
			// above proves nothing.
			srcParts := readPartsInsideZip(t, src)
			for _, value := range []string{odfSSN, odfAuthor, odfEditor} {
				var found bool
				for _, body := range srcParts {
					if bytes.Contains(body, []byte(value)) {
						found = true
					}
				}
				if !found {
					t.Fatalf("fixture never contained %q, so this case tests nothing", value)
				}
			}
		})
	}
}

// TestRedactedODFKeepsMimetypeFirstStoredAndDescriptorFree is the container invariant, and it is
// the check that nothing cheaper substitutes for.
//
// ODF 1.2 §3.3 requires `mimetype` to be the first entry and STORED. Go's zip writer additionally
// STREAMS: both Create and CreateHeader set general-purpose bit 3 and defer the CRC and sizes to a
// trailing data descriptor, leaving zeros in the local header. LibreOffice refuses such a package.
//
// Measured on the first local header while developing this:
//
//	CreateHeader   flag=0x0008  crc=00000000  csize=0   usize=0   -> "source file could not be loaded"
//	CreateRaw      flag=0x0000  crc=0c32c65e  csize=39  usize=39  -> opens
//
// With the descriptor form `file(1)` still reported "OpenDocument Text", zip integrity passed, and
// both XML parts parsed — so this test reads the raw local header rather than relying on any of
// those, because all three of them passed on a file no reader would open.
func TestRedactedODFKeepsMimetypeFirstStoredAndDescriptorFree(t *testing.T) {
	src := buildODF(t, filepath.Join(t.TempDir(), "doc.odt"),
		"application/vnd.oasis.opendocument.text",
		odfPart{name: "content.xml", body: odfContentXML()},
		odfPart{name: "meta.xml", body: odfMetaXML()},
	)
	written, _ := redactODF(t, src, []detector.Match{matchFor(odfSSN, "SSN")})
	if written == "" {
		t.Fatal("no redacted copy was written")
	}

	raw, err := os.ReadFile(written) // #nosec G304 -- path produced by the redactor under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 30 || !bytes.HasPrefix(raw, []byte("PK\x03\x04")) {
		t.Fatalf("output is not a zip (first bytes %q)", raw[:min(8, len(raw))])
	}

	flag := binary.LittleEndian.Uint16(raw[6:8])
	method := binary.LittleEndian.Uint16(raw[8:10])
	crc := binary.LittleEndian.Uint32(raw[14:18])
	csize := binary.LittleEndian.Uint32(raw[18:22])
	usize := binary.LittleEndian.Uint32(raw[22:26])
	nameLen := binary.LittleEndian.Uint16(raw[26:28])
	name := string(raw[30 : 30+int(nameLen)])

	if name != "mimetype" {
		t.Errorf("first zip entry is %q, want \"mimetype\" (ODF 1.2 §3.3)", name)
	}
	if method != zip.Store {
		t.Errorf("mimetype compression method = %d, want %d (Store). A deflated mimetype "+
			"defeats the fixed-offset byte sniff the format relies on.", method, zip.Store)
	}
	if flag&0x08 != 0 {
		t.Errorf("mimetype local header sets general-purpose bit 3 (flag=0x%04x), so its CRC and "+
			"sizes are deferred to a trailing data descriptor.\nLibreOffice refuses the package: "+
			"\"source file could not be loaded\". Write this entry with CreateRaw, not "+
			"CreateHeader.", flag)
	}
	if crc == 0 || csize == 0 || usize == 0 {
		t.Errorf("mimetype local header has crc=%08x csize=%d usize=%d; all three must be present "+
			"in the header itself", crc, csize, usize)
	}
	if csize != usize {
		t.Errorf("mimetype csize=%d != usize=%d, so it is not stored verbatim", csize, usize)
	}
}

// TestOfficeRedactorClaimsEveryScannableODFType.
//
// The scanner reads all six ODF forms, and a type the scanner reports but no redactor claims is a
// reported value with nowhere to go. Derived as a list rather than spot-checked because the leak
// reappears one extension at a time — .ott/.ots/.otp were added to the SCANNER by #528 while the
// redactor still claimed none of them.
func TestOfficeRedactorClaimsEveryScannableODFType(t *testing.T) {
	claimed := make(map[string]bool)
	for _, s := range NewOfficeRedactor(nil, nil).GetSupportedTypes() {
		claimed[strings.ToLower(s)] = true
	}
	for _, ext := range []string{".odt", ".ods", ".odp", ".ott", ".ots", ".otp"} {
		if !claimed[ext] {
			t.Errorf("the office redactor does not claim %s. Every finding in such a file is "+
				"reported and then left in cleartext (#514).", ext)
		}
		if !claimed[strings.TrimPrefix(ext, ".")] {
			t.Errorf("the office redactor claims %s but not the bare %q form; the registry is "+
				"consulted with both", ext, strings.TrimPrefix(ext, "."))
		}
	}
}

// TestODFDocumentTypeIsDetectedFromTheMimetypeEntry.
//
// Extension detection is the fast path, but a package whose name says nothing must still be
// recognised — ODF declares its type in the `mimetype` entry rather than in [Content_Types].xml,
// so the OOXML sniff cannot answer for it.
func TestODFDocumentTypeIsDetectedFromTheMimetypeEntry(t *testing.T) {
	src := buildODF(t, filepath.Join(t.TempDir(), "no-useful-extension.bin"),
		"application/vnd.oasis.opendocument.text",
		odfPart{name: "content.xml", body: odfContentXML()},
	)
	got, err := NewOfficeRedactor(nil, nil).detectDocumentType(src)
	if err != nil {
		t.Fatalf("detectDocumentType: %v", err)
	}
	if got != DocumentTypeODF {
		t.Errorf("detectDocumentType = %v, want DocumentTypeODF. ODF carries its media type in "+
			"the mimetype entry, which the [Content_Types].xml sniff cannot see.", got)
	}
}

// TestODFPartsSelectedAreTheOnesThatHoldValues bounds the part map.
//
// content.xml, meta.xml and styles.xml hold reportable values; settings.xml holds view state and
// the extractor reports nothing from it, so rewriting it would be risk without recall.
func TestODFPartsSelectedAreTheOnesThatHoldValues(t *testing.T) {
	or := NewOfficeRedactor(nil, nil)
	for _, name := range []string{"content.xml", "meta.xml", "styles.xml"} {
		if !or.isTextContainingFile(name, DocumentTypeODF) {
			t.Errorf("%s is not selected for ODF, so a value reported from it can never be "+
				"removed — and parentPartResidue then refuses the write, making the file "+
				"permanently un-redactable", name)
		}
	}
	for _, name := range []string{"settings.xml", "META-INF/manifest.xml", "mimetype", "Thumbnails/thumbnail.png"} {
		if or.isTextContainingFile(name, DocumentTypeODF) {
			t.Errorf("%s is selected for ODF but holds no reported value; rewriting it is risk "+
				"without benefit", name)
		}
	}
}

// TestODFValueElementsCoverTheExtractorsVocabulary.
//
// The redactor must be able to reach every element the SCANNER reads out of meta.xml, or that
// value becomes reportable-but-unremovable. The names here are the chardata fields of odfMeta in
// meta-extractors/meta-extract-officelib/odf-extractor.go.
//
// meta:template is deliberately absent from odfValueElements and therefore from this list: its
// value lives in an xlink:href ATTRIBUTE and this walker only rewrites character data, so a
// reported template path fails the residue check and the write is refused with the value named —
// disclosed, not leaked.
func TestODFValueElementsCoverTheExtractorsVocabulary(t *testing.T) {
	or := NewOfficeRedactor(nil, nil)
	for _, local := range []string{
		"initial-creator", "creator", "title", "subject", "description",
		"language", "keyword", "generator", "printed-by", "user-defined",
	} {
		if !or.isTextElement([]string{"document-meta", "meta", local}, DocumentTypeODF) {
			t.Errorf("meta.xml element %q is read by the extractor but not rewritable by the "+
				"redactor, so a value reported from it can never be removed", local)
		}
	}
	// Body text, across all three document kinds: a spreadsheet cell and a slide text box both
	// wrap their text in text:p, which is why one entry covers all of them.
	for _, path := range [][]string{
		{"document-content", "body", "text", "p"},
		{"document-content", "body", "spreadsheet", "table", "table-row", "table-cell", "p"},
		{"document-content", "body", "presentation", "page", "frame", "text-box", "p"},
		{"document-content", "body", "text", "p", "span"},
		{"document-content", "body", "text", "h"},
	} {
		if !or.isTextElement(path, DocumentTypeODF) {
			t.Errorf("body text at %v is not rewritable", path)
		}
	}
	// And the structural elements must NOT be treated as values, or the redactor would rewrite
	// markup and corrupt the document.
	for _, local := range []string{"document-content", "body", "text", "automatic-styles", "font-face", "table-row"} {
		if or.isTextElement([]string{"document-content", local}, DocumentTypeODF) {
			t.Errorf("structural element %q is treated as a value", local)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
