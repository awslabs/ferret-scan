// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// odfMimetypeFor returns the ODF media type for an extension.
var odfMimetypeFor = map[string]string{
	".odt": "application/vnd.oasis.opendocument.text",
	".ods": "application/vnd.oasis.opendocument.spreadsheet",
	".odp": "application/vnd.oasis.opendocument.presentation",
}

// writeODFFixture builds a spec-shaped ODF package on disk and returns its path.
//
// The `mimetype` entry is written FIRST and STORED rather than deflated, which ODF 1.2 §3.3 requires
// so that a reader can identify the type from the first bytes without inflating. Nothing in this
// extractor depends on that today — it reads meta.xml by name — but a fixture that violates the spec
// is a fixture that stops being evidence the moment anything starts sniffing the container.
func writeODFFixture(t *testing.T, ext, metaXML, bodyText string) string {
	t.Helper()

	dir := t.TempDir()
	target := filepath.Join(dir, "fixture"+ext)

	f, err := os.Create(target) // #nosec G304 -- t.TempDir()
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer func() { _ = f.Close() }()

	zw := zip.NewWriter(f)

	mime, ok := odfMimetypeFor[ext]
	if !ok {
		t.Fatalf("no ODF mimetype known for %q", ext)
	}
	mw, err := zw.CreateHeader(&zip.FileHeader{Name: "mimetype", Method: zip.Store})
	if err != nil {
		t.Fatalf("mimetype header: %v", err)
	}
	if _, err := mw.Write([]byte(mime)); err != nil {
		t.Fatalf("mimetype write: %v", err)
	}

	parts := map[string]string{
		"META-INF/manifest.xml": `<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">
 <manifest:file-entry manifest:full-path="/" manifest:media-type="` + mime + `"/>
 <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
 <manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/>
</manifest:manifest>`,
		"content.xml": `<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
 <office:body><office:text><text:p>` + bodyText + `</text:p></office:text></office:body>
</office:document-content>`,
	}
	if metaXML != "" {
		parts["meta.xml"] = metaXML
	}

	// Deterministic order so a failure is reproducible.
	for _, name := range []string{"META-INF/manifest.xml", "content.xml", "meta.xml"} {
		body, present := parts[name]
		if !present {
			continue
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatalf("%s header: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("%s write: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return target
}

// odfMetaXML wraps children in the office:document-meta envelope, declaring the namespaces a real
// writer declares.
func odfMetaXML(children string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
 xmlns:xlink="http://www.w3.org/1999/xlink">
 <office:meta>` + children + `</office:meta>
</office:document-meta>`
}

// TestODFMetadataIsExtractedForEveryODFType is the recall case for #498.
//
// Before this, ExtractMetadata's format switch fell through to `unsupported file format: .odt`, the
// office metadata preprocessor returned that error, the router quietly moved on to the text
// extractor, and meta.xml was never read on ANY ODF document — at exit 0 with no disclosure.
//
// The binding assertion is a value that exists ONLY in meta.xml, never in content.xml, so it cannot
// be found by the body-text path that already worked.
func TestODFMetadataIsExtractedForEveryODFType(t *testing.T) {
	const onlyInMeta = "Marcus Whitfield"
	const bodyOnly = "Body paragraph with no personal data."

	meta := odfMetaXML(`
  <meta:initial-creator>` + onlyInMeta + `</meta:initial-creator>
  <dc:creator>Priya Raghunathan</dc:creator>
  <dc:title>Q3 compensation review</dc:title>`)

	for _, ext := range []string{".odt", ".ods", ".odp"} {
		t.Run(ext, func(t *testing.T) {
			file := writeODFFixture(t, ext, meta, bodyOnly)

			md, err := ExtractMetadata(file)
			if err != nil {
				t.Fatalf("ExtractMetadata(%s): %v — the format switch is rejecting ODF again", ext, err)
			}
			if md.Author != onlyInMeta {
				t.Errorf("Author = %q, want %q (a value present ONLY in meta.xml)", md.Author, onlyInMeta)
			}
			if md.Title != "Q3 compensation review" {
				t.Errorf("Title = %q, want the meta.xml title", md.Title)
			}
			if want := odfMimetypeFor[ext]; md.MimeType != want {
				t.Errorf("MimeType = %q, want %q", md.MimeType, want)
			}
		})
	}
}

// TestODFCreatorSemanticsAreTheInverseOfOOXML is the assertion that a copy of the OOXML arm would
// fail.
//
// OOXML: dc:creator is the original author, cp:lastModifiedBy the last editor.
// ODF 1.2 §4.3.2 inverts the first: meta:initial-creator created it, dc:creator last modified it.
//
// Both values are reported either way, so getting this backwards loses nothing — it attributes every
// ODF document to the wrong person, which for a metadata finding is the entire content of the
// finding. Two distinct names, so a swap cannot pass.
func TestODFCreatorSemanticsAreTheInverseOfOOXML(t *testing.T) {
	const created = "Marcus Whitfield"
	const lastEdited = "Priya Raghunathan"

	file := writeODFFixture(t, ".odt", odfMetaXML(`
  <meta:initial-creator>`+created+`</meta:initial-creator>
  <dc:creator>`+lastEdited+`</dc:creator>`), "body")

	md, err := ExtractMetadata(file)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Author != created || md.Creator != created {
		t.Errorf("Author/Creator = %q/%q, want %q — meta:initial-creator is the AUTHOR in ODF",
			md.Author, md.Creator, created)
	}
	if md.LastModifiedBy != lastEdited {
		t.Errorf("LastModifiedBy = %q, want %q — ODF's dc:creator is the LAST EDITOR",
			md.LastModifiedBy, lastEdited)
	}
}

// TestODFCreatorAloneStillYieldsAnAuthor covers the shape 1 of 11 real files on the host had:
// dc:creator present with no initial-creator.
//
// Without the fallback, Author would be empty while a real name sat in LastModifiedBy — reported,
// but with nothing identifying it as a person's name in the author position.
func TestODFCreatorAloneStillYieldsAnAuthor(t *testing.T) {
	const only = "Priya Raghunathan"
	file := writeODFFixture(t, ".odt", odfMetaXML(`<dc:creator>`+only+`</dc:creator>`), "body")

	md, err := ExtractMetadata(file)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Author != only {
		t.Errorf("Author = %q, want %q when dc:creator is the only identity field", md.Author, only)
	}
	if md.LastModifiedBy != only {
		t.Errorf("LastModifiedBy = %q, want it kept as well so the report still says which field it came from", md.LastModifiedBy)
	}
}

// TestODFUserDefinedCannotOverwriteARealField pins the guard on an attacker-controlled name.
//
// meta:user-defined names come from the document. Used as bare Properties keys, an entry named
// "Template" would overwrite the real template path read from meta:template — a way to hide a value
// from the report by choosing its name.
func TestODFUserDefinedCannotOverwriteARealField(t *testing.T) {
	file := writeODFFixture(t, ".odt", odfMetaXML(`
  <meta:template xlink:href="/Users/mwhitfield/Templates/payroll.ott" xlink:title="Payroll"/>
  <meta:user-defined meta:name="Template">decoy</meta:user-defined>
  <meta:user-defined meta:name="Matter">Client 8841 — Raghunathan v. Northwind</meta:user-defined>
  <meta:user-defined>unnamed value</meta:user-defined>`), "body")

	md, err := ExtractMetadata(file)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	if got := md.Properties["Template"]; got != "/Users/mwhitfield/Templates/payroll.ott" {
		t.Errorf("Properties[Template] = %q — a user-defined entry named Template overwrote the real path", got)
	}
	if md.Properties["ODFUserDefined_Template"] != "decoy" {
		t.Errorf("the decoy entry should still be REPORTED under its prefixed key, not dropped; got %q",
			md.Properties["ODFUserDefined_Template"])
	}
	if got := md.Properties["ODFUserDefined_Matter"]; !strings.Contains(got, "Raghunathan") {
		t.Errorf("ODFUserDefined_Matter = %q, want the custom property value", got)
	}
	// An unnamed entry keeps its value: the value is what the validators scan, the name is a label.
	found := false
	for k, v := range md.Properties {
		if strings.HasPrefix(k, "ODFUserDefined_") && v == "unnamed value" {
			found = true
		}
	}
	if !found {
		t.Error("an unnamed meta:user-defined value was dropped; it is still scannable content")
	}
}

// TestODFRepeatableKeywordsAllSurvive: ODF allows several meta:keyword elements, unlike OOXML's one
// comma-joined string. A scalar field would keep only the last.
func TestODFRepeatableKeywordsAllSurvive(t *testing.T) {
	file := writeODFFixture(t, ".odt", odfMetaXML(`
  <meta:keyword>payroll</meta:keyword>
  <meta:keyword>SSN 449-87-4100</meta:keyword>
  <meta:keyword>confidential</meta:keyword>`), "body")

	md, err := ExtractMetadata(file)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	for _, want := range []string{"payroll", "449-87-4100", "confidential"} {
		if !strings.Contains(md.Keywords, want) {
			t.Errorf("Keywords = %q, missing %q — repeated meta:keyword elements are being collapsed",
				md.Keywords, want)
		}
	}
}

// TestODFWithoutMetaXMLIsNotAnError: meta.xml is optional in ODF 1.2 §2.2.3.
//
// Returning an error for a package that legitimately has none would send the caller back to the
// text-only fallback for a whole class of valid documents.
func TestODFWithoutMetaXMLIsNotAnError(t *testing.T) {
	file := writeODFFixture(t, ".odt", "", "body paragraph")

	md, err := ExtractMetadata(file)
	if err != nil {
		t.Fatalf("a package with no meta.xml must not error: %v", err)
	}
	if md.MimeType != odfMimetypeFor[".odt"] {
		t.Errorf("MimeType = %q, want it set even with no meta.xml", md.MimeType)
	}
	if md.Author != "" {
		t.Errorf("Author = %q, want empty", md.Author)
	}
}

// TestODFAgainstARealLibreOfficeFile reads a file LibreOffice ships, when present.
//
// The hand-built fixtures above and this extractor could share a wrong belief about the container and
// every test would still pass. This one cannot: the bytes were written by LibreOffice, and
// `dc:creator` genuinely holds a name in it. Skipped where the file is absent so Linux CI is
// unaffected.
func TestODFAgainstARealLibreOfficeFile(t *testing.T) {
	const real = "/Applications/LibreOffice.app/Contents/Resources/template/common/internal/idxexample.odt"
	if _, err := os.Stat(real); err != nil {
		t.Skipf("real ODF fixture not present on this host: %v", err)
	}

	md, err := ExtractMetadata(real)
	if err != nil {
		t.Fatalf("ExtractMetadata on a real .odt: %v", err)
	}

	// This file carries dc:creator and no initial-creator, so the fallback must fill Author.
	if md.Author == "" {
		t.Error("Author is empty on a real .odt whose meta.xml carries dc:creator")
	}
	if md.Application == "" {
		t.Error("Application is empty; meta:generator is present in this file")
	}
	// Sanity that we read meta.xml rather than something else: the generator names LibreOffice.
	if !strings.Contains(strings.ToLower(md.Application), "libreoffice") {
		t.Errorf("Application = %q, expected the LibreOffice generator string", md.Application)
	}
}
