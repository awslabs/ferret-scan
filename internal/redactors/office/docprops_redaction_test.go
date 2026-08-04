// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Document-property values must be redacted, not merely reported.
//
// isTextContainingFile required a body-part prefix ("word/", "xl/worksheets/",
// "ppt/slides/") for every document type, so docProps/* was never selected and
// the redactor never rewrote it. The scan named an author, a company, a template
// path — and then wrote a "redacted" copy with all of them still in cleartext.
// Measured across the golden container corpus before this fix: 10 reported
// findings survived, every one in docProps/core.xml.
//
// Selecting the part is only half of it. The values live in dc:title,
// dc:creator, cp:keywords, Company, Manager, Template — none of which are w:t or
// a spreadsheet cell, so isTextElement rejected them. With the part selected but
// the elements unrecognized, the part extracts to nothing and the result is the
// same silent no-op reached a different way. Each half is separately proven
// necessary: disabling either one alone puts all 7 reported values back in the
// output.
func TestDocPropsValuesAreRedacted(t *testing.T) {
	dir := filepath.Join("testdata", "tmp-docprops")
	if err := os.MkdirAll(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	const (
		author   = "Jane Quincy Analyst"
		company  = "Project Nightjar"
		template = `\\corp-fs01\unreleased\template.dotx`
		bodySSN  = "449-87-4100"
	)

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
			`<w:p><w:r><w:t>Employee SSN: ` + bodySSN + `</w:t></w:r></w:p>` +
			`</w:body></w:document>`,
		"docProps/core.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"` +
			` xmlns:dc="http://purl.org/dc/elements/1.1/">` +
			`<dc:creator>` + author + `</dc:creator>` +
			`</cp:coreProperties>`,
		"docProps/app.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">` +
			`<Company>` + company + `</Company>` +
			`<Template>` + template + `</Template>` +
			`</Properties>`,
	}
	order := []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml", "docProps/core.xml", "docProps/app.xml"}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range order {
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
	src := filepath.Join(dir, "props.docx")
	if err := os.WriteFile(src, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Matches as the scanner reports them: metadata findings carry the extracted
	// VALUE and the line number within the metadata section, and their FullLine is
	// the "Field: value" form the metadata preprocessor emits.
	matches := []detector.Match{
		{Text: author, Type: "AUTHOR_INFO", Confidence: 80, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: "Author: " + author}},
		{Text: company, Type: "COMPANY_INFO", Confidence: 60, LineNumber: 2,
			Context: detector.ContextInfo{FullLine: "Company: " + company}},
		{Text: template, Type: "TEMPLATE_INFO", Confidence: 85, LineNumber: 3,
			Context: detector.ContextInfo{FullLine: "Template: " + template}},
		{Text: bodySSN, Type: "SSN", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: "Employee SSN: " + bodySSN}},
	}

	out := filepath.Join(dir, "out", "props.docx")
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
		t.Fatalf("output is not a valid zip — redaction must not corrupt the package: %v", err)
	}

	// Parts are deflated, so scan the DECOMPRESSED entries. Grepping the .docx
	// bytes finds nothing whether or not redaction worked, which is how an
	// earlier version of this defect survived an md5 check that said "differs".
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		for _, secret := range []string{author, company, template, bodySSN} {
			if bytes.Contains(body, []byte(secret)) {
				t.Errorf("entry %s still contains a reported value (%d bytes) — the scan named "+
					"it, so redaction was asked to remove it and did not", f.Name, len(secret))
			}
		}
	}

	// The package must keep all five parts: a fix that dropped docProps to make
	// the leak assertion pass would be worse than the leak.
	if len(names) != len(order) {
		t.Errorf("output has %d parts %v, want %d — redaction must rewrite parts, not remove them",
			len(names), names, len(order))
	}
}

// The part selector must accept document properties for every Office format,
// since the part name is identical in all three, and must keep rejecting
// non-XML and unrelated parts.
func TestIsDocPropsPartSelection(t *testing.T) {
	or := NewOfficeRedactor(nil, nil)
	cases := []struct {
		name    string
		docType OfficeDocumentType
		want    bool
	}{
		{"docProps/core.xml", DocumentTypeDOCX, true},
		{"docProps/app.xml", DocumentTypeDOCX, true},
		{"docProps/custom.xml", DocumentTypeDOCX, true},
		{"docProps/core.xml", DocumentTypeXLSX, true},
		{"docProps/core.xml", DocumentTypePPTX, true},
		// Body parts keep working.
		{"word/document.xml", DocumentTypeDOCX, true},
		{"xl/worksheets/sheet1.xml", DocumentTypeXLSX, true},
		// Non-XML and unrelated parts stay out.
		{"docProps/thumbnail.jpeg", DocumentTypeDOCX, false},
		{"word/media/image1.png", DocumentTypeDOCX, false},
		{"_rels/.rels", DocumentTypeDOCX, false},
	}
	for _, c := range cases {
		if got := or.isTextContainingFile(c.name, c.docType); got != c.want {
			t.Errorf("isTextContainingFile(%q, %v) = %v, want %v", c.name, c.docType, got, c.want)
		}
	}
}

// Structural and numeric properties must NOT be treated as values. Rewriting
// Pages or AppVersion would corrupt the document for no privacy benefit.
func TestDocPropsValueElementsExcludeStructural(t *testing.T) {
	for _, v := range []string{"title", "creator", "keywords", "Company", "Manager", "Template", "lpwstr"} {
		if !isDocPropsValueElement(v) {
			t.Errorf("%q should be treated as a document-property VALUE", v)
		}
	}
	for _, s := range []string{"Pages", "Words", "Characters", "AppVersion", "TotalTime", "DocSecurity", "created", "modified"} {
		if isDocPropsValueElement(s) {
			t.Errorf("%q is structural/numeric and must not be rewritten", s)
		}
	}
}
