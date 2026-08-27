// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #528: ODF TEMPLATES were absent from officeExtensions, so `.ott`/`.ots`/`.otp` were refused as an
// unsupported type before any preprocessor was consulted and their meta.xml was never read — while
// the identical value in a `.odt` is reported.
//
// Measured on 12 real templates from this host, every one carrying identity metadata:
//
//	before   0 findings, no office_metadata section, on all 12
//	after    3-10 findings each, office_metadata on all 12
//
// The names in them are real: Alexander Wilms, Jun Nogata, Kevin Suo, Eric Lavarde,
// Peter Thielmann. A CV template carrying its author's name is exactly the document a PII
// scanner is expected to look at. 119 such templates exist on this host.

// templateOf pairs each document extension with its template counterpart.
var templateOf = map[string]string{".odt": ".ott", ".ods": ".ots", ".odp": ".otp"}

// TestATemplateReportsWhatItsDocumentFormReports is the control PAIR, and it is the assertion that
// matters.
//
// Asserting only that the `.ott` extracts something would also pass on a reader that ignored the
// extension and sniffed the container — a different fix with different consequences for the redactor
// registry. Byte-identical meta.xml under both extensions, compared field by field, is what pins
// "the template is treated as its document form".
func TestATemplateReportsWhatItsDocumentFormReports(t *testing.T) {
	const metaXML = `<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/"
 xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0">
 <office:meta>
  <meta:initial-creator>Marcus Whitfield</meta:initial-creator>
  <dc:creator>Priya Raghunathan</dc:creator>
  <dc:title>Quarterly Review</dc:title>
  <dc:subject>Compensation</dc:subject>
 </office:meta>
</office:document-meta>`

	for doc, tmpl := range templateOf {
		t.Run(doc+" vs "+tmpl, func(t *testing.T) {
			docPath := writeODFFixture(t, doc, metaXML, "Body text.")
			tmplPath := writeODFFixture(t, tmpl, metaXML, "Body text.")

			docMeta, err := ExtractMetadata(docPath)
			if err != nil {
				t.Fatalf("ExtractMetadata(%s): %v", doc, err)
			}
			tmplMeta, err := ExtractMetadata(tmplPath)
			if err != nil {
				t.Fatalf("ExtractMetadata(%s): %v — the template was refused where the document was "+
					"read, which is the whole defect", tmpl, err)
			}

			// Non-vacuity: the document form must actually have produced the values, or "they match"
			// would hold for two empty results.
			if docMeta.Author == "" || docMeta.Title == "" {
				t.Fatalf("the %s control extracted nothing (author=%q title=%q), so the comparison "+
					"below proves nothing", doc, docMeta.Author, docMeta.Title)
			}

			for _, f := range []struct{ name, got, want string }{
				{"Author", tmplMeta.Author, docMeta.Author},
				{"LastModifiedBy", tmplMeta.LastModifiedBy, docMeta.LastModifiedBy},
				{"Title", tmplMeta.Title, docMeta.Title},
				{"Subject", tmplMeta.Subject, docMeta.Subject},
			} {
				if f.got != f.want {
					t.Errorf("%s: %s = %q, want %q (what %s reports for byte-identical meta.xml)",
						tmpl, f.name, f.got, f.want, doc)
				}
			}
		})
	}
}

// TestATemplateGetsItsOwnMimeType.
//
// The media type is what distinguishes a template from a document in ODF, and it is reported. Reusing
// the document form's type would mislabel every template in the output while the values were right.
func TestATemplateGetsItsOwnMimeType(t *testing.T) {
	const metaXML = `<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
 <office:meta><dc:title>T</dc:title></office:meta>
</office:document-meta>`

	for _, tc := range []struct{ ext, want string }{
		{".ott", "application/vnd.oasis.opendocument.text-template"},
		{".ots", "application/vnd.oasis.opendocument.spreadsheet-template"},
		{".otp", "application/vnd.oasis.opendocument.presentation-template"},
	} {
		t.Run(tc.ext, func(t *testing.T) {
			meta, err := ExtractMetadata(writeODFFixture(t, tc.ext, metaXML, "Body."))
			if err != nil {
				t.Fatalf("ExtractMetadata: %v", err)
			}
			if meta.MimeType != tc.want {
				t.Errorf("MimeType = %q, want %q", meta.MimeType, tc.want)
			}
		})
	}
}

// TestATemplateWithoutMetaXMLIsNotAnError mirrors the document-form contract: ODF 1.2 §2.2.3 makes
// meta.xml optional, and returning an error would send a whole class of valid files back to the
// text-only fallback.
func TestATemplateWithoutMetaXMLIsNotAnError(t *testing.T) {
	for _, ext := range []string{".ott", ".ots", ".otp"} {
		path := writeODFFixture(t, ext, "", "Body only.")
		if _, err := ExtractMetadata(path); err != nil {
			t.Errorf("%s without meta.xml returned an error: %v", ext, err)
		}
	}
}

// TestTemplateAgainstRealFilesOnThisHost is what keeps the hand-built fixtures honest.
//
// The fixtures above and this extractor could share a wrong belief and every test would still pass —
// which is exactly what happened before #528: all the synthetic ODF tests were green while every real
// template on this host reported 0 findings, because the failure was in the EXTENSION GATE and no
// synthetic test crossed it. Skipped where absent so Linux CI is unaffected.
func TestTemplateAgainstRealFilesOnThisHost(t *testing.T) {
	roots := []string{"/Applications/LibreOffice.app/Contents/Resources/template"}
	var found []string
	for _, root := range roots {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil //nolint:nilerr // an unreadable subtree is not this test's concern
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".ott", ".ots", ".otp":
				found = append(found, p)
			}
			return nil
		})
	}
	if len(found) == 0 {
		t.Skip("no real ODF templates on this host")
	}

	var withIdentity int
	for _, p := range found {
		meta, err := ExtractMetadata(p)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(p), err)
			continue
		}
		if meta.Author != "" || meta.LastModifiedBy != "" || meta.Title != "" {
			withIdentity++
		}
	}
	if withIdentity == 0 {
		t.Errorf("read %d real templates and not one yielded an author, last-modified-by or title; "+
			"measured on this host, 12 of 12 carry at least one", len(found))
	}
	t.Logf("read %d real ODF templates, %d carrying identity metadata", len(found), withIdentity)
}
