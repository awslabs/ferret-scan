// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// The invariant under test: routing may change how a finding is LABELLED, but never
// whether the content is scanned.
//
// Routing decides what counts as "metadata" by reading "--- name ---" section headers
// out of the extracted text — text a document author supplies. The two paths do not
// run the same validators: the document path runs the full set, the metadata path
// runs a single field-name scanner with no SSN or card logic. So a section header in
// the wrong place used to remove findings rather than relabel them, and because only
// reported findings reach the redactor, a removed finding is a value left in
// cleartext.
//
// These tests drive core.ScanFile with real .docx bytes rather than calling the
// router or the bridge directly. That is deliberate on two counts: the defect lived
// in the seam BETWEEN those two components, so exercising either alone would miss it;
// and a hand-wired bridge would test the wiring in the test rather than the wiring
// that ships.

const (
	// A valid SSN and a Luhn-valid card, each with strong surrounding context, so
	// detection does not hinge on scoring subtleties unrelated to routing.
	ssnLine  = "Employee SSN 449-87-4100 on file."
	cardLine = "Card 4532-0151-1283-0366 expires soon."

	// The router's own section separator — typeable as a document paragraph.
	forgedHeader = "--- office_metadata ---"
)

// TestForgedSectionHeaderCannotRemoveFindings is the regression, run across every
// placement of the header. Each variant must detect the same PII as the control.
func TestForgedSectionHeaderCannotRemoveFindings(t *testing.T) {
	cases := []struct {
		name  string
		paras []string
	}{
		{
			name:  "control_no_header",
			paras: []string{"Quarterly summary follows.", ssnLine, cardLine},
		},
		{
			// The originally reported shape: header between body paragraphs.
			name:  "header_before_payload",
			paras: []string{"Quarterly summary follows.", forgedHeader, ssnLine, cardLine},
		},
		{
			// The placement that defeats a fix which only swaps the document path's
			// INPUT: with the header first there is no pre-header body, so a gate on
			// the routed DocumentBody skips the document path entirely and the
			// pre-routing text is never read.
			name:  "header_is_first_paragraph",
			paras: []string{forgedHeader, ssnLine, cardLine},
		},
		{
			// Section names are matched loosely, so a header need not name a real
			// preprocessor to be treated as a boundary.
			name:  "header_with_arbitrary_name",
			paras: []string{"--- Employee Metadata ---", ssnLine, cardLine},
		},
		{
			// Interleaved: under a positional split, no paragraph is ever "body".
			name:  "headers_interleaved",
			paras: []string{forgedHeader, ssnLine, forgedHeader, cardLine},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			types := scanDOCX(t, tc.paras)

			for _, want := range []string{"SSN", "VISA"} {
				if !types[want] {
					t.Errorf("%s was not detected.\n"+
						"  paragraphs: %q\n"+
						"  types found: %v\n"+
						"A section header in the document text changed WHETHER content is "+
						"scanned rather than how it is labelled. The value would also go "+
						"unredacted, because redaction only rewrites what is reported.",
						want, tc.paras, keys(types))
				}
			}
		})
	}
}

// TestForgedHeaderDoesNotChangeTheDetectedTypeSet states the invariant as an equality
// rather than a threshold. A "detects at least the SSN" assertion would not notice a
// header that removed some OTHER type, and the guarantee is about all of them.
func TestForgedHeaderDoesNotChangeTheDetectedTypeSet(t *testing.T) {
	control := scanDOCX(t, []string{"Quarterly summary follows.", ssnLine, cardLine})
	forged := scanDOCX(t, []string{forgedHeader, ssnLine, cardLine})

	if got, want := joined(forged), joined(control); got != want {
		t.Errorf("a forged section header changed the detected type set.\n"+
			"  without header: %s\n"+
			"  with header:    %s\n"+
			"Routing must decide labelling, not coverage.", want, got)
	}
}

// TestMetadataStillReportedUnderItsOwnType is the non-vacuity floor in the other
// direction. Scanning the union must not be achieved by abandoning the metadata path:
// AUTHOR_INFO comes only from the metadata validator, so its presence proves both
// paths still run. Without this, a "fix" that simply routed everything to the
// document path would satisfy every assertion above while silently dropping
// metadata-specific detection.
func TestMetadataStillReportedUnderItsOwnType(t *testing.T) {
	types := scanDOCX(t, []string{"Quarterly summary follows.", ssnLine, cardLine})

	if !types["AUTHOR_INFO"] {
		t.Errorf("no AUTHOR_INFO finding, so the metadata path did not run or did not "+
			"report; types found: %v.\nThe coverage guarantee must be additive — the "+
			"document path scanning everything must not replace metadata validation.",
			keys(types))
	}
}

// scanDOCX writes a minimal dual-extractor .docx and returns the set of finding types
// core.ScanFile reports for it.
func scanDOCX(t *testing.T, paras []string) map[string]bool {
	t.Helper()

	// The dual-extractor routing arm this test covers depends on BOTH preprocessors
	// claiming the fixture; see minimalDOCX below, which carries a body and core
	// properties for exactly that reason. t.TempDir() does not interfere — the path
	// denylist that once made a repo-relative fixture necessary was removed in #238.
	dir := t.TempDir()

	path := filepath.Join(dir, "report.docx")
	if err := os.WriteFile(path, minimalDOCX(paras), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	res, err := core.ScanFile(core.ScanConfig{
		FilePath:            filepath.ToSlash(path),
		Checks:              []string{"SSN", "CREDIT_CARD", "METADATA"},
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	types := map[string]bool{}
	for _, m := range res.Matches {
		types[m.Type] = true
	}
	return types
}

// minimalDOCX builds a .docx carrying both a document body and core properties, so
// two preprocessors claim it and the combined-output routing arm is exercised. A
// .docx with only word/document.xml would take a different path.
func minimalDOCX(paras []string) []byte {
	var body strings.Builder
	for _, p := range paras {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`)
	}

	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", decl +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
			`</Types>`},
		{"_rels/.rels", decl +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"docProps/core.xml", decl +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">` +
			`<dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>Ops Reviewer</cp:lastModifiedBy>` +
			`</cp:coreProperties>`},
		{"word/document.xml", decl +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			body.String() + `</w:body></w:document>`},
	}

	out := new(bytes.Buffer)
	zw := zip.NewWriter(out)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, p.body); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// joined renders a type set in a stable order for comparison in failure messages.
func joined(m map[string]bool) string {
	ks := keys(m)
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return strings.Join(ks, ",")
}
