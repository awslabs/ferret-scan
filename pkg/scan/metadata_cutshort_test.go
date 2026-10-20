// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capDocx is the #771 cap fixture: a .docx whose body is one address followed by 4,560 copies of
// a neutral 1,150-byte filler, 5,248,606 body bytes, just over CLOUD_RESOURCES's 5,242,880-byte
// cap. The author in docProps/core.xml makes it dual-extractor like a real Word file.
func capDocx(t *testing.T) string {
	t.Helper()
	const w = "http://schemas.openxmlformats.org/"
	filler := strings.Repeat("the quarterly report covers routine operational matters for the period under review ", 14)[:1150]
	var body strings.Builder
	body.WriteString(`<w:p><w:r><w:t xml:space="preserve">Contact user00001@example.com for the record.</w:t></w:r></w:p>`)
	for i := 0; i < 4560; i++ {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + filler + `</w:t></w:r></w:p>`)
	}
	parts := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="` + w + `package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="` + w + `package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + w + `officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="` + w + `package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`},
		{"word/document.xml", `<w:document xmlns:w="` + w + `wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="` + w +
			`package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Sample Author</dc:creator></cp:coreProperties>`},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		f, err := zw.Create(p[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(p[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cap.docx")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanFileKeepsFindingsWhenAMetadataCapableFileIsCutShort is #771 at the library boundary.
// Before the fix, ScanFile on this file with Checks [EMAIL CLOUD_RESOURCES] returned 0 findings
// and Incomplete=false: CLOUD_RESOURCES declining the oversize body made the dual-path bridge
// discard the EMAIL finding along with the disclosure, so an embedder saw a clean, complete scan.
// The same text as .txt returned the finding with Incomplete=true.
func TestScanFileKeepsFindingsWhenAMetadataCapableFileIsCutShort(t *testing.T) {
	path := capDocx(t)
	scan := func(checks ...string) *Result {
		t.Helper()
		res, err := ScanFile(context.Background(), path, FileOptions{Checks: checks, DisableConfigDiscovery: true})
		if err != nil {
			t.Fatalf("ScanFile(%v): %v", checks, err)
		}
		return res
	}

	control := scan("EMAIL")
	if len(control.Findings) != 1 || control.Incomplete {
		t.Fatalf("control [EMAIL]: %d findings, Incomplete=%v; want 1, false", len(control.Findings), control.Incomplete)
	}

	res := scan("EMAIL", "CLOUD_RESOURCES")
	if len(res.Findings) != 1 {
		t.Errorf("[EMAIL CLOUD_RESOURCES]: %d findings, want 1: the cap fired in CLOUD_RESOURCES, which "+
			"says nothing about the EMAIL finding", len(res.Findings))
	}
	if !res.Incomplete {
		t.Errorf("[EMAIL CLOUD_RESOURCES]: Incomplete=false, want true; a validator declined the body, "+
			"so the result is partial (IncompleteReason=%q)", res.IncompleteReason)
	}
	if len(res.NotExamined) != 1 || res.NotExamined[0].Cause != "coverage cut short" {
		t.Errorf("NotExamined = %+v, want one entry with Cause \"coverage cut short\"", res.NotExamined)
	}
}
