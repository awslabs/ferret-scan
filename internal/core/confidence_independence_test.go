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

// A finding's confidence must not depend on what else is in the file.
//
// The bridge used to add a flat +5 to EVERY finding whenever both validation paths
// reported something. So scanning the same value in two documents gave two answers.
// Measured on two .docx files with identical content and identical basenames, differing
// only by an unrelated author name in the metadata, the same API_KEY_OR_SECRET scored 55
// in one and 60 in the other. On a real 10 MB .docx all 78 findings carried the boost and
// 14 had their score genuinely shifted by it, across 9 types.
//
// That is wrong on its own terms — a confidence answers "how sure are we about THIS
// value" — and it had a second-order cost: while the suppression hash folded confidence,
// adding one unrelated finding to a file silently invalidated the saved rules of every
// other finding in it, turning a reviewed-and-accepted finding back into noise.
//
// Driven through core.ScanFile rather than the bridge directly: the defect lived in how
// the paths were combined, and a hand-wired bridge would test the test's own wiring.

const unlabelledSecret = `value "wJalrXUtnFEMI7K7MDENGbPxRfiCYzz1"`

// TestConfidenceIsIndependentOfUnrelatedFindings is the regression.
func TestConfidenceIsIndependentOfUnrelatedFindings(t *testing.T) {
	alone := secretConfidence(t, "alone", "")
	withMeta := secretConfidence(t, "withmeta", "Jane Analyst")

	if alone == 0 {
		t.Fatal("no API_KEY_OR_SECRET finding in the control fixture; the comparison " +
			"below would be vacuous")
	}
	if alone != withMeta {
		t.Errorf("the same value scored %v alone and %v when the document also carried an "+
			"unrelated metadata finding.\nConfidence must describe the finding, not the "+
			"file it happens to live in: the same secret in two documents has to score the "+
			"same. While the suppression hash folded confidence this also invalidated "+
			"saved rules for findings that had not changed at all.", alone, withMeta)
	}
}

// TestMetadataConfidenceIsIndependentOfTheBody covers the other direction — the boost
// applied to every match, so a metadata finding moved merely because the body had one.
func TestMetadataConfidenceIsIndependentOfTheBody(t *testing.T) {
	withBody := metadataConfidence(t, "mwith", unlabelledSecret)
	withoutBody := metadataConfidence(t, "mwithout", "nothing sensitive here")

	if withoutBody == 0 {
		t.Fatal("no metadata finding produced; the comparison below would be vacuous")
	}
	if withBody != withoutBody {
		t.Errorf("a metadata finding scored %v when the body also had a finding and %v when "+
			"it did not; its confidence must not depend on the body", withBody, withoutBody)
	}
}

func secretConfidence(t *testing.T, name, creator string) float64 {
	t.Helper()
	for _, m := range scanDOCXWith(t, name, creator, unlabelledSecret) {
		if m == "API_KEY_OR_SECRET" {
			return confidences[m]
		}
	}
	return 0
}

func metadataConfidence(t *testing.T, name, body string) float64 {
	t.Helper()
	for _, m := range scanDOCXWith(t, name, "Jane Analyst", body) {
		switch m {
		case "AUTHOR_INFO", "LAST_MODIFIED_BY", "COMPANY_INFO":
			return confidences[m]
		}
	}
	return 0
}

// confidences is populated by scanDOCXWith for the most recent scan.
var confidences = map[string]float64{}

func scanDOCXWith(t *testing.T, name, creator, body string) []string {
	t.Helper()

	dir, err := os.MkdirTemp(".", "conf-indep-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, name+".docx")
	if err := os.WriteFile(path, buildDOCX(creator, body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	res, err := core.ScanFile(core.ScanConfig{
		FilePath:            filepath.ToSlash(path),
		Checks:              []string{"SECRETS", "METADATA"},
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	confidences = map[string]float64{}
	var types []string
	for _, m := range res.Matches {
		confidences[m.Type] = m.Confidence
		types = append(types, m.Type)
	}
	return types
}

// buildDOCX makes a .docx with the given body, and core properties only when creator is
// non-empty — the presence of a metadata finding is the variable under test.
func buildDOCX(creator, body string) []byte {
	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
	ov := `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`
	rel := `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`
	if creator != "" {
		ov += `<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`
		rel += `<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`
	}

	parts := []struct{ name, body string }{
		{"[Content_Types].xml", decl + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` + ov + `</Types>`},
		{"_rels/.rels", decl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel + `</Relationships>`},
		{"word/document.xml", decl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			`<w:p><w:r><w:t xml:space="preserve">` + strings.ReplaceAll(body, `"`, "&quot;") + `</w:t></w:r></w:p>` +
			`</w:body></w:document>`},
	}
	if creator != "" {
		parts = append(parts, struct{ name, body string }{"docProps/core.xml",
			decl + `<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">` +
				`<dc:creator>` + creator + `</dc:creator></cp:coreProperties>`})
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
