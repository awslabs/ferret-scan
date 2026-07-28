// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Regression tests for issue #179: scanning the same container file twice
// produced different line numbers, and sometimes different finding types and
// counts, on the same binary.
//
// Three constructs contributed, all of them order-of-iteration bugs:
//
//  1. processFileInternal consumed preprocessor results in goroutine COMPLETION
//     order, so for a .docx (where both "Text Extractor" and "office_metadata"
//     are capable) the metadata block landed above or below the document body at
//     random — shifting every content finding by the height of that block.
//  2. formatOfficeMetadata ranged meta.CustomProps directly.
//  3. MetadataFormatter.FormatPropertiesMap ranged its properties map directly.
//
// The golden corpus cannot catch any of these: CanonicalSort imposes a total
// order on matches before snapshotting, and the corpus has no container-format
// case at all. So these tests assert reproducibility directly, on the extracted
// text, which is the artifact line numbers are derived from.

// newProductionRouter wires the router exactly as core.ScanFile does, so the
// registry creation order these tests depend on is the real one.
func newProductionRouter() *FileRouter {
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))
	return fr
}

// buildDOCX synthesizes a minimal but valid .docx: the OPC parts a reader needs
// (content types, the main document body) plus core/app/custom properties, so
// both the text extractor and the Office metadata extractor have real work to
// do. Custom properties are deliberately numerous and NOT in sorted order in the
// archive, so a map-order regression shows up as reordered output.
func buildDOCX(t *testing.T, body string, custom map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}

	add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="xml" ContentType="application/xml"/>`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`</Types>`)

	var paras strings.Builder
	for _, line := range strings.Split(body, "\n") {
		fmt.Fprintf(&paras, `<w:p><w:r><w:t>%s</w:t></w:r></w:p>`, line)
	}
	add("word/document.xml", `<?xml version="1.0" encoding="UTF-8"?>`+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`+
		`<w:body>`+paras.String()+`</w:body></w:document>`)

	add("docProps/core.xml", `<?xml version="1.0" encoding="UTF-8"?>`+
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" `+
		`xmlns:dc="http://purl.org/dc/elements/1.1/">`+
		`<dc:creator>Dana Reviewer</dc:creator>`+
		`<cp:lastModifiedBy>Sam Approver</cp:lastModifiedBy>`+
		`<dc:title>Quarterly Records</dc:title>`+
		`</cp:coreProperties>`)

	add("docProps/app.xml", `<?xml version="1.0" encoding="UTF-8"?>`+
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">`+
		`<Application>Microsoft Office Word</Application>`+
		`<Company>Example Holdings</Company>`+
		`<Template>Normal.dotm</Template>`+
		`<Pages>3</Pages><Words>120</Words><Characters>800</Characters>`+
		`</Properties>`)

	if len(custom) > 0 {
		var props strings.Builder
		props.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` +
			`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" ` +
			`xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">`)
		pid := 2
		for name, value := range custom { // archive order is intentionally arbitrary
			fmt.Fprintf(&props, `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="%d" name="%s"><vt:lpwstr>%s</vt:lpwstr></property>`, pid, name, value)
			pid++
		}
		props.WriteString(`</Properties>`)
		add("docProps/custom.xml", props.String())
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// docxFixture writes a synthesized .docx carrying PII in both the body and the
// document properties, with many custom properties (the Purview/SharePoint shape
// that made this bug so visible in practice).
func docxFixture(t *testing.T) string {
	t.Helper()

	body := strings.Join([]string{
		"Customer record for review.",
		"Contact: casey.morgan@example.com",
		"Phone: (555) 012-3456",
		"Account owner: Riley Chen",
		"Notes: follow up before renewal.",
	}, "\n")

	custom := map[string]string{
		"MSIP_Label_ContentBits":   "0",
		"MSIP_Label_Enabled":       "true",
		"MSIP_Label_SetBy":         "dana.reviewer@example.com",
		"MSIP_Label_SiteId":        "11111111-2222-3333-4444-555555555555",
		"MSIP_Label_ActionId":      "66666666-7777-8888-9999-000000000000",
		"ContentTypeId":            "0x010100A1B2C3",
		"ReviewOwner":              "Sam Approver",
		"CostCenter":               "CC-4417",
		"RetentionPolicy":          "7-years",
		"ClassificationReviewedBy": "morgan.blake@example.com",
	}

	// NOT t.TempDir(). The Office metadata extractor runs every path through
	// validateFilePath, which rejects absolute paths under /var/, /tmp/ and
	// /home/ (office-extractor.go). TMPDIR resolves under /var/folders on macOS
	// and /tmp on Linux, and on Linux CI the checkout itself sits under
	// /home/runner — so an absolute fixture path makes office_metadata fail
	// silently and only the text extractor runs, which is precisely the
	// multi-preprocessor path these tests exist to cover. A relative path
	// matches none of those prefixes on any platform.
	dir, err := os.MkdirTemp(".", "determinism-fixture-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "determinism_fixture.docx")
	if err := os.WriteFile(path, buildDOCX(t, body, custom), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestProcessFile_ContainerOutputIsReproducible is the core #179 regression: the
// same .docx processed repeatedly must yield byte-identical extracted text and
// the same ProcessorType every time. Before the fix this failed within a handful
// of iterations.
func TestProcessFile_ContainerOutputIsReproducible(t *testing.T) {
	path := docxFixture(t)

	const reps = 25
	texts := make(map[string]int)
	types := make(map[string]int)

	for i := 0; i < reps; i++ {
		// A fresh router per iteration, so registry creation order is exercised
		// too — not just the per-call assembly.
		fr := newProductionRouter()
		got, err := fr.ProcessFile(path, &ProcessingContext{FilePath: path})
		if err != nil {
			t.Fatalf("iteration %d: ProcessFile: %v", i, err)
		}
		sum := sha256.Sum256([]byte(got.Text))
		texts[hex.EncodeToString(sum[:])]++
		types[got.ProcessorType]++
	}

	if len(texts) != 1 {
		t.Errorf("extracted text is not reproducible: %d distinct results over %d runs (distribution %v)", len(texts), reps, texts)
	}
	if len(types) != 1 {
		t.Errorf("ProcessorType is not reproducible: got %v over %d runs", types, reps)
	}
}

// TestProcessFile_ContainerBodyPrecedesMetadata pins the arrangement itself, not
// just its stability. "Text Extractor" sorts before "office_metadata", so the
// document body is the leading section and the metadata block is introduced by
// its own "--- name ---" header. That matters because the leading section is the
// one the content router has to classify without a name.
func TestProcessFile_ContainerBodyPrecedesMetadata(t *testing.T) {
	path := docxFixture(t)

	fr := newProductionRouter()
	got, err := fr.ProcessFile(path, &ProcessingContext{FilePath: path})
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	if !strings.Contains(got.ProcessorType, "+") {
		t.Skipf("only one preprocessor handled the fixture (%q); arrangement not exercised", got.ProcessorType)
	}
	if want := "Text Extractor+office_metadata"; got.ProcessorType != want {
		t.Errorf("ProcessorType = %q, want %q", got.ProcessorType, want)
	}

	bodyMarker := "casey.morgan@example.com"
	metaSeparator := "\n\n--- office_metadata ---\n"
	bodyAt := strings.Index(got.Text, bodyMarker)
	metaAt := strings.Index(got.Text, metaSeparator)
	if bodyAt < 0 {
		t.Fatalf("body text missing from extraction")
	}
	if metaAt < 0 {
		t.Fatalf("office_metadata section header missing from extraction")
	}
	if bodyAt > metaAt {
		t.Errorf("document body (offset %d) must precede the metadata section (offset %d)", bodyAt, metaAt)
	}
}

// TestProcessFile_CustomPropertiesAreSorted covers the two map-range sites
// directly: every block of Custom_* lines must be emitted in sorted key order.
// This is the assertion that fails if formatOfficeMetadata or
// FormatPropertiesMap goes back to ranging a map.
//
// Blocks, plural: the Office extractor also mirrors every custom property into
// meta.Properties under the same "Custom_" prefix, so formatOfficeMetadata emits
// the set once from meta.CustomProps and FormatPropertiesMap emits it again. That
// duplication is a separate (deterministic) defect — it doubles the metadata
// findings for every Office document — and it is what makes BOTH sort sites
// load-bearing: fixing either one alone still leaves the other permuting. The
// test therefore checks each contiguous run independently rather than assuming a
// single run, and does not pin how many runs there are.
func TestProcessFile_CustomPropertiesAreSorted(t *testing.T) {
	path := docxFixture(t)

	fr := newProductionRouter()
	got, err := fr.ProcessFile(path, &ProcessingContext{FilePath: path})
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	var keys []string
	for _, line := range strings.Split(got.Text, "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && strings.HasPrefix(name, "Custom_") {
			keys = append(keys, name)
		}
	}
	if len(keys) == 0 {
		t.Fatalf("fixture yielded no Custom_ lines; the office_metadata path did not run")
	}

	// The distinct keys in sorted order are what ONE correct emission looks like.
	// The blocks are adjacent with no intervening line, so rather than trying to
	// find the seam we assert the whole sequence is an exact repetition of that
	// unit: N sorted copies back to back. A permutation from either map-range site
	// breaks this even though the multiset of keys is unchanged.
	seen := make(map[string]bool, len(keys))
	var unit []string
	for _, k := range keys {
		if !seen[k] {
			seen[k] = true
			unit = append(unit, k)
		}
	}
	sort.Strings(unit)

	if len(unit) < 2 {
		t.Fatalf("fixture yielded %d distinct Custom_ keys; ordering not exercised", len(unit))
	}
	if len(keys)%len(unit) != 0 {
		t.Fatalf("got %d Custom_ lines over %d distinct keys — not a whole number of blocks: %v", len(keys), len(unit), keys)
	}

	for block := 0; block*len(unit) < len(keys); block++ {
		chunk := keys[block*len(unit) : (block+1)*len(unit)]
		for i := range chunk {
			if chunk[i] != unit[i] {
				t.Errorf("Custom_ block %d is not in sorted key order\n got: %v\nwant: %v", block, chunk, unit)
				break
			}
		}
	}
}
