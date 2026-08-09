// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A 0-byte file is not a failure. It is a file with nothing in it.
//
// Every preprocessor legitimately declines an empty file, and the fall-through then
// reported "all preprocessors failed", which the CLI surfaced as:
//
//	NOT EXAMINED: 1 of 1 file — contents were never read, so findings may be missing
//
// and which made --fail-on-incomplete exit 3. All of that is false: the contents
// WERE read, there are none, and an empty file cannot hold sensitive data.
//
// It matters because false alarms are how the warning that matters becomes noise an
// operator filters out — and the warning it shares a channel with is the one that
// says a file full of PII went unexamined.

func TestEmptyFileIsCleanNotAFailure(t *testing.T) {
	dir := t.TempDir()

	// Several extensions, because routing is extension-driven and an empty file
	// must be clean whatever it claims to be.
	for _, name := range []string{"empty.csv", "empty.txt", "empty.docx", "empty.pdf", "empty.json"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			fr := NewFileRouter(false)
			got, err := fr.ProcessFile(p, nil)

			if err != nil {
				t.Fatalf("empty %s returned an error (%v). An empty file is not a "+
					"processing failure; reporting one produces a false 'contents were "+
					"never read' warning and makes --fail-on-incomplete exit 3.", name, err)
			}
			if got == nil {
				t.Fatalf("empty %s returned nil content with no error", name)
			}
			if got.Text != "" {
				t.Errorf("empty %s extracted %q; want empty text", name, got.Text)
			}
			if !got.Success {
				t.Errorf("empty %s reported Success=false; it succeeded, there was just "+
					"nothing in it", name)
			}
		})
	}
}

// TestNonEmptyFailureStillFails is the control.
//
// Without it, a change that made EVERY unparseable file return clean would satisfy
// the test above and look correct — while silently converting real failures into
// clean bills of health, which is the most serious defect this tool can have.
func TestNonEmptyFailureStillFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "corrupt.docx")
	// A zip signature the archive reader cannot open: non-empty, genuinely broken.
	if err := os.WriteFile(p, []byte("PK\x03\x04truncated-not-a-real-zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	fr := NewFileRouter(false)
	if _, err := fr.ProcessFile(p, nil); err == nil {
		t.Error("a corrupt non-empty .docx was reported as processed. The empty-file " +
			"exemption must be scoped to size 0 exactly, or a truncated document reads " +
			"as scanned-and-clean.")
	}
}

// A file whose BODY is empty but whose METADATA carries PII must still be scanned,
// and must not be described as unread.
//
// This is the boundary of the size-0 exemption above, and it is the case that
// matters most: a .docx with an empty <w:body> but a docProps/core.xml holding an
// author name and an SSN is a real shape (templates, generated documents, files
// whose text was deleted but whose properties were not).
//
// Measured before the reporting fix, on exactly that file:
//
//	Files: 0 scanned, 1 NOT examined | Findings: 4
//	NOT EXAMINED: 1 of 1 file — contents were never read
//
// Four findings came out of a file the report said was never read, and the scanned
// count was 0 on a run that produced findings from it. Both claims were false: the
// metadata WAS read, through a separate channel from the body.
func TestBodyEmptyFileStillYieldsMetadata(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "meta_only.docx")
	if err := os.WriteFile(p, buildBodyEmptyDocxWithMetadata(), 0o600); err != nil {
		t.Fatal(err)
	}

	// A real router: the default preprocessors must be REGISTERED, or every file
	// fails with "no preprocessor can handle file" and the test proves nothing about
	// metadata extraction.
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))

	got, err := fr.ProcessFile(p, nil)
	if err != nil {
		t.Fatalf("a body-empty .docx with metadata errored (%v). It is not empty: the "+
			"container is valid and docProps carries PII, so it must be processed.", err)
	}
	if got == nil {
		t.Fatal("nil content for a body-empty .docx with metadata")
	}

	// The size-0 exemption must NOT have claimed this file: it is not 0 bytes, and
	// the empty_file processor would discard the metadata channel entirely.
	if got.ProcessorType == "empty_file" {
		t.Errorf("a body-empty .docx was handled by the size-0 exemption "+
			"(ProcessorType=%q). That path returns empty content and would drop the "+
			"metadata, losing the author name and SSN in docProps.", got.ProcessorType)
	}
}

// buildBodyEmptyDocxWithMetadata writes a minimal valid .docx whose body holds no
// text but whose core properties carry PII.
func buildBodyEmptyDocxWithMetadata() []byte {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, err := z.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			panic(err)
		}
	}
	add("[Content_Types].xml", `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`)
	add("_rels/.rels", `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`+
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`)
	// An empty body: valid document, no extractable text.
	add("word/document.xml", `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body></w:body></w:document>`)
	add("docProps/core.xml", `<?xml version="1.0"?><cp:coreProperties `+
		`xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" `+
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Margaret Chen</dc:creator>`+
		`<cp:lastModifiedBy>SSN 449-87-4100</cp:lastModifiedBy></cp:coreProperties>`)
	if err := z.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
