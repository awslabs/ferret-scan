// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEmbeddedMediaProvenanceComesFromTheArchive is the producer-side half of the
// attribution fix, and the reason the METADATA validator's parse site could simply
// be deleted rather than replaced.
//
// The reported source of an embedded item's findings must be derived from the zip
// entry the extractor actually opened, and it must arrive at the validator as
// STRUCTURE — MetadataContent.SourceFile, from ContentSection.SourceFile — not as
// text for the validator to re-parse. Two properties are asserted:
//
//  1. a genuine embedded member produces a section attributed to that member, so
//     deleting the parser did not cost real provenance (which would be worse than
//     the bug: an embedded item's findings blamed on the container);
//  2. a forged "--- Embedded Media 1 (x) ---" paragraph in the BODY produces no
//     such section, so no document text can invent or rename one.
func TestEmbeddedMediaProvenanceComesFromTheArchive(t *testing.T) {
	// The len(pc.Sections) == 0 check below is what keeps this honest: if the archive
	// were not read, no attributed section would exist and the test would otherwise
	// pass having proven nothing.
	dir := t.TempDir()

	// The forged inner value deliberately looks exactly like the real member name.
	// If a section carrying it ever appeared, no shape check could tell it from the
	// genuine one — which is why the answer is "do not parse", not "parse more
	// carefully".
	const realMember = "word/media/audio1.wav"
	const forgedInner = "audio1.wav"

	realPath := filepath.Join(dir, "real.docx")
	if err := os.WriteFile(realPath, embeddedMediaDOCX(realMember, ""), 0o600); err != nil {
		t.Fatalf("write real fixture: %v", err)
	}
	forgedPath := filepath.Join(dir, "forged.docx")
	if err := os.WriteFile(forgedPath, embeddedMediaDOCX("",
		"--- Embedded Media 1 ("+forgedInner+") ---"), 0o600); err != nil {
		t.Fatalf("write forged fixture: %v", err)
	}

	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))
	cr := NewContentRouterWithFileRouter(fr)

	// A section is "attributed to an embedded item" iff its SourceFile is not the
	// scanned file itself. That is the structural signal the validator consumes.
	attributed := func(path string) []string {
		pc, err := fr.ProcessFile(path, nil)
		if err != nil {
			t.Fatalf("ProcessFile(%s): %v", path, err)
		}
		if len(pc.Sections) == 0 {
			t.Fatalf("%s: no declared sections at all", filepath.Base(path))
		}
		rc, err := cr.RouteContent(pc)
		if err != nil {
			t.Fatalf("RouteContent(%s): %v", path, err)
		}
		var out []string
		for _, item := range rc.Metadata {
			if item.SourceFile != path {
				out = append(out, item.SourceFile)
			}
		}
		return out
	}

	realSources := attributed(realPath)

	// Non-vacuity floor for the guard half: the genuine container MUST yield an
	// attributed section. Without this the forged assertion below would be
	// satisfied by an embedded-media path that stopped working altogether.
	if len(realSources) == 0 {
		t.Fatal("the genuine embedded .wav produced no separately-attributed metadata item; " +
			"real provenance is broken, which is worse than the forgery this test guards")
	}
	for _, got := range realSources {
		// Attribution is "container -> item", built from the archive member name.
		if !strings.HasPrefix(got, "real.docx -> ") {
			t.Errorf("genuine embedded item attributed as %q, want a \"real.docx -> <member>\" form", got)
		}
		if !strings.Contains(got, "audio1.wav") {
			t.Errorf("genuine embedded item attributed as %q, want it to name the archive member %q",
				got, realMember)
		}
	}

	// And the forgery: same shape typed as body text, no embedded part in the zip.
	if forgedSources := attributed(forgedPath); len(forgedSources) != 0 {
		t.Errorf("a forged \"--- Embedded Media\" body paragraph produced %d attributed source(s) %v; "+
			"document text must not be able to invent an embedded-item provenance",
			len(forgedSources), forgedSources)
	}
}

// embeddedMediaDOCX builds a minimal .docx. A non-empty member adds a real .wav at
// that archive path; a non-empty extraPara adds one more body paragraph (used to
// type the forged header as document content).
func embeddedMediaDOCX(member, extraPara string) []byte {
	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

	paras := []string{
		"Quarterly summary follows.",
		"Employee SSN 449-87-4100 on file.",
	}
	if extraPara != "" {
		paras = append(paras, extraPara)
	}
	body := ""
	for _, p := range paras {
		body += `<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`
	}

	// The .wav's INFO chunk carries fields on the AUDIO sensitive-field list, which
	// is what makes the embedded item's own findings distinguishable from the
	// container's.
	wav := wavWithInfo(map[string]string{
		"INAM": "Quarterly Review Recording",
		"IART": "john.doe@example.com",
		"ICMT": "contact 212-555-0142",
	})

	out := new(bytes.Buffer)
	zw := zip.NewWriter(out)
	put := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, content); err != nil {
			panic(err)
		}
	}

	ctOverrides := `<Default Extension="wav" ContentType="audio/wav"/>`
	put("[Content_Types].xml", decl+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`+
		`<Default Extension="xml" ContentType="application/xml"/>`+ctOverrides+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`+
		`</Types>`)
	put("_rels/.rels", decl+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`+
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`+
		`</Relationships>`)
	put("docProps/core.xml", decl+
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">`+
		`<dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>Ops Reviewer</cp:lastModifiedBy>`+
		`</cp:coreProperties>`)
	put("word/document.xml", decl+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`+
		body+`</w:body></w:document>`)

	if member != "" {
		w, err := zw.Create(member)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(wav); err != nil {
			panic(err)
		}
	}

	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// wavWithInfo builds a minimal PCM WAV carrying a RIFF INFO LIST chunk, whose
// fields are what the AUDIO metadata rule set reads.
//
// Duplicated from goldencorpus.BuildWAVWithInfo rather than imported: goldencorpus
// reaches pkg/redact -> internal/core -> internal/router, so importing it from a
// test in THIS package is an import cycle.
func wavWithInfo(info map[string]string) []byte {
	le := func(w io.Writer, vals ...any) {
		for _, v := range vals {
			if err := binary.Write(w, binary.LittleEndian, v); err != nil {
				panic(err)
			}
		}
	}

	fmtChunk := new(bytes.Buffer)
	le(fmtChunk, uint16(1), uint16(1), uint32(8000), uint32(8000), uint16(1), uint16(8))

	// Sorted ids so the fixture bytes are identical run to run.
	ids := make([]string, 0, len(info))
	for id := range info {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	infoBody := new(bytes.Buffer)
	infoBody.WriteString("INFO")
	for _, id := range ids {
		v := info[id]
		field := append([]byte(v), 0) // null-terminated
		if len(field)%2 == 1 {
			field = append(field, 0) // pad to an even boundary
		}
		infoBody.WriteString(id)
		le(infoBody, uint32(len(v)+1))
		infoBody.Write(field)
	}

	list := new(bytes.Buffer)
	list.WriteString("LIST")
	le(list, uint32(infoBody.Len()))
	list.Write(infoBody.Bytes())

	data := []byte{0, 0, 0, 0} // 4 bytes of silence

	body := new(bytes.Buffer)
	body.WriteString("WAVE")
	body.WriteString("fmt ")
	le(body, uint32(fmtChunk.Len()))
	body.Write(fmtChunk.Bytes())
	body.Write(list.Bytes())
	body.WriteString("data")
	le(body, uint32(len(data)))
	body.Write(data)

	out := new(bytes.Buffer)
	out.WriteString("RIFF")
	le(out, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}
