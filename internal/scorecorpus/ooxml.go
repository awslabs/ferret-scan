// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"archive/zip"
	"bytes"
)

// selfDOCX builds a minimal but real .docx: a ZIP carrying word/document.xml plus
// docProps/core.xml, so the file routes through the OOXML preprocessor and has BOTH
// a body and metadata.
//
// This is scorecorpus's OWN builder rather than a call into goldencorpus, so this
// package imports nothing from there. That is deliberate: a rename inside
// goldencorpus would otherwise produce a merge that is textually clean and does not
// compile, which is a failure mode this repo has already hit.
//
// Both parts matter. The PR #250 regression was specifically that a metadata match
// (a two-word author) suppressed a BODY match, because overlap resolution compared
// per-part line numbers as though they shared one coordinate space. A fixture with
// only a body, or only metadata, cannot express that bug.
func selfDOCX(body, author string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	add := func(name, content string) {
		w, err := zw.Create(name)
		if err != nil {
			return
		}
		_, _ = w.Write([]byte(content))
	}

	add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`+
		`<Default Extension="xml" ContentType="application/xml"/>`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>`+
		`</Types>`)

	add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`+
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`+
		`</Relationships>`)

	add("word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`+
		`<w:body><w:p><w:r><w:t>`+body+`</w:t></w:r></w:p></w:body></w:document>`)

	add("docProps/core.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<cp:coreProperties `+
		`xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" `+
		`xmlns:dc="http://purl.org/dc/elements/1.1/">`+
		`<dc:creator>`+author+`</dc:creator>`+
		`<cp:lastModifiedBy>`+author+`</cp:lastModifiedBy>`+
		`</cp:coreProperties>`)

	_ = zw.Close()
	return buf.Bytes()
}

// FileCase is a labelled document written to disk, so it routes through the real
// FileRouter and preprocessor chain rather than being scanned as a string.
//
// It exists because the in-memory path cannot reach container formats at all, and
// containers are where the most serious leaks have been found: a value correctly
// detected, correctly reported, and then left in cleartext inside a ZIP part.
type FileCase struct {
	Name      string
	Origin    string
	Rationale string
	// Basename's extension drives routing, so it must be the real one.
	Basename string
	// Build returns the document bytes.
	Build  func() []byte
	Checks []string
	// Leaks lists values that must NOT survive anywhere in the redacted artifact.
	//
	// Unlike Label this carries no line number: a container has no single
	// coordinate space (the same .docx reports metadata and body findings both at
	// "line 1"), so a line-keyed assertion would be measuring a synthetic number.
	// Absence of the bytes is the honest question for a container.
	Leaks []string
}

// The container fixture's strings, named so a test can assert the geometry that
// makes the case non-vacuous.
//
// The bug being guarded is span subsumption ACROSS parts: the office redactor
// resolved overlaps using (line number, text) and both a body match and a metadata
// match report line 1. It only manifests when the metadata span numerically
// contains the body span, so the author has to be long enough, and positioned
// within its own rendered line ("Creator: <author>") such that its offsets enclose
// the SSN's offsets within "Employee SSN: <ssn>".
const (
	containerSSN       = "449-87-4100"
	containerBodyLine  = "Employee SSN: 449-87-4100"
	containerAuthor    = "Jane Quincy Analyst-Smith"
	containerAuthorPfx = "Creator: "
)

// SSNContainerCases are the labelled container documents.
var SSNContainerCases = []FileCase{
	{
		Name:     "docx_metadata_and_body_ssn",
		Origin:   "built in-process by selfDOCX (session 2026-08)",
		Basename: "docx_metadata_and_body_ssn.docx",
		Rationale: "A .docx whose BODY holds an SSN and whose author metadata holds a long " +
			"name. PR #250 fixed exactly this shape: overlap resolution compared line " +
			"numbers across different source texts, so a metadata match on 'line 1' " +
			"subsumed a body match on 'line 1' and the SSN stayed in cleartext inside " +
			"word/document.xml. Detection was never wrong, so no precision or recall " +
			"number moves when this breaks -- only the redacted artifact does.\n" +
			"\n" +
			"The author string is long ON PURPOSE. Subsumption only triggers when the " +
			"metadata span numerically CONTAINS the body span, so the author must be " +
			"positioned to span the SSN's offsets within its own line. A short author " +
			"(e.g. 'Jane Smith') makes this case pass whatever the redactor does -- " +
			"measured: it did not reproduce the leak. TestContainerCaseWouldCatchTheLeak " +
			"pins the containment arithmetic so the case cannot silently go vacuous.",
		Build: func() []byte {
			return selfDOCX(containerBodyLine, containerAuthor)
		},
		Checks: []string{"SSN", "PERSON_NAME", "METADATA"},
		Leaks:  []string{"449-87-4100"},
	},
}
