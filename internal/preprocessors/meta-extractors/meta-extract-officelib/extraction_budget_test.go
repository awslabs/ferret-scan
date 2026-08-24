// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// The AGGREGATE bytes one container may materialise must be bounded, not just the per-part size.
//
// MaxEmbeddedMediaSize bounds a single part; nothing bounded the sum. Measured at main @ 0610b7e on a
// 1.43MB .docx holding 30 parts that each declare 49MB — just under the per-part cap:
//
//	peak temp disk   1.44 GB      (7x embedded.BudgetBytes)
//	peak RSS         0.27 GB      so this is DISK exhaustion, not memory
//	warnings         none, and the scan reported success
//
// After: peak temp 0.23 GB, and the truncation is disclosed as a coverage loss.
//
// embedded.BudgetBytes existed as a declared constant that no production code consulted — only
// comments and a test asserting it was positive. This is the check it was written for.
//
// Asserted on the extractor rather than end to end, because the property is "the sum of what this
// function writes is bounded" and that is exactly what it returns.
func TestAggregateExtractionBudgetIsEnforced(t *testing.T) {
	// Parts sized so that the third one crosses embedded.BudgetBytes. Deliberately each UNDER
	// MaxEmbeddedMediaSize, because a per-part cap is what already existed and what the aggregate
	// budget has to catch beyond.
	const per = 40 * 1024 * 1024
	parts := int(embedded.BudgetBytes/per) + 2

	path := buildDocxWithParts(t, parts, per)

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}

	// Non-vacuity first: some parts must have been extracted, or a function that refused
	// everything would satisfy the bound trivially.
	if len(media) == 0 {
		t.Fatal("no parts were extracted at all, so the bound below proves nothing")
	}
	if len(media) >= parts {
		t.Errorf("extracted %d of %d parts — the aggregate budget did not bite, so a container can "+
			"still materialise parts x per-part-cap bytes of temp", len(media), parts)
	}

	// Everything it did extract must fit the budget.
	var total int64
	for _, m := range media {
		info, statErr := os.Stat(m.TempFilePath)
		if statErr != nil {
			continue
		}
		total += info.Size()
	}
	// One part's overshoot is allowed by construction: the budget is charged AFTER the copy with
	// the bytes actually written, because charging the DECLARED size first would let a lying
	// declaration deny the rest of the document.
	if total > embedded.BudgetBytes+per {
		t.Errorf("materialised %d bytes, over the %d-byte budget plus one part's allowance",
			total, embedded.BudgetBytes)
	}

	// And the truncation must be DISCLOSED, not silent — a partial scan reported as complete is
	// the failure this whole family is about.
	if len(notExamined) == 0 {
		t.Error("parts were dropped with no note, so a truncated scan reports as complete")
	}
	found := false
	for _, n := range notExamined {
		if bytes.Contains([]byte(n), []byte("budget")) {
			found = true
		}
	}
	if !found {
		t.Errorf("no note mentions the budget, so the operator cannot tell this from a read error: %v",
			notExamined)
	}

	for _, m := range media {
		_ = os.Remove(m.TempFilePath)
	}
}

// A document within the budget must be entirely unaffected.
//
// The risk of an aggregate bound is that it starts refusing ordinary documents, which would trade a
// disk-exhaustion fix for a coverage loss — and a coverage loss is a cleartext leak by the sink rule.
func TestOrdinaryDocumentIsUnaffectedByTheBudget(t *testing.T) {
	const parts, per = 6, 32 * 1024
	path := buildDocxWithParts(t, parts, per)

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer func() {
		for _, m := range media {
			_ = os.Remove(m.TempFilePath)
		}
	}()

	if len(media) != parts {
		t.Errorf("extracted %d of %d parts from a document well inside the budget", len(media), parts)
	}
	if len(notExamined) != 0 {
		t.Errorf("a document inside the budget produced coverage notes: %v", notExamined)
	}
}

// The budget is per container, so scanning two documents must not exhaust it for the second.
//
// A package-level counter would have passed every test above and then silently truncated the second
// document of a directory scan.
func TestBudgetIsPerContainerNotGlobal(t *testing.T) {
	const per = 40 * 1024 * 1024
	parts := int(embedded.BudgetBytes/per) + 2
	first := buildDocxWithParts(t, parts, per)
	second := buildDocxWithParts(t, 4, 32*1024)

	m1, _, err := ExtractEmbeddedMediaForProcessing(first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for _, m := range m1 {
		_ = os.Remove(m.TempFilePath)
	}

	m2, notExamined, err := ExtractEmbeddedMediaForProcessing(second)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	defer func() {
		for _, m := range m2 {
			_ = os.Remove(m.TempFilePath)
		}
	}()

	if len(m2) != 4 {
		t.Errorf("the second document extracted %d of 4 parts — the budget is leaking across "+
			"containers, so a directory scan would truncate everything after the first big file",
			len(m2))
	}
	if len(notExamined) != 0 {
		t.Errorf("the second document produced coverage notes: %v", notExamined)
	}
}

// buildDocxWithParts writes a minimal but structurally valid .docx with the requested embedded parts.
//
// The parts are highly compressible so the fixture stays small on disk while declaring a large
// uncompressed size — the shape that makes this a bomb rather than a big file. Written with
// writestr, NOT a streaming writer: a streamed entry leaves UncompressedSize64 unset, the copy reads
// nothing, and the test passes while measuring an empty extraction. That happened while developing
// this, and the first measurement was vacuous because of it.
func buildDocxWithParts(t *testing.T, parts, per int) string {
	t.Helper()

	const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`
	const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Patient SSN 449-87-4100</w:t></w:r></w:p></w:body></w:document>`

	path := filepath.Join(t.TempDir(), "parts.docx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("close: %v", cerr)
		}
	}()

	z := zip.NewWriter(f)
	for name, body := range map[string]string{
		"[Content_Types].xml": ct,
		"_rels/.rels":         rels,
		"word/document.xml":   doc,
	} {
		w, werr := z.Create(name)
		if werr != nil {
			t.Fatalf("create %s: %v", name, werr)
		}
		if _, werr = w.Write([]byte(body)); werr != nil {
			t.Fatalf("write %s: %v", name, werr)
		}
	}

	// A PNG signature so the part is admitted, then compressible padding.
	payload := make([]byte, per)
	copy(payload, []byte("\x89PNG\r\n\x1a\n"))
	for i := 0; i < parts; i++ {
		w, werr := z.Create(filepath.ToSlash(filepath.Join("word", "media", "image"+itoa(i)+".png")))
		if werr != nil {
			t.Fatalf("create part %d: %v", i, werr)
		}
		if _, werr = w.Write(payload); werr != nil {
			t.Fatalf("write part %d: %v", i, werr)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}
