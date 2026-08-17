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

// A value present in TWO parts must be redacted in both.
//
// redactMatch resolved a match with strings.Index(extractedText, match.Text) --
// the FIRST occurrence -- then found the single OfficeTextPosition covering that
// offset and handed that one part to applyXMLRedaction, whose bytes.ReplaceAll is
// scoped to the part it is given. So when an SSN appeared in both
// word/document.xml and docProps/core.xml, the scan emitted two SSN matches, both
// resolved to the same offset, both selected the same part, and the other part
// kept the SSN in CLEARTEXT.
//
// Measured on the shipped binary before the fix, with the value in both parts:
//
//	body part first: 3 findings (2x SSN) -> residue in docProps/core.xml, rc=0
//	core part first: 3 findings (2x SSN) -> residue in word/document.xml, rc=0
//
// Same bytes, different zip entry order, different part leaked -- because
// extractedText is concatenated in entry order, so entry order decides which
// occurrence is "first". Both exited 0 and produced a file the caller believes is
// redacted. Nothing increments FailedRedactions (it is declared in
// redactors/index.go and manager.go and never incremented in production), so the
// leak is silent by construction.
//
// Both orders are asserted on purpose: a fix that happened to favour whichever
// part came first would pass one order and leak the other.
func TestCrossPartValueIsRedactedInEveryPart(t *testing.T) {
	const (
		ssn    = "449-87-4100"
		author = "Jane Quincy Analyst"
	)

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`
	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`</Relationships>`
	// The SAME ssn value in the body AND in a document property.
	body := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>Employee SSN ` + ssn + ` on file.</w:t></w:r></w:p>` +
		`</w:body></w:document>`
	core := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"` +
		` xmlns:dc="http://purl.org/dc/elements/1.1/">` +
		`<dc:title>Record for SSN ` + ssn + `</dc:title>` +
		`<dc:creator>` + author + `</dc:creator>` +
		`</cp:coreProperties>`

	parts := map[string]string{
		"[Content_Types].xml": contentTypes,
		"_rels/.rels":         rels,
		"word/document.xml":   body,
		"docProps/core.xml":   core,
	}

	orders := map[string][]string{
		"body part first": {"[Content_Types].xml", "_rels/.rels", "word/document.xml", "docProps/core.xml"},
		"core part first": {"[Content_Types].xml", "_rels/.rels", "docProps/core.xml", "word/document.xml"},
	}

	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()

			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			for _, n := range order {
				w, err := zw.Create(n)
				if err != nil {
					t.Fatalf("create zip entry %s: %v", n, err)
				}
				if _, err := w.Write([]byte(parts[n])); err != nil {
					t.Fatalf("write zip entry %s: %v", n, err)
				}
			}
			if err := zw.Close(); err != nil {
				t.Fatalf("close zip: %v", err)
			}
			src := filepath.Join(dir, "crosspart.docx")
			if err := os.WriteFile(src, buf.Bytes(), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			// As the scanner reports it: one SSN match per part, plus the author.
			matches := []detector.Match{
				{Text: ssn, Type: "SSN", Confidence: 100, LineNumber: 1,
					Context: detector.ContextInfo{FullLine: "Employee SSN " + ssn + " on file."}},
				{Text: ssn, Type: "SSN", Confidence: 100, LineNumber: 2,
					Context: detector.ContextInfo{FullLine: "Title: Record for SSN " + ssn}},
				{Text: author, Type: "AUTHOR_INFO", Confidence: 80, LineNumber: 3,
					Context: detector.ContextInfo{FullLine: "Author: " + author}},
			}

			out := filepath.Join(dir, "out.docx")
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

			// Inflate every member. Grepping the .docx bytes searches COMPRESSED
			// data and finds nothing whether or not redaction worked, which makes a
			// leak indistinguishable from a clean file.
			var names []string
			for _, f := range zr.File {
				names = append(names, f.Name)
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("open entry %s: %v", f.Name, err)
				}
				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Fatalf("read entry %s: %v", f.Name, err)
				}
				if bytes.Contains(content, []byte(ssn)) {
					t.Errorf("entry %s still contains the SSN in cleartext — it was reported "+
						"twice, so redaction was asked to remove it from both parts and only "+
						"rewrote the one holding its first occurrence", f.Name)
				}
				if bytes.Contains(content, []byte(author)) {
					t.Errorf("entry %s still contains the reported author in cleartext", f.Name)
				}
			}

			// A fix that dropped a part to make the residue assertion pass would be
			// worse than the leak.
			if len(names) != len(order) {
				t.Errorf("output has %d parts %v, want %d — redaction must rewrite parts, not remove them",
					len(names), names, len(order))
			}
		})
	}
}

// Several DISTINCT values in one part must all be redacted.
//
// The cross-part fix skips a (part, value) pair already rewritten, because
// bytes.ReplaceAll removed every occurrence the first time and repeating it is a
// wasted full-part scan. Keying that skip on the part ALONE would redact the first
// value and silently drop every other value in the same part — a far worse leak
// than the one being fixed. This is the test that distinguishes the two keyings.
func TestMultipleDistinctValuesInOnePartAreAllRedacted(t *testing.T) {
	const (
		ssn   = "449-87-4100"
		card  = "4111111111111111"
		phone = "206-555-0143"
	)
	dir := t.TempDir()

	body := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>SSN ` + ssn + ` card ` + card + ` phone ` + phone + `</w:t></w:r></w:p>` +
		// the SSN a second time, to exercise the repeat-skip alongside the distinct values
		`<w:p><w:r><w:t>again SSN ` + ssn + `</w:t></w:r></w:p>` +
		`</w:body></w:document>`
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
		"word/document.xml": body,
	}
	order := []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml"}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range order {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", n, err)
		}
		if _, err := w.Write([]byte(parts[n])); err != nil {
			t.Fatalf("write zip entry %s: %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	src := filepath.Join(dir, "multi.docx")
	if err := os.WriteFile(src, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	line := "SSN " + ssn + " card " + card + " phone " + phone
	matches := []detector.Match{
		{Text: ssn, Type: "SSN", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: card, Type: "CREDIT_CARD", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: phone, Type: "PHONE", Confidence: 90, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: ssn, Type: "SSN", Confidence: 100, LineNumber: 2,
			Context: detector.ContextInfo{FullLine: "again SSN " + ssn}},
	}

	out := filepath.Join(dir, "out.docx")
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
		t.Fatalf("output is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		for label, secret := range map[string]string{"SSN": ssn, "card": card, "phone": phone} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("entry %s still contains the reported %s in cleartext — every reported "+
					"value in a part must be redacted, not just the first", f.Name, label)
			}
		}
	}
}

// positionForOffset binary searches, so its boundaries are pinned directly: an
// off-by-one here would attribute a match to the wrong part and redact the wrong
// file, which is the same class of defect as the leak this fixes.
func TestPositionForOffset(t *testing.T) {
	positions := []OfficeTextPosition{
		{FileName: "a.xml", DocumentOffset: 0, Text: "abc"},  // covers 0,1,2
		{FileName: "b.xml", DocumentOffset: 3, Text: "de"},   // covers 3,4
		{FileName: "c.xml", DocumentOffset: 5, Text: "fghi"}, // covers 5..8
	}
	cases := []struct {
		off  int
		want string // "" means no part
	}{
		{-1, ""},
		{0, "a.xml"}, {2, "a.xml"},
		{3, "b.xml"}, {4, "b.xml"},
		{5, "c.xml"}, {8, "c.xml"},
		{9, ""}, // one past the last part
		{100, ""},
	}
	for _, c := range cases {
		got := positionForOffset(positions, c.off)
		name := ""
		if got != nil {
			name = got.FileName
		}
		if name != c.want {
			t.Errorf("positionForOffset(off=%d) = %q, want %q", c.off, name, c.want)
		}
	}
	if positionForOffset(nil, 0) != nil {
		t.Error("positionForOffset(nil, 0) must be nil, not a panic or a bogus part")
	}

	// A gap between parts must resolve to no part rather than to the part before
	// it, or a value in an unextracted region would be redacted in the wrong file.
	gapped := []OfficeTextPosition{
		{FileName: "a.xml", DocumentOffset: 0, Text: "ab"}, // covers 0,1
		{FileName: "b.xml", DocumentOffset: 9, Text: "cd"}, // covers 9,10
	}
	if got := positionForOffset(gapped, 4); got != nil {
		t.Errorf("offset in a gap resolved to %q, want no part", got.FileName)
	}
}

// The occurrence walk must not loop forever on an empty needle and must not
// double-count self-overlapping text (the same bytes redacted twice).
func TestPartsHoldingMatchWalkEdges(t *testing.T) {
	single := []OfficeTextPosition{{FileName: "a.xml", DocumentOffset: 0, Text: "aaa"}}
	if got := partsHoldingMatch("aaa", single, ""); got != nil {
		t.Errorf("empty needle returned %+v, want nil (and must not hang)", got)
	}
	if got := partsHoldingMatch("", single, "a"); len(got) != 0 {
		t.Errorf("empty haystack returned %+v, want none", got)
	}
	if got := partsHoldingMatch("aaa", single, "aa"); len(got) != 1 {
		t.Errorf("self-overlapping needle returned %d parts, want 1", len(got))
	}
	if got := partsHoldingMatch("aaa", nil, "a"); got != nil {
		t.Errorf("no positions returned %+v, want nil", got)
	}
	// A needle longer than the haystack must not read out of range.
	if got := partsHoldingMatch("ab", single, "abcdef"); len(got) != 0 {
		t.Errorf("needle longer than haystack returned %+v, want none", got)
	}
}

// partsHoldingMatch must return the DISTINCT parts holding a value, in
// first-occurrence order, and must not report a part twice when the value occurs
// twice inside it (bytes.ReplaceAll already covers repeats within one part, so a
// duplicate entry would mean redacting the same part twice).
func TestPartsHoldingMatch(t *testing.T) {
	// Two parts concatenated: "A 7 B " (offset 0) then "C 7 7 D" (offset 6).
	const bodyText = "A 7 B "
	const propText = "C 7 7 D"
	extracted := bodyText + propText
	positions := []OfficeTextPosition{
		{FileName: "word/document.xml", DocumentOffset: 0, Text: bodyText},
		{FileName: "docProps/core.xml", DocumentOffset: len(bodyText), Text: propText},
	}

	got := partsHoldingMatch(extracted, positions, "7")
	if len(got) != 2 {
		t.Fatalf("got %d parts, want 2 (the value is in both) — %+v", len(got), got)
	}
	if got[0].FileName != "word/document.xml" || got[1].FileName != "docProps/core.xml" {
		t.Errorf("parts = [%s %s], want [word/document.xml docProps/core.xml] in first-occurrence order",
			got[0].FileName, got[1].FileName)
	}

	// A value in only one part resolves to only that part — the fix must not
	// broaden redaction to parts that do not hold the value.
	only := partsHoldingMatch(extracted, positions, "D")
	if len(only) != 1 || only[0].FileName != "docProps/core.xml" {
		t.Errorf("single-part value resolved to %+v, want just docProps/core.xml", only)
	}

	if none := partsHoldingMatch(extracted, positions, "absent"); len(none) != 0 {
		t.Errorf("absent value resolved to %+v, want none", none)
	}
}
