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

// writeDocx builds a .docx whose body is the supplied lines, and returns its path.
func writeDocx(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`</Relationships>`

	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, l := range lines {
		body.WriteString("<w:p><w:r><w:t>" + l + "</w:t></w:r></w:p>")
	}
	body.WriteString(`</w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range []struct{ n, c string }{
		{"[Content_Types].xml", ct}, {"_rels/.rels", rels}, {"word/document.xml", body.String()},
	} {
		w, err := zw.Create(p.n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(p.c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// inflateAll returns every decompressed member of a .docx.
//
// Grepping the .docx bytes searches COMPRESSED data and finds nothing whether or not
// redaction worked, so residue must always be checked on inflated members.
func inflateAll(t *testing.T, path string) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	out := make(map[string][]byte, len(zr.File))
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out[f.Name] = b
	}
	return out
}

// Overlapping values must not leave part of the wider value in cleartext.
//
// Replacements are applied in ONE batched pass per part instead of one bytes.ReplaceAll
// per value. strings.Replacer compares the old strings in argument order at each
// position and never overlaps a replacement, so argument order decides which of two
// overlapping values wins. Offering them longest-first makes the wider span win,
// mirroring how redactors.ResolveOverlaps keeps the widest span — the same principle
// that stops a CREDIT_CARD's BIN being left exposed when a PHONE match inside it is
// applied first.
//
// Two conditions have to hold at once for the ordering to be observable, and it took
// three attempts to construct them. Recording them so the fixture is not "simplified"
// back into a vacuous one:
//
//  1. The values must be on DIFFERENT lines. redactors.ResolveOverlaps runs first and
//     drops a match contained in a wider one ON THE SAME LINE, so a same-line pair
//     never reaches the replacer at all.
//  2. The narrow value must be a PREFIX of the wide one. strings.Replacer is
//     positional: it tries the patterns in argument order at each offset, so argument
//     order only decides an outcome when two patterns match at the SAME offset. A
//     narrow value merely nested somewhere inside a wider one is never consulted there,
//     because the replacer has already consumed those bytes.
//
// With shortest-first, the narrow prefix wins at that shared offset, is replaced, and
// the remainder of the wide value survives in cleartext — while a Contains check for
// the wide value itself PASSES, because its prefix is gone. Only the fragment
// assertions below catch it.
func TestBatchedReplacementPrefersTheWidestValue(t *testing.T) {
	dir := t.TempDir()
	const (
		wide   = "449874100-XY" // narrow is a PREFIX of this
		narrow = "449874100"
	)
	line1 := "Account " + wide + " end"
	line2 := "SSN " + narrow + " alone"
	src := writeDocx(t, dir, "overlap.docx", line1, line2)

	matches := []detector.Match{
		{Text: wide, Type: "ACCOUNT", Confidence: 90, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line1}},
		{Text: narrow, Type: "SSN", Confidence: 100, LineNumber: 2,
			Context: detector.ContextInfo{FullLine: line2}},
	}

	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	for name, content := range inflateAll(t, out) {
		for _, secret := range []string{wide, narrow} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("%s still contains %q", name, secret)
			}
		}
		// The tell for a shortest-first ordering: the narrow value is replaced inside
		// the wide one first, so the wide value's WRAPPER survives — a reported value
		// left partially in cleartext.
		for _, fragment := range []string{"-XY"} {
			if bytes.Contains(content, []byte(fragment)) {
				t.Errorf("%s still contains %q, part of the reported value %q — a shorter "+
					"overlapping value was applied first and consumed bytes the wider value "+
					"needed, stranding the rest of it in cleartext", name, fragment, wide)
			}
		}
	}
}

// A value contained entirely within a wider one must also leave nothing behind.
func TestBatchedReplacementHandlesFullyContainedValue(t *testing.T) {
	dir := t.TempDir()
	const outer = "ACCT-449874100-XY"
	const inner = "449874100"
	line := "Reference " + outer + " end"
	src := writeDocx(t, dir, "contained.docx", line)

	matches := []detector.Match{
		{Text: inner, Type: "SSN", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: outer, Type: "ACCOUNT", Confidence: 90, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
	}

	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	for name, content := range inflateAll(t, out) {
		for _, secret := range []string{outer, inner} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("%s still contains %q", name, secret)
			}
		}
	}
}

// The batched pass must be deterministic: the same document and matches must produce
// byte-identical output, whatever order Go iterates the pending map in.
func TestBatchedReplacementIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	line := "SSN 449-87-4100 card 4111111111111111 phone 206-555-0143"
	src := writeDocx(t, dir, "det.docx", line, "again SSN 449-87-4100")

	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: "4111111111111111", Type: "CREDIT_CARD", Confidence: 100, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: "206-555-0143", Type: "PHONE", Confidence: 90, LineNumber: 1,
			Context: detector.ContextInfo{FullLine: line}},
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2,
			Context: detector.ContextInfo{FullLine: "again SSN 449-87-4100"}},
	}

	r := NewOfficeRedactor(nil, nil)
	var want []byte
	for run := 0; run < 12; run++ {
		out := filepath.Join(t.TempDir(), "o.docx")
		if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		got := inflateAll(t, out)["word/document.xml"]
		if want == nil {
			want = got
			continue
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("run %d produced different body bytes — the batched pass depends on map "+
				"iteration order somewhere", run)
		}
	}
}

// distinctPartCount is the hoist that made this linear in the number of parts rather
// than the number of text ELEMENTS, so its contract is pinned directly.
func TestDistinctPartCount(t *testing.T) {
	// One part named by many consecutive entries — the real shape, since textPositions
	// carries one entry per <w:t> run.
	many := make([]OfficeTextPosition, 0, 500)
	for i := 0; i < 500; i++ {
		many = append(many, OfficeTextPosition{FileName: "word/document.xml"})
	}
	if got := distinctPartCount(many); got != 1 {
		t.Errorf("distinctPartCount = %d for 500 entries naming one part, want 1", got)
	}

	mixed := []OfficeTextPosition{
		{FileName: "word/document.xml"},
		{FileName: "word/document.xml"},
		{FileName: "docProps/core.xml"},
		{FileName: "docProps/app.xml"},
		{FileName: "docProps/core.xml"}, // returns to an earlier part: must not double count
	}
	if got := distinctPartCount(mixed); got != 3 {
		t.Errorf("distinctPartCount = %d, want 3", got)
	}

	if got := distinctPartCount(nil); got != 0 {
		t.Errorf("distinctPartCount(nil) = %d, want 0", got)
	}
}

// partReplacements keeps the FIRST replacement recorded for a value.
//
// With a format-preserving or synthetic strategy, two matches carrying the same text
// can generate different replacements. The previous code applied the first and skipped
// the rest, so first-write-wins preserves that behaviour rather than silently switching
// to last-write-wins.
func TestPartReplacementsFirstWriteWins(t *testing.T) {
	p := &partReplacements{}
	p.add("value", "FIRST")
	p.add("value", "SECOND")
	p.add("other", "X")

	if len(p.order) != 2 {
		t.Fatalf("order = %v, want 2 entries", p.order)
	}
	if p.order[0] != "value" || p.order[1] != "other" {
		t.Errorf("order = %v, want first-seen order [value other]", p.order)
	}
	if p.repl["value"] != "FIRST" {
		t.Errorf("replacement = %q, want FIRST", p.repl["value"])
	}
}
