// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// writeFormFieldDocx builds a .docx whose body is n form-field runs, each
// carrying a distinct value. Distinct values matter: identical text would let a
// single replacement collapse many matches and hide per-match cost.
//
// The path is relative to the test's working directory rather than under
// t.TempDir(): the Office preprocessors reject absolute paths below /tmp, /var
// and /home, and a fixture that lands there silently exercises a different code
// path.
func writeFormFieldDocx(t *testing.T, dir string, n int) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}

	var body strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&body,
			`<w:p><w:r><w:instrText> FORMTEXT record%d value %06d </w:instrText></w:r></w:p>`, i, i)
	}
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() + `</w:body></w:document>`

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
		"word/document.xml": doc,
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(parts[name])); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	path := filepath.Join(dir, fmt.Sprintf("formfields_%d.docx", n))
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestFormFieldReplacementIsOnePass_Equivalence proves the one-pass
// ReplaceAllString is byte-identical to the previous per-match
// FindAllStringSubmatch + strings.Replace loop, including the cases where they
// could plausibly diverge.
//
// The important one is the "$" cases. ReplaceAllString expands $1/${x} in the
// REPLACEMENT string, so the worry is that a captured value containing "$1"
// gets re-expanded. It does not — expansion applies to the template, not to the
// text substituted in for a capture — and these cases pin that.
func TestFormFieldReplacementIsOnePass_Equivalence(t *testing.T) {
	formFieldRe := regexp.MustCompile(`<w:fldSimple[^>]*w:instr="[^"]*"[^>]*>(.*?)</w:fldSimple>`)

	// The previous implementation, kept here as the reference oracle.
	loop := func(x string) string {
		for _, m := range formFieldRe.FindAllStringSubmatch(x, -1) {
			if len(m) > 1 {
				x = strings.Replace(x, m[0], "[FORM:"+m[1]+"]", 1)
			}
		}
		return x
	}
	onepass := func(x string) string {
		return formFieldRe.ReplaceAllString(x, "[FORM:$1]")
	}

	cases := []struct{ name, in string }{
		{"single", `<w:fldSimple w:instr="A">one</w:fldSimple>`},
		{"two distinct", `<w:fldSimple w:instr="A">one</w:fldSimple><w:fldSimple w:instr="B">two</w:fldSimple>`},
		// Byte-identical duplicates: strings.Replace(...,1) rewrites the first
		// occurrence each iteration, ReplaceAllString rewrites both at once. The
		// results must still agree.
		{"identical duplicates", `<w:fldSimple w:instr="A">dup</w:fldSimple><w:fldSimple w:instr="A">dup</w:fldSimple>`},
		{"value with $1", `<w:fldSimple w:instr="A">cost $1 each</w:fldSimple>`},
		{"value with $0 and braces", `<w:fldSimple w:instr="A">$0 $1 ${x}</w:fldSimple>`},
		{"empty value", `<w:fldSimple w:instr="A"></w:fldSimple>`},
		{"no fields", `plain text with no fields`},
		{"adjacent no separator", `<w:fldSimple w:instr="A">a</w:fldSimple><w:fldSimple w:instr="A">b</w:fldSimple>`},
	}
	for _, c := range cases {
		got, want := onepass(c.in), loop(c.in)
		if got != want {
			t.Errorf("%s: one-pass output differs from the per-match loop\n  loop:    %q\n  onepass: %q",
				c.name, want, got)
		}
	}
}

// TestFormFieldExtractionComplexity is the guard that was missing. The
// complexity guard in internal/goldencorpus covers validators, and a redaction
// target was added separately, but EXTRACTION had none — which is how a
// per-match whole-document rescan survived here. Measured before this fix on a
// .docx of N form fields: 0.38s / 0.99s / 3.10s at 2000 / 4000 / 8000, i.e.
// ~2.6-3.1x per doubling where linear is 2x, and a 43KB file cost 3.1s.
//
// This asserts GROWTH, not an absolute time, and it asserts the extracted
// CONTENT scales too — a flat, content-blind timing check is exactly how the
// previous quadratic hid.
func TestFormFieldExtractionComplexity(t *testing.T) {
	dir := filepath.Join("testdata", "tmp-formfield-complexity")
	t.Cleanup(func() { os.RemoveAll(dir) })

	const (
		baseN = 1000
		bigN  = 4000 // 4x
	)

	basePath := writeFormFieldDocx(t, dir, baseN)
	bigPath := writeFormFieldDocx(t, dir, bigN)

	extract := func(path string) (time.Duration, int) {
		t.Helper()
		start := time.Now()
		tc, err := ExtractText(path)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("extract %s: %v", path, err)
		}
		return elapsed, strings.Count(tc.Text, "[FORM_INSTR:")
	}

	tBase, nBase := extract(basePath)
	tBig, nBig := extract(bigPath)

	// NON-VACUITY. Both assertions below are ratios, and both pass trivially if
	// extraction returns nothing or stops finding fields as input grows. Assert
	// the measurement had something to measure before trusting the timing.
	if nBase != baseN {
		t.Fatalf("base fixture extracted %d form fields, want %d — the timing ratio "+
			"below would be measuring a path that is not doing the work", nBase, baseN)
	}
	if nBig != bigN {
		t.Fatalf("4x fixture extracted %d form fields, want %d — extraction that stops "+
			"scaling with input makes a growth ratio meaningless", nBig, bigN)
	}

	// Growth: 4x input under linear scaling is ~4x time; under quadratic ~16x.
	// The pre-fix code measured ~9-10x for this 4x step. 8x leaves generous room
	// for constant factors, GC and a loaded CI runner while still failing on a
	// return to per-match rescanning. Only meaningful once the base time is
	// large enough to measure.
	if tBase > 2*time.Millisecond {
		if ratio := float64(tBig) / float64(tBase); ratio > 8.0 {
			t.Errorf("4x more form fields took %.1fx longer to extract (base=%v big=%v) — "+
				"superlinear growth means each match is being rewritten by re-scanning the "+
				"whole document again", ratio, tBase, tBig)
		}
	}
}
