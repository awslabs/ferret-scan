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
	"runtime"
	"strings"
	"testing"
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

	// Instrument: bytes ALLOCATED, not wall clock.
	//
	// The regression this guard exists for is a per-match strings.Replace loop, and every
	// iteration of it copies the whole document — so the defect's signature is allocation,
	// and allocation is deterministic in a way a shared CI runner's clock is not. Measured
	// over three runs each on this fixture:
	//
	//	                   base        big        ratio
	//	one-pass         3.19MB     12.36MB    3.87-3.88x
	//	per-match loop  72.89MB   1095.75MB   15.03-15.03x
	//
	// The correct population spans 0.01x. The wall-clock version of this assertion spanned
	// 2.89-4.43x, and 4.02-4.65x under GOMAXPROCS=1 — constraining the CPU alone ate half the
	// headroom against the same 8.0 threshold.
	//
	// This is the instrument change that fixed embedded_media_complexity_test.go in c16909e
	// (#361) after a 6.4x-against-6.0 failure on CORRECT code, and that guard has not flaked
	// since. It works here for the same reason: the defect copies bytes. It would NOT work for
	// a pure step-count regression — re-scanning a string the caller already owns has no
	// allocation signature at all — so this is not a general substitute for the clock.
	extract := func(path string) (uint64, int) {
		t.Helper()
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		tc, err := ExtractText(path)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatalf("extract %s: %v", path, err)
		}
		return after.TotalAlloc - before.TotalAlloc, strings.Count(tc.Text, "[FORM_INSTR:")
	}

	aBase, nBase := extract(basePath)
	aBig, nBig := extract(bigPath)

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

	// Growth: 4x input under linear scaling allocates ~4x; a per-match rescan allocates ~15x.
	//
	// 8.0 sits between the two measured populations with a ~2x margin on each side —
	// 8.0/3.88 = 2.06x below, 15.03/8.0 = 1.88x above — and is the same number the wall-clock
	// version used, so the threshold's meaning is unchanged even though its instrument is not.
	//
	// No "is the base large enough to measure" guard is needed any more. That existed because a
	// sub-millisecond base made the clock's resolution a large fraction of the reading; a 3MB
	// base is measured exactly.
	ratio := float64(aBig) / float64(aBase)
	t.Logf("4x more form fields allocated %.2fx more (base=%.2fMB big=%.2fMB, limit %.1fx%s)",
		ratio, float64(aBase)/1e6, float64(aBig)/1e6, maxAllocGrowth, raceAllocNote())

	if ratio > maxAllocGrowth {
		t.Errorf("4x more form fields allocated %.2fx more (base=%.2fMB big=%.2fMB, limit %.1fx%s) — "+
			"superlinear allocation means each match is being rewritten by re-scanning and "+
			"re-copying the whole document again",
			ratio, float64(aBase)/1e6, float64(aBig)/1e6, maxAllocGrowth, raceAllocNote())
	}

	// Absolute floor, as a second and independent signal: a regression that somehow kept its
	// growth ratio under the limit would still be caught here. Both this and the limit above are
	// declared in the race_alloc_*_test.go pair, because the race detector's own bookkeeping is
	// a large near-constant addend to both terms — see the measurements there.
	if aBase > baseAllocCeiling {
		t.Errorf("extracting %d form fields allocated %.2fMB (> %dMB%s) — one pass over the "+
			"document should not need a multiple of its size",
			baseN, float64(aBase)/1e6, baseAllocCeiling>>20, raceAllocNote())
	}
}
