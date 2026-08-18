// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/office"
)

// The OFFICE redactor had no complexity target.
//
// complexity_guard_redaction_test.go drives only plaintext.NewPlainTextRedactor, and
// the validator guard drives validators. So the container path — the one that rewrites
// zip members — was measured by nothing, and a measured superlinearity in it went
// unnoticed.
//
// Measured on the shipped binary over documents holding N DISTINCT SSNs, end to end
// through the CLI:
//
//	n=2000  0.383s
//	n=4000  1.124s   (2.93x for 2x input)
//	n=8000  3.578s   (3.18x for 2x input)   => ~O(n^1.6)
//
// Linear would be 2.0x per doubling. The cause is applyXMLRedaction: it calls
// bytes.ReplaceAll over the WHOLE part once per distinct value, so N values means N
// full scans of the part. The arithmetic corroborates it — 8000 values over a ~484KB
// part is 3.9GB scanned, and 3.9GB/3.58s is 1.1GB/s, i.e. memory-bandwidth-bound.
//
// This is PRE-EXISTING, not a regression: a binary built before the cross-part fix
// measures O(n^1.64) against O(n^1.61) after, with the largest size 1.1% FASTER after.
// The (part, value) dedup added there collapses repeats of one value, which is a
// different case from many distinct values.
//
// This guard therefore locks in current behaviour as a RATCHET rather than asserting
// linearity it does not have: it fails on an order-of-magnitude regression, and the
// growth ratio is logged for a human. Making the office path actually linear needs
// batched replacement (one pass applying every value) and is tracked separately.

// officeComplexityCeiling bounds the largest office-redaction sample.
//
// Sized from measurement with real headroom, exactly as redactionAbsoluteCeiling is:
// the biggest fixture here costs well under a second locally, so 8s catches a 10-20x
// blowup while tolerating a loaded shared runner.
const officeComplexityCeiling = 8 * time.Second

// buildOfficeFixture writes a .docx whose body holds n DISTINCT SSN-shaped values,
// and returns the path plus the matches a scan would report for it.
//
// Distinct values on purpose. Repeating ONE value lets the per-(part,value) dedup
// collapse the work to a single replacement, which would make this guard measure
// almost nothing as n grows — the same trap complexity_generators_test.go documents
// for the validators.
func buildOfficeFixture(t *testing.T, dir string, n int) (string, []detector.Match) {
	t.Helper()

	const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
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

	matches := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		ssn := fmt.Sprintf("%03d-%02d-%04d", 400+(i/8100)%500, 10+(i/90)%90, 1000+i%9000)
		line := fmt.Sprintf("row %d SSN %s end", i, ssn)
		body.WriteString("<w:p><w:r><w:t>" + line + "</w:t></w:r></w:p>")
		matches = append(matches, detector.Match{
			Text:       ssn,
			Type:       "SSN",
			Confidence: 100,
			LineNumber: i + 1,
			Validator:  "ssn",
			Context:    detector.ContextInfo{FullLine: line},
		})
	}
	body.WriteString(`</w:body></w:document>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, part := range []struct{ name, content string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", body.String()},
	} {
		w, err := zw.Create(part.name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", part.name, err)
		}
		if _, err := w.Write([]byte(part.content)); err != nil {
			t.Fatalf("write zip entry %s: %v", part.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	path := filepath.Join(dir, fmt.Sprintf("dense_%d.docx", n))
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path, matches
}

// timeOfficeRedact redacts the fixture and returns the elapsed time plus the number
// of values PROVEN absent from every inflated member.
//
// The residue check is the non-vacuity signal, and it has to inflate the zip: grepping
// the .docx bytes searches COMPRESSED data and finds nothing whether or not redaction
// worked, so a redactor that silently stopped redacting would look both fast and
// clean.
func timeOfficeRedact(t *testing.T, src string, matches []detector.Match) (time.Duration, int) {
	t.Helper()

	out := filepath.Join(t.TempDir(), "out.docx")
	r := office.NewOfficeRedactor(nil, nil)

	start := time.Now()
	res, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if res == nil {
		t.Fatal("RedactDocument returned no result")
	}

	raw, err := os.ReadFile(out) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("read redacted output: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}

	var members [][]byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open entry %s: %v", f.Name, err)
		}
		b := new(bytes.Buffer)
		if _, err := b.ReadFrom(rc); err != nil {
			rc.Close()
			t.Fatalf("read entry %s: %v", f.Name, err)
		}
		rc.Close()
		members = append(members, b.Bytes())
	}

	// Correctness floor on every timing sample: a redaction that leaves the value in
	// place is not a faster redaction, it is a leak. This is what stops an
	// "optimisation" that skips matches from passing the ceiling below.
	redacted := 0
	for i := range matches {
		leaked := false
		for _, m := range members {
			if bytes.Contains(m, []byte(matches[i].Text)) {
				leaked = true
				break
			}
		}
		if leaked {
			t.Fatalf("redacted output still contains match %d of %d (%s) — a timing target "+
				"must never accept a redaction that leaks", i, len(matches), matches[i].Type)
		}
		redacted++
	}
	return elapsed, redacted
}

// TestOfficeRedactionComplexity is the ratchet described above.
func TestOfficeRedactionComplexity(t *testing.T) {
	if testing.Short() {
		t.Skip("office redaction complexity guard skipped in -short mode")
	}

	dir := t.TempDir()
	const baseN, bigN = 500, 2000 // 4x input

	baseSrc, baseMatches := buildOfficeFixture(t, dir, baseN)
	bigSrc, bigMatches := buildOfficeFixture(t, dir, bigN)

	tBase, nBase := timeOfficeRedact(t, baseSrc, baseMatches)
	tBig, nBig := timeOfficeRedact(t, bigSrc, bigMatches)

	// Non-vacuity floor: the work must actually GROW with the input. A redactor that
	// stops redacting as input grows makes any timing number meaningless.
	if nBase < baseN || nBig < bigN {
		t.Fatalf("redacted %d/%d and %d/%d values — the guard is vacuous unless every "+
			"reported value is removed at both sizes", nBase, baseN, nBig, bigN)
	}
	if nBig <= nBase {
		t.Fatalf("work did not grow: %d values at n=%d vs %d at n=%d", nBig, bigN, nBase, baseN)
	}

	// Ratio is LOGGED, not asserted: tBase is small enough that scheduler noise
	// dominates it, exactly as in the plaintext guard. The known shape is ~O(n^1.6),
	// so a 4x input is expected around 7-9x here, NOT 4x.
	t.Logf("4x input office redaction ratio: %.1fx (base=%v big=%v) — informational. "+
		"~O(n^1.6) is the known current shape: applyXMLRedaction runs bytes.ReplaceAll "+
		"over the whole part once per DISTINCT value. Linear would be 4x.",
		float64(tBig)/float64(tBase), tBase, tBig)

	ceiling := officeComplexityCeiling
	if raceDetectorEnabled {
		ceiling *= raceCeilingMultiplier
	}
	if tBig > ceiling {
		t.Errorf("redacting %d distinct values in an Office package took %v (> %v ceiling%s) — "+
			"a regression of this size means the per-value whole-part rescan got worse, or a "+
			"new whole-document pass was added per match",
			bigN, tBig, ceiling, raceNote())
	}
}
