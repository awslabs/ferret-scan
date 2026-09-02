// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #314 end to end, through the SAME wiring the CLI uses: the router with all default
// preprocessors registered, and NewDefaultRedactionManager with all default redactors.
//
// A unit test on the extractor and a unit test on the redactor both pass while a type is
// still broken -- that is exactly how #400's half-fix shipped. This file is the third
// leg: it drives the real assembly and checks both the report and the SINK.
//
// Measured on this fixture before the change:
//
//	standalone .svg    4 findings (SSN 100, BUSINESS 98, PERSON_NAME 92, PHONE 15)
//	embedded in .docx  0 findings, exit 0, 0 bytes of stderr, exit 0 again under
//	                   --fail-on-incomplete, and NO redacted copy written at all
//	64KB glyph .svg    1,313 findings, 1,143 of them PHONE (162 HIGH)
//	7.2MB one-attr     400,001 findings in 19.9s wall / 80s CPU

const svgE2EDrawing = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="600" height="200" viewBox="0 0 600 200">
  <title>Onboarding diagram for Renee Vasquez</title>
  <desc>Contact the owner at renee.vasquez@examplecorp.com before editing.</desc>
  <path d="M32.6982,23.9008 C33.0592,24.3698 32.0078 31.3992 43.5968 15.4721"/>
  <text x="10" y="40">Employee SSN: 452-11-9384</text>
  <text x="10" y="70">Desk phone: <tspan>+1 (202) 555-0143</tspan></text>
</svg>
`

// svgE2EValues must be gone from the output; svgE2EKeep must survive it.
var (
	svgE2EValues = []string{
		"452-11-9384",
		"renee.vasquez@examplecorp.com",
		"Renee Vasquez",
		"(202) 555-0143",
	}
	svgE2EKeep = []string{
		"<svg",
		`viewBox="0 0 600 200"`,
		"M32.6982,23.9008",
		"</svg>",
	}
)

// svgE2EGlyphGeometry builds the flood fixture: integer-coordinate glyph paths, the
// shape real icon and font SVGs carry. Distinct coordinates per path, so a
// deduplicating step cannot flatten it.
func svgE2EGlyphGeometry(paths int) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>` + "\n" + `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2048 2048">` + "\n")
	seed := uint32(11)
	next := func(n uint32) uint32 {
		seed = seed*1664525 + 1013904223
		return seed%n + 1
	}
	for i := 0; i < paths; i++ {
		b.WriteString(`  <path d="m`)
		for j := 0; j < 12; j++ {
			if j > 0 {
				b.WriteByte(' ')
			}
			writeUint(&b, next(1999))
		}
		b.WriteString(` c`)
		for j := 0; j < 12; j++ {
			if j > 0 {
				b.WriteByte(' ')
			}
			writeUint(&b, next(1999))
		}
		b.WriteString(` z\"/>` + "\n")
	}
	b.WriteString("</svg>\n")
	return strings.ReplaceAll(b.String(), `\"`, `"`)
}

func writeUint(b *strings.Builder, v uint32) {
	var buf [12]byte
	i := len(buf)
	if v == 0 {
		b.WriteByte('0')
		return
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	b.Write(buf[i:])
}

// svgE2EWriteDocx packages one .svg as word/media/diagram1.svg inside a minimal .docx.
func svgE2EWriteDocx(t *testing.T, path, svgBody string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="svg" ContentType="image/svg+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>See the attached architecture diagram.</w:t></w:r></w:p></w:body>
</w:document>`},
		{"word/_rels/document.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/diagram1.svg"/>
</Relationships>`},
		{"word/media/diagram1.svg", svgBody},
	}
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatalf("zip create %s: %v", p.name, err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			t.Fatalf("zip write %s: %v", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write docx: %v", err)
	}
}

func svgE2EWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func svgE2EXMLParses(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		if _, err := dec.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// TestSVGRecallAndFloodBothDirections is the pair of measurements the fix has to satisfy
// at once. Either one alone is passable by a broken change.
func TestSVGRecallAndFloodBothDirections(t *testing.T) {
	dir := t.TempDir()
	cfg := config.LoadConfigOrDefault("")

	prose := svgE2EWrite(t, dir, "diagram.svg", svgE2EDrawing)
	geometry := svgE2EWrite(t, dir, "icons.svg", svgE2EGlyphGeometry(600))

	proseDoc := filepath.Join(dir, "with_prose.docx")
	svgE2EWriteDocx(t, proseDoc, svgE2EDrawing)
	geomDoc := filepath.Join(dir, "with_geometry.docx")
	svgE2EWriteDocx(t, geomDoc, svgE2EGlyphGeometry(600))

	t.Run("recall standalone", func(t *testing.T) {
		res, err := ScanFile(ScanConfig{FilePath: prose, Config: cfg, EnablePreprocessors: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		assertTypesReported(t, res.Matches, "SSN", "BUSINESS", "PERSON_NAME")
	})

	t.Run("recall embedded", func(t *testing.T) {
		res, err := ScanFile(ScanConfig{FilePath: proseDoc, Config: cfg, EnablePreprocessors: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		// This is the leak #314 reports: 0 findings before the change, silently.
		if len(res.Matches) == 0 {
			t.Fatal("an embedded .svg carrying an SSN, an email, a name and a phone reported NOTHING.\n" +
				"Only reported findings reach the redactor, so a miss here is a cleartext leak.")
		}
		assertTypesReported(t, res.Matches, "SSN", "BUSINESS", "PERSON_NAME")
	})

	t.Run("flood standalone", func(t *testing.T) {
		res, err := ScanFile(ScanConfig{FilePath: geometry, Config: cfg, EnablePreprocessors: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if n := len(res.Matches); n != 0 {
			t.Errorf("a geometry-only SVG produced %d findings; every one is a path coordinate.\n"+
				"Measured at 9046dae on this fixture: 1,313 findings, 1,143 of them PHONE.\nfirst few: %v",
				n, typesOf(res.Matches, 8))
		}
	})

	t.Run("flood embedded", func(t *testing.T) {
		res, err := ScanFile(ScanConfig{FilePath: geomDoc, Config: cfg, EnablePreprocessors: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		// The container's own body text holds nothing reportable, so the only findings
		// possible here come from the embedded drawing.
		if n := len(res.Matches); n != 0 {
			t.Errorf("an embedded geometry-only SVG produced %d findings: %v", n, typesOf(res.Matches, 8))
		}
	})
}

// TestSVGRedactionAllStrategies drives the real redaction wiring, standalone and
// embedded, for every strategy.
func TestSVGRedactionAllStrategies(t *testing.T) {
	cfg := config.LoadConfigOrDefault("")

	for _, strategy := range []string{"simple", "format_preserving", "synthetic"} {
		for _, embedded := range []bool{false, true} {
			name := strategy
			if embedded {
				name += "/embedded"
			} else {
				name += "/standalone"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				var in string
				if embedded {
					in = filepath.Join(dir, "deck.docx")
					svgE2EWriteDocx(t, in, svgE2EDrawing)
				} else {
					in = svgE2EWrite(t, dir, "diagram.svg", svgE2EDrawing)
				}

				res, err := RedactFile(RedactConfig{
					FilePath:  in,
					OutputDir: filepath.Join(dir, "redacted"),
					Strategy:  strategy,
					Config:    cfg,
				})
				if err != nil {
					t.Fatalf("redaction failed: %v", err)
				}
				// NON-VACUITY: the redaction must have had something to do.
				if res.RedactionCount == 0 {
					t.Fatal("0 values were redacted, so every check below is vacuous")
				}

				// ASSERT THE FILE EXISTS before grepping it.
				out, err := os.ReadFile(res.RedactedFilePath)
				if err != nil {
					t.Fatalf("no redacted file at %s: %v", res.RedactedFilePath, err)
				}
				if len(out) == 0 {
					t.Fatal("the redacted file is empty")
				}

				svgPart := out
				if embedded {
					svgPart = svgE2EPart(t, out, "word/media/diagram1.svg")
					// Every member, so a value cannot hide in a part nobody checked.
					svgE2EAssertNoLeakAnywhere(t, out)
				}

				// POSITIVE CONTROL: the drawing must still be a drawing.
				for _, keep := range svgE2EKeep {
					if !strings.Contains(string(svgPart), keep) {
						t.Errorf("the drawing was destroyed: %q is gone.\n"+
							"An output with no <svg> element passes every leak check and is still data loss.\n"+
							"got:\n%s", keep, svgPart)
					}
				}
				for _, v := range svgE2EValues {
					if strings.Contains(string(svgPart), v) {
						t.Errorf("a reported value survived redaction in cleartext.\ngot:\n%s", svgPart)
						break
					}
				}
				if err := svgE2EXMLParses(svgPart); err != nil {
					t.Errorf("the redacted drawing no longer parses as XML: %v\ngot:\n%s", err, svgPart)
				}
			})
		}
	}
}

// TestSyntheticRedactionIsRandomAcrossRuns is the positive control for the comparison
// method: synthetic picks fresh values per run, so byte equality is not the test.
func TestSyntheticRedactionIsRandomAcrossRuns(t *testing.T) {
	cfg := config.LoadConfigOrDefault("")
	var seen []string
	for i := 0; i < 2; i++ {
		dir := t.TempDir()
		in := svgE2EWrite(t, dir, "diagram.svg", svgE2EDrawing)
		res, err := RedactFile(RedactConfig{
			FilePath:  in,
			OutputDir: filepath.Join(dir, "redacted"),
			Strategy:  "synthetic",
			Config:    cfg,
		})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		out, err := os.ReadFile(res.RedactedFilePath)
		if err != nil {
			t.Fatalf("run %d: no output: %v", i, err)
		}
		for _, v := range svgE2EValues {
			if strings.Contains(string(out), v) {
				t.Errorf("run %d: a value survived", i)
			}
		}
		seen = append(seen, string(out))
	}
	if seen[0] == seen[1] {
		t.Error("two synthetic runs produced identical bytes; if that is now the contract, the " +
			"length-and-leak comparison used elsewhere should be replaced with a byte A/B")
	}
	if len(seen[0]) == 0 || len(seen[1]) == 0 {
		t.Fatal("an empty output made this comparison vacuous")
	}
}

// TestCleanIconIsNotReportedUnexamined: a prose-less drawing is fully handled.
//
// Before the router learned to accept a parsed-but-textless result, a well-formed 64KB
// SVG of pure path geometry produced "cannot parse: contents do not match the .svg
// format" and exit 3 under --fail-on-incomplete. 88 of 90 real .svg files measured carry
// no prose, so that is a false alarm on nearly every SVG in existence.
func TestCleanIconIsNotReportedUnexamined(t *testing.T) {
	dir := t.TempDir()
	p := svgE2EWrite(t, dir, "icon.svg", svgE2EGlyphGeometry(50))

	res, err := ScanFile(ScanConfig{FilePath: p, Config: config.LoadConfigOrDefault(""), EnablePreprocessors: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Matches) != 0 {
		t.Errorf("a geometry-only icon reported %d findings", len(res.Matches))
	}
	if res.Incomplete {
		t.Errorf("a fully-read icon was reported as incomplete: %q.\n"+
			"That is coverage loss claimed where none happened, and it puts a line against nearly "+
			"every .svg on disk.", res.IncompleteReason)
	}
}

// svgE2EPart returns one member of a zip, failing the test if it is absent.
//
// Failing loudly matters: a missing part greps clean, so a repackaging bug that DROPPED
// the drawing would otherwise pass the leak check.
func svgE2EPart(t *testing.T, archive []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("the redacted .docx is not a readable zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer func() { _ = rc.Close() }()
		body, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return body
	}
	var have []string
	for _, f := range zr.File {
		have = append(have, f.Name)
	}
	t.Fatalf("the embedded part %s is missing from the redacted container; it holds %v", name, have)
	return nil
}

// svgE2EAssertNoLeakAnywhere inflates every member and checks all of them.
func svgE2EAssertNoLeakAnywhere(t *testing.T, archive []byte) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatalf("not a readable zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Fatal("the redacted container has no members, so this check is vacuous")
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		for _, v := range svgE2EValues {
			if bytes.Contains(body, []byte(v)) {
				t.Errorf("a reported value survived inside %s", f.Name)
			}
		}
	}
}

// assertTypesReported checks each wanted type appears at least once.
func assertTypesReported(t *testing.T, matches []detector.Match, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, m := range matches {
		got[m.Type] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s was not reported. reported types: %v", w, keysOf(got))
		}
	}
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func typesOf(matches []detector.Match, limit int) []string {
	var out []string
	for i, m := range matches {
		if i >= limit {
			break
		}
		out = append(out, m.Type)
	}
	return out
}
