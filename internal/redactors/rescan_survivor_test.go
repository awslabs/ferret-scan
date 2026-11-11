// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestNoReportedValueSurvivesARescanOfTheCopy is TEST_PLAN dimension 5 as a test: scan a container,
// redact it, scan the copy with the same scanner, and fail on any value reported both times. A value
// reported again is a silent survivor (#914, #915) whatever a byte-level search of the copy says, and
// for a zip container a byte-level search says nothing at all.
//
// The fixtures hold the shapes #914 measured on the public corpus, with fictional values: a slide whose
// paragraphs the scanner joins with a space, a sheet whose cells it joins with a tab, an OpenDocument
// spreadsheet whose cells it joins with a space, and a Word paragraph whose runs a <w:tab/> separates.
// On main @ 2fb4719 every one of them was written at exit 0 with the joined value still in it. Now the
// first three are rewritten, and the fourth, which no boundary view models, is refused: a refusal writes
// no copy, so there is nothing to re-scan and nothing silent about it.
func TestNoReportedValueSurvivesARescanOfTheCopy(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	for _, fx := range rescanFixtures() {
		for _, strategy := range []string{"simple", "format_preserving"} {
			t.Run(fx.name+"/"+strategy, func(t *testing.T) {
				in := filepath.Join(t.TempDir(), "doc"+fx.ext)
				if err := os.WriteFile(in, fx.pkg(t), 0o600); err != nil {
					t.Fatal(err)
				}
				reported := scanFile(t, cfg, in)
				assertSomeFindingSpansNodes(t, fx, reported)

				res, err := core.RedactFile(core.RedactConfig{
					FilePath:  in,
					OutputDir: filepath.Join(t.TempDir(), "redacted"),
					Strategy:  strategy,
					Config:    cfg,
					LogWriter: io.Discard,
				})
				if fx.refused {
					if err == nil {
						t.Fatalf("a copy was written although no rewrite can place the joined value: %s", res.RedactedFilePath)
					}
					if !strings.Contains(err.Error(), "could not locate") {
						t.Errorf("the refusal does not say the value could not be located: %v", err)
					}
					return
				}
				if err != nil {
					if errors.Is(err, core.ErrRedactionIncomplete) {
						t.Fatalf("the fixture was not fully examined, so the re-scan proves nothing: %v", err)
					}
					t.Fatalf("RedactFile: %v", err)
				}

				again := make(map[string]bool)
				for _, m := range scanFile(t, cfg, res.RedactedFilePath) {
					again[m.Type+"\x00"+m.Text] = true
				}
				for _, m := range reported {
					if eligibleSurvivor(m.Text) && again[m.Type+"\x00"+m.Text] {
						t.Errorf("silent survivor: %s %q is reported in the input and again in its redacted copy", m.Type, m.Text)
					}
				}
			})
		}
	}
}

// labelOnly is scripts/corpus-ab.sh's LABEL_ONLY: a field name with no value is not a survivor.
var labelOnly = regexp.MustCompile(`^\s*[A-Za-z][\w .()/-]{0,40}:\s*$`)

// eligibleSurvivor mirrors the residue floor: values shorter than four bytes are not searched for anywhere.
func eligibleSurvivor(text string) bool {
	return len(text) >= 4 && !labelOnly.MatchString(strings.TrimSpace(text))
}

func scanFile(t *testing.T, cfg *config.Config, path string) []detector.Match {
	t.Helper()
	res, err := core.ScanFile(core.ScanConfig{FilePath: path, Config: cfg, EnablePreprocessors: true, LogWriter: io.Discard})
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", filepath.Base(path), err)
	}
	if res.Incomplete {
		t.Fatalf("ScanFile(%s) did not finish: %s", filepath.Base(path), res.IncompleteReason)
	}
	return res.Matches
}

// assertSomeFindingSpansNodes is the non-vacuity check: at least one value the scanner reports must be
// held whole by no single text node of the fixture, or the fixture tests only the per-node rewrite.
func assertSomeFindingSpansNodes(t *testing.T, fx rescanFixture, reported []detector.Match) {
	t.Helper()
	var nodes []string
	for _, p := range fx.parts {
		dec := xml.NewDecoder(strings.NewReader(p[1]))
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			if cd, ok := tok.(xml.CharData); ok {
				nodes = append(nodes, string(cd))
			}
		}
	}
	for _, m := range reported {
		whole := false
		for _, n := range nodes {
			if strings.Contains(n, m.Text) {
				whole = true
				break
			}
		}
		if !whole {
			return
		}
	}
	t.Fatalf("every finding in %s sits inside one text node, so the fixture no longer exercises #914: %d findings",
		fx.name, len(reported))
}

type rescanFixture struct {
	name    string
	ext     string
	parts   [][2]string
	refused bool // no boundary view models this shape: the copy must be refused, not written
}

func (f rescanFixture) pkg(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range f.parts {
		method := zip.Deflate
		if p[0] == "mimetype" {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p[0], Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, p[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rescanFixtures() []rescanFixture {
	const types = `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="xml" ContentType="application/xml"/>`
	para := func(s string) string { return `<a:p><a:r><a:rPr lang="en-US"/><a:t>` + s + `</a:t></a:r></a:p>` }
	slide := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
		`xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody>` +
		para("Contact:") + para("Mary Johnson") + para("English Language Arts &amp; Assessment") +
		para("Employee SSN: 234-56-0001") + `</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`

	const sheetNS = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`
	sst := `<?xml version="1.0" encoding="UTF-8"?><sst ` + sheetNS + ` count="4" uniqueCount="4">` +
		`<si><t>Name</t></si><si><t>Mary</t></si><si><t>Johnson</t></si><si><t>Phone</t></si></sst>`
	sheet := `<?xml version="1.0" encoding="UTF-8"?><worksheet ` + sheetNS + `><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>3</v></c></row>` +
		`<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2" t="s"><v>2</v></c>` +
		`<c r="C2"><v>600</v></c><c r="D2"><v>600</v></c><c r="E2"><v>1250</v></c></row>` +
		`<row r="3"><c r="A3" t="s"><v>1</v></c><c r="B3"><v>234560001</v></c></row></sheetData></worksheet>`

	cell := func(s string) string {
		return `<table:table-cell office:value-type="string"><text:p>` + s + `</text:p></table:table-cell>`
	}
	ods := `<?xml version="1.0" encoding="UTF-8"?><office:document-content ` +
		`xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" ` +
		`xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" ` +
		`xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:spreadsheet>` +
		`<table:table table:name="Sheet1"><table:table-row>` + cell("Contact") + cell("Mary") + cell("Johnson") +
		`</table:table-row><table:table-row>` + cell("SSN 234-56-0001") + `</table:table-row></table:table>` +
		`</office:spreadsheet></office:body></office:document-content>`

	docx := `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>Holder: Mary</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>Johnson</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>SSN 234-56-0001</w:t></w:r></w:p></w:body></w:document>`

	return []rescanFixture{
		{name: "pptx", ext: ".pptx", parts: [][2]string{{"[Content_Types].xml", types + `</Types>`}, {"ppt/slides/slide1.xml", slide}}},
		{name: "xlsx", ext: ".xlsx", parts: [][2]string{{"[Content_Types].xml", types + `</Types>`},
			{"xl/sharedStrings.xml", sst}, {"xl/worksheets/sheet1.xml", sheet}}},
		{name: "ods", ext: ".ods", parts: [][2]string{{"mimetype", "application/vnd.oasis.opendocument.spreadsheet"}, {"content.xml", ods}}},
		{name: "docx", ext: ".docx", refused: true, parts: [][2]string{
			{"[Content_Types].xml", types + `<Override PartName="/word/document.xml" ` +
				`ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
			{"word/document.xml", docx}}},
	}
}
