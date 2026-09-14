// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The per-format redaction contract, one row per container part.
//
// # Why a contract table and not another targeted test
//
// One class of defect has now been fixed SIX times, once per part somebody noticed was missing: an
// extension list that omitted a real part name, a container the extractor walked but the redactor did
// not, a part matched case-sensitively, docProps unreachable behind a body-part prefix, and (#670)
// OOXML relationship parts, which are named *.rels rather than *.xml and so were in no predicate at
// all. Every one was fixed at its own site, which is what guaranteed the next one.
//
// The pattern in all six is the same: coverage was decided by an ALLOWLIST of the parts someone had
// thought of, and nothing anywhere asserted that the list was complete. So this table is the gate. A
// new part type is one row, and a part that is scanned but not redactable — or redactable but not
// scanned — fails here rather than in a customer's "redacted" document.
//
// # The two directions, and why both must be asserted together
//
// Under the sink rule only REPORTED findings reach the redactor, so the two failures are different
// bugs with different severities and a test for one is blind to the other:
//
//	not scanned    -> nothing is reported -> nothing is redacted -> cleartext at exit 0, silently.
//	                  The residue guard cannot save this: it searches for reported values, and there
//	                  is no reported value.
//	not redactable -> the value IS reported, the residue guard sees it survive, and the tool REFUSES
//	                  to write the document. Loud and safe, but the user cannot redact the file.
//
// Measured on origin/main before this change, with a positive control in the same run: an SSN planted
// in word/comments.xml, word/footnotes.xml, word/endnotes.xml, xl/comments1.xml or a hyperlink target
// was absent from --preprocess-only, reported by no validator, and written to the redacted copy
// verbatim at exit 0 — while the SAME fixture generator's word/header1.xml and word/footer1.xml rows
// passed, which is exactly why the omission had stayed invisible.
//
// # Fixtures
//
// Built here rather than committed as binaries, so a reviewer can see what is being asserted and a new
// row costs no new binary file. They are validated by TestOfficeContractFixturesAreWellFormed below:
// every part must parse as XML, every planted part must be declared in [Content_Types].xml and
// reachable by a relationship, and the CONTROL rows must detect. A fixture that stopped being a valid
// document would otherwise turn this whole table into a pass — "not detected" for a boring reason.
//
// The behaviour these fixtures encode was first established against real documents produced by
// LibreOffice, not against the fixtures themselves; the fixtures exist to keep it fixed in CI, which
// has no office suite.

const (
	// Distinct per row so a finding can be attributed to the part it was planted in. All are
	// synthetic and all are detected in plain text — asserted by the control in
	// TestOfficeContractFixturesAreWellFormed.
	bodySSN      = "449-87-4100"
	commentsSSN  = "578-24-9163"
	footnoteSSN  = "601-42-7788"
	endnoteSSN   = "623-19-5504"
	headerSSN    = "647-88-3021"
	footerSSN    = "659-30-4412"
	xlCommentSSN = "731-60-2245"
	notesSSN     = "712-55-8890"
	linkSSN      = "764-22-9051"
	customXMLSSN = "778-45-1120"
	settingsSSN  = "786-33-6607"
)

type contractRow struct {
	name string
	// build returns a container holding value in the part named by part, and nothing else
	// sensitive except when coPlantBody is set.
	build func(t *testing.T, dir string) string
	part  string
	value string

	// scanned: the value must be REPORTED by a scan of this container. False for a part
	// deliberately left out of the scan path, which must still satisfy removal below.
	scanned bool

	// coPlantBody also places the value in the body part, so it is reported even when the part
	// itself is not scanned. This is the case that used to make a document UN-REDACTABLE: the
	// value located in the body, the broad search never ran, and the copy elsewhere survived into
	// the residue check.
	coPlantBody bool

	why string
}

func officeContractRows() []contractRow {
	return []contractRow{
		{
			name: "docx/body", part: "word/document.xml", value: bodySSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "body", bodySSN) },
			why:   "CONTROL. If this row fails the fixture generator is broken, not the tool.",
		},
		{
			name: "docx/header", part: "word/header1.xml", value: headerSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "header", headerSSN) },
			why:   "CONTROL. Already covered before #670; proves the generator can reach a non-body part.",
		},
		{
			name: "docx/footer", part: "word/footer1.xml", value: footerSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "footer", footerSSN) },
			why:   "CONTROL, as above.",
		},
		{
			name: "docx/comments", part: "word/comments.xml", value: commentsSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "comments", commentsSSN) },
			why:   "Silent leak before #670. Present in 58 of 330 real .docx. A review comment naming a person is ordinary.",
		},
		{
			name: "docx/footnotes", part: "word/footnotes.xml", value: footnoteSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "footnotes", footnoteSSN) },
			why:   "Silent leak before #670. Present in 158 of 330 real .docx.",
		},
		{
			name: "docx/endnotes", part: "word/endnotes.xml", value: endnoteSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "endnotes", endnoteSSN) },
			why:   "Silent leak before #670. Present in 150 of 330 real .docx.",
		},
		{
			name: "docx/hyperlink-target", part: "word/_rels/document.xml.rels", value: linkSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "link", linkSSN) },
			why: "THE #670 CASE. A relationship part is named *.rels, so it failed the .xml gate in the " +
				"redactor, in the residue check, and in partsHoldingRunJoined — where the .rels allowance " +
				"was live in the name filter and dead in practice, because partSpans reads character data " +
				"and a .rels part has none. Every one of 330 real .docx contains this part.",
		},
		{
			name: "docx/customXml-removal-only", part: "customXml/item1.xml", value: customXMLSSN,
			scanned: false, coPlantBody: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "customxml", customXMLSSN) },
			why: "NOT scanned on purpose — measured, it adds 403 findings that are almost all false " +
				"positives (zero-padded record ids read as PHONE, place names as PERSON_NAME). It must " +
				"still be cleaned when the value is reported from elsewhere, which is what this row pins.",
		},
		{
			name: "docx/settings-removal-only", part: "word/settings.xml", value: settingsSSN,
			scanned: false, coPlantBody: true,
			build: func(t *testing.T, d string) string { return buildDocx(t, d, "settings", settingsSSN) },
			why: "NOT scanned on purpose — producer configuration, and it yielded ZERO findings across 403 " +
				"real containers. Removal is still required.",
		},
		{
			name: "xlsx/cell", part: "xl/worksheets/sheet1.xml", value: bodySSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildXlsx(t, d, "cell", bodySSN) },
			why:   "CONTROL for the spreadsheet generator.",
		},
		{
			name: "xlsx/comments", part: "xl/comments1.xml", value: xlCommentSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildXlsx(t, d, "comments", xlCommentSSN) },
			why:   "Silent leak before #670. Cell comments are where a reviewer writes about a row.",
		},
		{
			name: "pptx/slide", part: "ppt/slides/slide1.xml", value: bodySSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildPptx(t, d, "slide", bodySSN) },
			why:   "CONTROL for the presentation generator.",
		},
		{
			name: "pptx/speaker-notes", part: "ppt/notesSlides/notesSlide1.xml", value: notesSSN, scanned: true,
			build: func(t *testing.T, d string) string { return buildPptx(t, d, "notes", notesSSN) },
			why: "Scanned before #670 but NOT in the redactor's part list, so it only ever redacted through " +
				"the split-run fallback — which runs solely when the value cannot be located at all. " +
				"See the coPlantBody row below for the case that made a document un-redactable.",
		},
		{
			name: "pptx/notes-with-body-copy", part: "ppt/notesSlides/notesSlide1.xml", value: bodySSN,
			scanned: true, coPlantBody: true,
			build: func(t *testing.T, d string) string { return buildPptx(t, d, "notes-and-slide", bodySSN) },
			why: "THE ASYMMETRY. Before #670 the same value in the slide AND its notes was located in the " +
				"slide, the broad search never ran, and the whole presentation was REFUSED — while the " +
				"value in the notes alone redacted fine. A name on a slide and again in its speaker notes " +
				"is completely ordinary, so the common case failed and the rarer one worked.",
		},
	}
}

// TestOfficePartRedactionContract is the gate: for every part, a planted value must be reported when
// the part is in the scan path, and must be ABSENT from every member of the redacted output.
func TestOfficePartRedactionContract(t *testing.T) {
	bin := buildScanner(t)

	for _, row := range officeContractRows() {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			doc := row.build(t, dir)

			// Non-vacuity, first: the value must really be in the part this row names, read
			// DECOMPRESSED. A fixture that failed to plant would make every assertion below pass.
			assertPartHoldsValue(t, doc, row.part, row.value)

			if row.scanned {
				if !scanReportsValue(t, bin, doc, row.value) {
					t.Errorf("%s was NOT reported.\n  why this row exists: %s\n"+
						"  Under the sink rule an unreported value is an unredacted value: the "+
						"redactor is given only reported findings, so this ships in cleartext at "+
						"exit 0 with nothing on stderr.", row.part, row.why)
				}
			}

			out := filepath.Join(dir, "out")
			if err := os.MkdirAll(out, 0o750); err != nil {
				t.Fatalf("creating output dir: %v", err)
			}
			redacted, stderr := redactDocument(t, bin, doc, out)
			if redacted == "" {
				t.Fatalf("no redacted artifact was written for %s — the tool refused.\n"+
					"  why this row exists: %s\n  stderr: %s", row.part, row.why, stderr)
			}

			// The whole point: absent from EVERY member, read decompressed. Grepping the
			// compressed bytes returns 0 and looks like a pass, which is how earlier instances of
			// this class got through review.
			if holders := membersContaining(t, redacted, row.value); len(holders) > 0 {
				t.Errorf("%s: the value survives redaction in %v.\n  why this row exists: %s",
					row.part, holders, row.why)
			}

			// And the document must still be a document.
			assertContainerWellFormed(t, redacted)
		})
	}
}

// TestOfficeContractFixturesAreWellFormed is the non-vacuity guard for the table above.
//
// Every fixture must be a structurally valid container — each XML member parses, and the planted part
// is declared in [Content_Types].xml — because "not detected" from a document the tool cannot read is
// not evidence of anything. It also asserts the planted values are detectable AT ALL in plain text, so
// a value that stopped being reported for an unrelated scoring reason fails here, loudly, instead of
// turning a row above into a false leak report.
func TestOfficeContractFixturesAreWellFormed(t *testing.T) {
	bin := buildScanner(t)

	// Every planted value must be reported in plain text. If this fails, the table above is
	// measuring the validators, not part coverage.
	dir := t.TempDir()
	plain := filepath.Join(dir, "control.txt")
	var sb strings.Builder
	values := []string{bodySSN, commentsSSN, footnoteSSN, endnoteSSN, headerSSN, footerSSN,
		xlCommentSSN, notesSSN, linkSSN, customXMLSSN, settingsSSN}
	for i, v := range values {
		fmt.Fprintf(&sb, "record %d SSN: %s\n", i, v)
	}
	if err := os.WriteFile(plain, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("writing control: %v", err)
	}
	for _, v := range values {
		if !scanReportsValue(t, bin, plain, v) {
			t.Errorf("control: %q is not reported even in plain text, so every row using it is "+
				"vacuous — pick a different value rather than deleting the row", v)
		}
	}

	for _, row := range officeContractRows() {
		t.Run(row.name, func(t *testing.T) {
			d := t.TempDir()
			doc := row.build(t, d)
			assertContainerWellFormed(t, doc)
			assertPartHoldsValue(t, doc, row.part, row.value)
			assertPartDeclared(t, doc, row.part)
		})
	}
}

// ---- helpers ----------------------------------------------------------------------------------

func scanReportsValue(t *testing.T, bin, doc, value string) bool {
	t.Helper()
	cmd := exec.Command(bin, "--file", doc, "--config", os.DevNull,
		"--checks", "all", "--format", "json", "--limit", "0", "--show-match")
	out, err := cmd.Output()
	if err != nil {
		// A non-zero exit is normal when findings exist; only an unparseable document is fatal.
		if len(out) == 0 {
			t.Fatalf("scanning %s: %v", doc, err)
		}
	}
	var doc2 struct {
		Results []struct {
			Text string `json:"text"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &doc2); err != nil {
		t.Fatalf("parsing findings JSON for %s: %v", doc, err)
	}
	for _, r := range doc2.Results {
		if r.Text == value {
			return true
		}
	}
	return false
}

func redactDocument(t *testing.T, bin, doc, outDir string) (artifact string, stderr string) {
	t.Helper()
	cmd := exec.Command(bin, "--file", doc, "--config", os.DevNull, "--checks", "all",
		"--enable-redaction", "--redaction-output-dir", outDir)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	_ = cmd.Run() // findings make the exit code non-zero by design
	want := strings.ToLower(filepath.Ext(doc))
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || artifact != "" {
			return nil //nolint:nilerr // a missing artifact is the caller's assertion, not an error here
		}
		if strings.ToLower(filepath.Ext(p)) == want {
			artifact = p
		}
		return nil
	})
	return artifact, errBuf.String()
}

// membersContaining returns the names of every zip member whose DECOMPRESSED bytes hold value.
func membersContaining(t *testing.T, container, value string) []string {
	t.Helper()
	zr, err := zip.OpenReader(container)
	if err != nil {
		t.Fatalf("opening %s: %v", container, err)
	}
	defer zr.Close()
	var holders []string
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			continue
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(rc)
		rc.Close()
		if bytes.Contains(buf.Bytes(), []byte(value)) {
			holders = append(holders, f.Name)
		}
	}
	return holders
}

func assertPartHoldsValue(t *testing.T, container, part, value string) {
	t.Helper()
	for _, name := range membersContaining(t, container, value) {
		if name == part {
			return
		}
	}
	t.Fatalf("fixture problem: %s does not hold %q, so this row asserts nothing", part, value)
}

func assertPartDeclared(t *testing.T, container, part string) {
	t.Helper()
	if strings.HasSuffix(part, ".rels") {
		return // relationship parts are located by convention, not declared as overrides
	}
	zr, err := zip.OpenReader(container)
	if err != nil {
		t.Fatalf("opening %s: %v", container, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "[Content_Types].xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening content types: %v", err)
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(rc)
		rc.Close()
		if strings.Contains(buf.String(), "/"+part) || strings.Contains(buf.String(), "Default") {
			return
		}
		t.Errorf("fixture problem: %s is not declared in [Content_Types].xml, so a real "+
			"consumer would ignore it and 'not detected' would mean nothing", part)
		return
	}
	// ODF has no [Content_Types].xml; its manifest serves the same role and is checked by
	// assertContainerWellFormed.
}

// assertContainerWellFormed checks every XML member parses, so a redaction that corrupted a part
// fails here rather than silently producing a file no office suite will open.
func assertContainerWellFormed(t *testing.T, container string) {
	t.Helper()
	zr, err := zip.OpenReader(container)
	if err != nil {
		t.Fatalf("opening %s: %v", container, err)
	}
	defer zr.Close()
	seen := 0
	for _, f := range zr.File {
		low := strings.ToLower(f.Name)
		if !strings.HasSuffix(low, ".xml") && !strings.HasSuffix(low, ".rels") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Errorf("%s: opening member %s: %v", container, f.Name, err)
			continue
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(rc)
		rc.Close()
		if err := xmlWellFormed(buf.Bytes()); err != nil {
			t.Errorf("%s: member %s is not well-formed XML after redaction: %v", container, f.Name, err)
		}
		seen++
	}
	if seen == 0 {
		t.Errorf("%s: no XML members found, so well-formedness was not actually checked", container)
	}
}
