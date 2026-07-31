// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// The Office builders exist to give the corpus its first .docx/.xlsx cases, so the
// builders themselves have to be trustworthy before any snapshot is generated from
// them. Two properties matter: the bytes must be identical across runs (a golden
// generated from a wobbling builder would fail on the next run for a reason that has
// nothing to do with the code under test), and the archive must actually be the
// dual-extractor shape whose routing the new cases are meant to lock.

// TestBuildDOCXIsDeterministic guards the property that makes snapshotting possible
// at all. archive/zip stamps each entry's modtime from FileHeader.Modified, so an
// unset header would embed "now" and the bytes would differ run to run.
func TestBuildDOCXIsDeterministic(t *testing.T) {
	paras := []string{"employee ssn 449-87-4100", "card 4532-0151-1283-0366"}
	a := BuildDOCX("Jane Analyst", "Jane Analyst", paras)
	b := BuildDOCX("Jane Analyst", "Jane Analyst", paras)

	if !bytes.Equal(a, b) {
		t.Fatalf("BuildDOCX is not byte-stable across calls (%d vs %d bytes); "+
			"a golden generated from it would fail on the next run", len(a), len(b))
	}
}

// TestBuildXLSXIsDeterministic is the same property for the spreadsheet builder.
func TestBuildXLSXIsDeterministic(t *testing.T) {
	cells := []string{"ssn 449-87-4100", "card 4532-0151-1283-0366"}
	a := BuildXLSX("xl/worksheets/sheet1.xml", "Jane Analyst", cells)
	b := BuildXLSX("xl/worksheets/sheet1.xml", "Jane Analyst", cells)

	if !bytes.Equal(a, b) {
		t.Fatalf("BuildXLSX is not byte-stable across calls (%d vs %d bytes)", len(a), len(b))
	}
}

// TestBuildDOCXCarriesBothChannels is the non-vacuity floor for the DOCX cases. The
// whole point of these fixtures is the arm where TWO preprocessors claim one file,
// so the archive must carry both a document body and core properties. If a future
// edit dropped docProps/core.xml the file would silently take the single-extractor
// fast path and every routing case built on it would still pass while testing
// nothing.
func TestBuildDOCXCarriesBothChannels(t *testing.T) {
	data := BuildDOCX("Jane Analyst", "Ops Reviewer", []string{"ssn 449-87-4100"})

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("BuildDOCX did not produce a readable zip: %v", err)
	}

	names := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening %s: %v", f.Name, err)
		}
		var sb strings.Builder
		if _, err := sb.Write(readAll(t, rc)); err != nil {
			t.Fatal(err)
		}
		rc.Close()
		names[f.Name] = sb.String()
	}

	body, ok := names["word/document.xml"]
	if !ok {
		t.Fatalf("no word/document.xml in the archive; parts are %v", keysOf(names))
	}
	if !strings.Contains(body, "449-87-4100") {
		t.Error("the document body does not carry the paragraph text it was given")
	}

	core, ok := names["docProps/core.xml"]
	if !ok {
		t.Fatalf("no docProps/core.xml in the archive — the file would take the "+
			"single-extractor path and the routing cases built on it would be vacuous; "+
			"parts are %v", keysOf(names))
	}
	if !strings.Contains(core, "Jane Analyst") || !strings.Contains(core, "Ops Reviewer") {
		t.Error("core properties do not carry both creator and lastModifiedBy")
	}
}

// TestBuildDOCXWithMainPartHonorsTheName pins the knob the part-name cases depend
// on: the caller must be able to place the body at a non-conventional path, because
// that is precisely the input whose handling the corpus needs to record.
func TestBuildDOCXWithMainPartHonorsTheName(t *testing.T) {
	data := BuildDOCXWithMainPart("word/Document.xml", "Jane Analyst", "", []string{"ssn 449-87-4100"})

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a readable zip: %v", err)
	}

	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
	}
	if !contains(got, "word/Document.xml") {
		t.Errorf("the requested main part name was not used; parts are %v", got)
	}
	if contains(got, "word/document.xml") {
		t.Errorf("the conventional part name is also present, so a case using this "+
			"builder would not isolate the alternate name; parts are %v", got)
	}
}

// TestBuildXLSXHonorsSheetPartName is the same knob for worksheets. The office text
// extractor derives the section label it emits from this name, so a case cannot lock
// that behavior unless the builder passes the name through untouched.
func TestBuildXLSXHonorsSheetPartName(t *testing.T) {
	const part = "xl/worksheets/sheet_office_metadata.xml"
	data := BuildXLSX(part, "Jane Analyst", []string{"ssn 449-87-4100"})

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a readable zip: %v", err)
	}
	var got []string
	for _, f := range zr.File {
		got = append(got, f.Name)
	}
	if !contains(got, part) {
		t.Errorf("sheet part name %q was not honored; parts are %v", part, got)
	}
	if !contains(got, "xl/sharedStrings.xml") {
		t.Errorf("no sharedStrings part — cell text would not be extractable; parts are %v", got)
	}
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatalf("reading part: %v", err)
	}
	return buf.Bytes()
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
