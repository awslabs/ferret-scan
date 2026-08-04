// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end legacy Office extraction: a REAL OLE compound file goes in, and the
// assertions are on what a scan would actually see.
//
// The unit tests next door cover recoverPrintableRuns and the stream-name tables
// in isolation. Neither proves the pieces are wired together: a container whose
// property stream is never located, or whose property names never match the
// mapping switch, would satisfy every one of them while reporting nothing. Since
// only reported findings are redacted, that gap is a cleartext leak rather than a
// cosmetic one, so the path is exercised through ExtractMetadata — the same entry
// point the preprocessor calls.
//
// Fixtures are built in-process by buildLegacyCFB (see cfb_fixture_test.go),
// matching how the OOXML cases synthesize .docx/.xlsx rather than committing an
// opaque binary.

func writeLegacyFixture(t *testing.T, name string, streams []legacyCFBStream) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buildLegacyCFB(t, streams), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

// The headline case: an author name in the property stream and an SSN in the body
// must BOTH surface. Before legacy support existed this file produced the error
// "legacy Office formats not supported" and nothing in it was scanned at all.
func TestLegacyExtraction_BodyAndPropertiesBothSurface(t *testing.T) {
	path := writeLegacyFixture(t, "report.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Quarterly summary follows.\r" +
			"Employee SSN: 449-87-4100 on file.\r" +
			"Card 4532-0151-1283-0366 expires soon.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropAuthor:     "Jane Analyst",
			SummaryPropLastAuthor: "Ops Reviewer",
			SummaryPropAppName:    "Microsoft Word 97",
			SummaryPropTitle:      "Quarterly Review",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	// --- the metadata half (exact: a documented key/value format) -------------
	for _, tc := range []struct{ field, got, want string }{
		{"Author", md.Author, "Jane Analyst"},
		{"Creator", md.Creator, "Jane Analyst"},
		{"LastModifiedBy", md.LastModifiedBy, "Ops Reviewer"},
		{"Application", md.Application, "Microsoft Word 97"},
		{"Title", md.Title, "Quarterly Review"},
	} {
		if tc.got != tc.want {
			t.Errorf("md.%s = %q, want %q — this field is present in the container's "+
				"property stream, so a wrong or empty value here means it is never "+
				"reported and therefore never redacted", tc.field, tc.got, tc.want)
		}
	}

	// --- the body half (approximate: recovered printable runs) ----------------
	body := md.Properties["LegacyBodyText"]
	if body == "" {
		t.Fatal("Properties[\"LegacyBodyText\"] is empty — the document body was not " +
			"recovered, so every value in it goes unscanned and stays in cleartext")
	}
	for _, want := range []string{"449-87-4100", "4532-0151-1283-0366"} {
		if !strings.Contains(body, want) {
			t.Errorf("recovered body does not contain %q; a validator would never see it.\nbody=%q",
				want, body)
		}
	}
}

// Company and Manager live in DocumentSummaryInformation, a SECOND property set
// with a different FMTID. A mapping that only handled SummaryInformation would
// pass every other test here and still drop them.
func TestLegacyExtraction_DocumentSummaryInformationProperties(t *testing.T) {
	path := writeLegacyFixture(t, "corp.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05DocumentSummaryInformation", Data: BuildDocSummaryInformation(map[uint32]string{
			DocSummaryPropCompany:  "Example Holdings LLC",
			DocSummaryPropManager:  "Dana Director",
			DocSummaryPropCategory: "Internal",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	for _, tc := range []struct{ field, got, want string }{
		{"Company", md.Company, "Example Holdings LLC"},
		{"Manager", md.Manager, "Dana Director"},
		{"Category", md.Category, "Internal"},
	} {
		if tc.got != tc.want {
			t.Errorf("md.%s = %q, want %q — DocumentSummaryInformation is a separate "+
				"property set; if it is not read, company and manager names leak",
				tc.field, tc.got, tc.want)
		}
	}
}

// Property NAMES come from msoleps's own tables, not from the OOXML vocabulary,
// and the two disagree: msoleps calls property 0x1B "Content status", with a
// space. A case written as "ContentStatus" — the OOXML spelling, and the obvious
// guess — matches nothing and the field is silently always empty.
//
// This is separated from the case above because it is the spelling, not the
// property set, that is under test.
func TestLegacyExtraction_ContentStatusSpelling(t *testing.T) {
	path := writeLegacyFixture(t, "status.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05DocumentSummaryInformation", Data: BuildDocSummaryInformation(map[uint32]string{
			DocSummaryPropContentStatus: "Confidential Draft",
			DocSummaryPropLanguage:      "en-US",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.ContentStatus != "Confidential Draft" {
		t.Errorf("ContentStatus = %q, want %q — msoleps names this property "+
			"\"Content status\" WITH A SPACE; a \"ContentStatus\" case never fires and "+
			"the value is never reported", md.ContentStatus, "Confidential Draft")
	}
	if md.Language != "en-US" {
		t.Errorf("Language = %q, want %q", md.Language, "en-US")
	}
}

// Every legacy format must work, not just .doc. Each has a differently NAMED body
// stream, and the name table is the entire selection mechanism, so a missing entry
// silently unscans a whole format.
func TestLegacyExtraction_AllThreeFormats(t *testing.T) {
	cases := []struct {
		filename   string
		bodyStream string
		wantMime   string
	}{
		{"letter.doc", "WordDocument", "application/msword"},
		{"budget.xls", "Workbook", "application/vnd.ms-excel"},
		{"deck.ppt", "PowerPoint Document", "application/vnd.ms-powerpoint"},
		// Excel 5.0/95 named the stream "Book". Archives still contain these.
		{"old.xls", "Book", "application/vnd.ms-excel"},
	}
	for _, tc := range cases {
		t.Run(tc.filename+"/"+tc.bodyStream, func(t *testing.T) {
			path := writeLegacyFixture(t, tc.filename, []legacyCFBStream{
				{Name: tc.bodyStream, Data: []byte("Employee SSN: 449-87-4100 recorded here.")},
				{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
					SummaryPropAuthor: "Jane Analyst",
				})},
			})

			md, err := ExtractMetadata(path)
			if err != nil {
				t.Fatalf("ExtractMetadata: %v", err)
			}
			if md.MimeType != tc.wantMime {
				t.Errorf("MimeType = %q, want %q", md.MimeType, tc.wantMime)
			}
			if md.Author != "Jane Analyst" {
				t.Errorf("Author = %q, want %q", md.Author, "Jane Analyst")
			}
			if body := md.Properties["LegacyBodyText"]; !strings.Contains(body, "449-87-4100") {
				t.Errorf("%s body stream %q was not read: the SSN in it is invisible to "+
					"every validator.\nbody=%q", tc.filename, tc.bodyStream, body)
			}
		})
	}
}

// Timestamps come back as OLE FileTime values, and the type assertion that reads
// them is easy to get wrong in a way nothing else catches: msoleps returns
// types.FileTime BY VALUE, so a *types.FileTime assertion silently never fires and
// every legacy document reports a zero Created/Modified with no error.
func TestLegacyExtraction_TimestampsAreParsed(t *testing.T) {
	path := writeLegacyFixture(t, "dated.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformationWithTimes(
			map[uint32]string{SummaryPropAuthor: "Jane Analyst"},
			map[uint32]uint64{
				SummaryPropCreateTime:   fileTimeFor(2021, 3, 4),
				SummaryPropLastSaveTime: fileTimeFor(2022, 6, 7),
			},
		)},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Created.IsZero() {
		t.Error("Created is zero although the property stream carries a CreateTime — " +
			"a value-vs-pointer type assertion mismatch drops the whole field silently")
	}
	if md.Modified.IsZero() {
		t.Error("Modified is zero although the property stream carries a LastSaveTime")
	}
	if y := md.Created.UTC().Year(); !md.Created.IsZero() && y != 2021 {
		t.Errorf("Created year = %d, want 2021 (FileTime epoch conversion is wrong)", y)
	}
	if y := md.Modified.UTC().Year(); !md.Modified.IsZero() && y != 2022 {
		t.Errorf("Modified year = %d, want 2022", y)
	}
}

// A template path is a classic legacy leak: it routinely holds an internal UNC
// share, and it is a field users do not know is in the file.
func TestLegacyExtraction_TemplatePathIsReported(t *testing.T) {
	const tmpl = `\\corp-fs01\templates\quarterly.dot`
	path := writeLegacyFixture(t, "tmpl.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropTemplate: tmpl,
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Template != tmpl {
		t.Errorf("Template = %q, want %q — an unreported internal share path cannot be redacted",
			md.Template, tmpl)
	}
}

// Malformed and hostile inputs must fail predictably rather than crash or, worse,
// report success on a file that was never parsed.
func TestLegacyExtraction_MalformedInputs(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		why     string
	}{
		{"not_ole.doc", []byte("This is plain text that happens to end in .doc\n"),
			"a text file misnamed .doc"},
		{"zip.doc", []byte{0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0},
			"a ZIP misnamed .doc"},
		{"truncated.doc", []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
			"the CFB signature with no sectors behind it"},
		{"signature_only_padded.doc", append(
			[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 600)...),
			"a plausible header with an empty FAT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, tc.content, 0o600); err != nil {
				t.Fatal(err)
			}

			// The contract is "do not panic, and do not invent metadata". An error
			// is the expected outcome; an empty result without error is tolerable.
			// Silently returning a populated Metadata would not be.
			md, err := ExtractMetadata(path)
			if err != nil {
				return // predictable failure: correct
			}
			if md == nil {
				return
			}
			if md.Author != "" || md.Company != "" || md.Title != "" {
				t.Errorf("%s (%s) produced metadata from a file that is not an OLE "+
					"container: Author=%q Company=%q Title=%q",
					tc.name, tc.why, md.Author, md.Company, md.Title)
			}
			if body := md.Properties["LegacyBodyText"]; body != "" {
				t.Errorf("%s (%s) produced body text %q from an unparseable container",
					tc.name, tc.why, body)
			}
		})
	}
}

// An empty property stream, and a container with no property stream at all, must
// leave the fields empty rather than fail the whole file: partial recovery beats
// none for a scanner, so a missing SummaryInformation must not cost the body text.
func TestLegacyExtraction_PartialRecovery(t *testing.T) {
	t.Run("body only, no property stream", func(t *testing.T) {
		path := writeLegacyFixture(t, "bodyonly.doc", []legacyCFBStream{
			{Name: "WordDocument", Data: []byte("Employee SSN: 449-87-4100 recorded here.")},
		})
		md, err := ExtractMetadata(path)
		if err != nil {
			t.Fatalf("a container with no property stream must still yield its body: %v", err)
		}
		if !strings.Contains(md.Properties["LegacyBodyText"], "449-87-4100") {
			t.Error("body text was lost because the property stream was absent")
		}
	})

	t.Run("property stream only, no body", func(t *testing.T) {
		path := writeLegacyFixture(t, "propsonly.doc", []legacyCFBStream{
			{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
				SummaryPropAuthor: "Jane Analyst",
			})},
		})
		md, err := ExtractMetadata(path)
		if err != nil {
			t.Fatalf("a container with no body stream must still yield its properties: %v", err)
		}
		if md.Author != "Jane Analyst" {
			t.Errorf("Author = %q; properties were lost because the body was absent", md.Author)
		}
	})

	t.Run("garbage in the property stream", func(t *testing.T) {
		path := writeLegacyFixture(t, "badprops.doc", []legacyCFBStream{
			{Name: "WordDocument", Data: []byte("Employee SSN: 449-87-4100 recorded here.")},
			{Name: "\x05SummaryInformation", Data: []byte("not a property set stream at all")},
		})
		md, err := ExtractMetadata(path)
		if err != nil {
			t.Fatalf("an unparseable property stream must not fail the file: %v", err)
		}
		if !strings.Contains(md.Properties["LegacyBodyText"], "449-87-4100") {
			t.Error("an unparseable property stream cost the body text; partial recovery " +
				"is the whole point of skipping a bad stream")
		}
	})
}

// Extraction must be byte-for-byte repeatable. Map iteration order inside a
// property walk has produced nondeterministic output in this repo before, and a
// scanner whose findings vary run to run cannot be gated in CI.
func TestLegacyExtraction_IsDeterministic(t *testing.T) {
	streams := []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("SSN 449-87-4100 and card 4532-0151-1283-0366 here.")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropAuthor:     "Jane Analyst",
			SummaryPropLastAuthor: "Ops Reviewer",
			SummaryPropTitle:      "Quarterly Review",
			SummaryPropSubject:    "Numbers",
			SummaryPropKeywords:   "confidential",
		})},
		{Name: "\x05DocumentSummaryInformation", Data: BuildDocSummaryInformation(map[uint32]string{
			DocSummaryPropCompany: "Example Holdings LLC",
			DocSummaryPropManager: "Dana Director",
		})},
	}
	path := writeLegacyFixture(t, "stable.doc", streams)

	type snapshot struct{ author, company, manager, title, body string }
	var first snapshot
	const runs = 12
	for i := 0; i < runs; i++ {
		md, err := ExtractMetadata(path)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		got := snapshot{md.Author, md.Company, md.Manager, md.Title, md.Properties["LegacyBodyText"]}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("run %d differs from run 0 on the SAME file:\n first=%+v\n got  =%+v\n"+
				"nondeterministic extraction cannot be gated in CI and makes redaction "+
				"depend on which run the user got", i, first, got)
		}
	}
}
