// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryKnownOOXMLPartIsClassified is the gate for the whole class of defect #680 belongs to.
//
// Part coverage has been decided by an allowlist seven times, and each time the list was missing
// something nobody had thought of: #670 found the .rels parts, #680 found six more, and classifying
// the real-world inventory then found five MORE that #680 had not listed — including word/people.xml
// and ppt/authors.xml, which hold comment authors' display names, and the SmartArt data parts.
//
// The failure mode is silence. Under the sink rule only reported findings reach the redactor, so a
// part nothing reads is written to the "redacted" copy in cleartext at exit 0 with an empty stderr.
// Nothing anywhere noticed, for years, because there was no assertion that could notice.
//
// So this is the assertion: every part name in the observed inventory must be classified — read, or
// deliberately skipped WITH a reason. An unclassified part fails here, and someone decides.
func TestEveryKnownOOXMLPartIsClassified(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "ooxml_part_inventory.txt"))
	if err != nil {
		t.Fatalf("opening the part inventory: %v", err)
	}
	defer f.Close()

	var unclassified []string
	var included, excluded int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		switch c, why := classifyPart(name); c {
		case partIncluded:
			included++
			if why == "" {
				t.Errorf("%s is included with no recorded reason", name)
			}
		case partExcluded:
			excluded++
			if why == "" {
				t.Errorf("%s is excluded with no recorded reason", name)
			}
		default:
			unclassified = append(unclassified, name)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading the inventory: %v", err)
	}

	// Non-vacuity: an empty or unreadable inventory must not pass. 90 families were observed; require
	// most of them to still be here so a truncated file fails rather than silently asserting nothing.
	if total := included + excluded + len(unclassified); total < 80 {
		t.Fatalf("the inventory holds only %d parts; it had 90. A truncated inventory makes this "+
			"guard vacuous — every part it does not list is a part nobody has to classify", total)
	}
	if included < 6 {
		t.Errorf("only %d parts are INCLUDED; #680 alone covers six part families, so this list has "+
			"been narrowed and the guard is now asserting less than it did", included)
	}

	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Errorf("%d container part(s) are neither read nor deliberately skipped:\n  %s\n\n"+
			"Decide, and record the decision in ooxml_auxiliary.go:\n"+
			"  - it holds text a person typed  -> add it to auxiliaryPartIncludes with why\n"+
			"  - it does not                   -> add it to auxiliaryPartExclusions with why\n\n"+
			"Leaving it unclassified is the one option this test exists to remove: an unread part is "+
			"not partial coverage, it is a value written to the redacted copy in cleartext at exit 0.",
			len(unclassified), strings.Join(unclassified, "\n  "))
	}
	t.Logf("classified: %d read, %d deliberately skipped", included, excluded)
}

// TestAuxiliaryClassificationIsUnambiguous pins the precedence the two lists rely on.
//
// Exclusions are checked first so a narrow "already read by the slide loop" entry beats a broad
// include prefix. If that order were reversed, ppt/slides/slide1.xml would be read twice — once by
// the slide loop and once here — and every finding in a deck would be reported twice.
func TestAuxiliaryClassificationIsUnambiguous(t *testing.T) {
	cases := []struct {
		part string
		want partClassification
		why  string
	}{
		{"ppt/comments/modernComment_1_1.xml", partIncluded, "#680: PowerPoint review comments"},
		{"ppt/tags/tag1.xml", partIncluded, "#680: producer/user tags"},
		{"ppt/presentation.xml", partIncluded, "#680: presentation-level text"},
		{"xl/tables/table1.xml", partIncluded, "#680: user-authored column headings"},
		{"xl/charts/chart1.xml", partIncluded, "#680: chart titles"},
		{"word/charts/chart1.xml", partIncluded, "#680: chart titles"},
		{"word/people.xml", partIncluded, "found by the guard: comment author display names"},
		{"ppt/authors.xml", partIncluded, "found by the guard: modern comment authors"},
		{"ppt/commentAuthors.xml", partIncluded, "found by the guard: comment authors"},
		{"word/diagrams/data1.xml", partIncluded, "found by the guard: SmartArt content"},
		{"ppt/diagrams/data1.xml", partIncluded, "found by the guard: SmartArt content"},

		// Already read by a format pass. These MUST be excluded or their findings double.
		{"ppt/slides/slide1.xml", partExcluded, "the slide loop reads it"},
		{"ppt/notesSlides/notesSlide1.xml", partExcluded, "read per slide, via that slide's rels"},
		{"ppt/slideMasters/slideMaster1.xml", partExcluded, "the master loop reads it"},
		{"xl/worksheets/sheet1.xml", partExcluded, "the worksheet loop reads it"},
		{"xl/sharedStrings.xml", partExcluded, "resolved by the worksheet pass"},
		{"word/document.xml", partExcluded, "the body"},
		{"word/header1.xml", partExcluded, "the header loop reads it"},
		{"word/footer1.xml", partExcluded, "the footer loop reads it"},
		{"word/comments.xml", partExcluded, "the annotation loop reads it"},
		{"xl/comments1.xml", partExcluded, "the comment loop reads it"},

		// Measured exclusions. Each of these was implemented, measured and reverted.
		{"customXml/item1.xml", partExcluded, "403 findings, false positives throughout (#679)"},
		{"ppt/slideLayouts/slideLayout1.xml", partExcluded, "~50 boilerplate findings per layout"},
		{"xl/externalLinks/externalLink1.xml", partExcluded, "cached labels: place names as PERSON_NAME"},
		{"word/numbering.xml", partExcluded, "list-definition GUID fragments as PHONE/SWIFT_BIC"},
		{"docProps/core.xml", partExcluded, "the metadata extractor's job"},
		{"[Content_Types].xml", partExcluded, "package manifest"},
		{"word/_rels/document.xml.rels", partExcluded, "read by appendExternalRelationshipTargets"},
		{"word/media/image1.png", partExcluded, "not an .xml part"},
	}
	for _, c := range cases {
		got, why := classifyPart(c.part)
		if got != c.want {
			t.Errorf("classifyPart(%q) = %v, want %v (%s)", c.part, got, c.want, c.why)
			continue
		}
		if got != partUnclassified && why == "" {
			t.Errorf("classifyPart(%q) classified it with no reason", c.part)
		}
	}
}

// TestLabelBearingAttributesAreKeyedOnTheElement is the regression guard for the false-positive
// source that a bare attribute-name list produced.
//
// `val` is OOXML's universal scalar attribute. Keyed on the name alone it matched <c:axId val="..."/>
// and reported 28 chart axis identifiers as PHONE across the real corpus. Keyed on the element it
// matches <p:tag val="..."/> and nothing else.
func TestLabelBearingAttributesAreKeyedOnTheElement(t *testing.T) {
	for key := range labelBearingAttrs {
		if !strings.Contains(key, "|") {
			t.Errorf("labelBearingAttrs key %q has no element part. A bare attribute name is what "+
				"reported chart axis ids as PHONE; keys must be \"element|attribute\"", key)
		}
	}

	// The axis-id shape must contribute nothing...
	axis := `<c:chartSpace><c:axId val="1829252287"/><c:crossAx val="1978746304"/></c:chartSpace>`
	if got := auxiliaryTextOf(t, axis); got != "" {
		t.Errorf("chart axis identifiers were extracted as text: %q.\n"+
			"These read as PHONE at confidence 25 and there were 28 of them on the real corpus.", got)
	}

	// ...while the tag shape, which uses the SAME attribute, must.
	tag := `<p:tagLst><p:tag name="OWNER" val="449-87-4100"/></p:tagLst>`
	got := auxiliaryTextOf(t, tag)
	if !strings.Contains(got, "449-87-4100") {
		t.Errorf("a p:tag value was NOT extracted (got %q). ppt/tags holds its value in this "+
			"attribute, so losing it re-opens #680's second row.", got)
	}
	if !strings.Contains(got, "OWNER") {
		t.Errorf("a p:tag name was not extracted (got %q)", got)
	}
}

// TestAuxiliaryExtractionSkipsTheNumericCache pins the other measured false-positive source.
func TestAuxiliaryExtractionSkipsTheNumericCache(t *testing.T) {
	// A chart part as a producer writes one: an authored title, and a cache of the plotted numbers.
	chart := `<c:chartSpace xmlns:c="c" xmlns:a="a">` +
		`<c:title><c:tx><c:rich><a:p><a:r><a:t>Headcount for 449-87-4100</a:t></a:r></a:p></c:rich></c:tx></c:title>` +
		`<c:ser><c:val><c:numRef><c:numCache>` +
		`<c:pt idx="0"><c:v>78260869565217395</c:v></c:pt>` +
		`<c:pt idx="1"><c:v>870366751</c:v></c:pt>` +
		`</c:numCache></c:numRef></c:val></c:ser></c:chartSpace>`
	got := auxiliaryTextOf(t, chart)

	if !strings.Contains(got, "449-87-4100") {
		t.Errorf("the chart TITLE was not extracted (got %q). Titles are the authored text and the "+
			"whole reason chart parts are read.", got)
	}
	for _, cached := range []string{"78260869565217395", "870366751"} {
		if strings.Contains(got, cached) {
			t.Errorf("a numeric cache entry (%s) was extracted.\n"+
				"Measured on 452 real containers, reading these produced a 17-digit datum as VIN at "+
				"confidence 90, plus 10-digit ids as PHONE and 9-digit ids as SSN — the false "+
				"positives that #680's own justification for this row turned out to be.\ngot: %q",
				cached, got)
		}
	}
}

// TestAuxiliaryExtractionAcceptsAnyNamespacePrefix — a producer chooses its prefixes, and this repo
// has already lost a whole body part to one capital letter.
func TestAuxiliaryExtractionAcceptsAnyNamespacePrefix(t *testing.T) {
	for _, doc := range []string{
		`<x:body xmlns:x="a"><x:t>Reviewer 449-87-4100</x:t></x:body>`,
		`<body><t>Reviewer 449-87-4100</t></body>`,
		`<w15:people xmlns:w15="w"><w15:person w15:author="449-87-4100"/></w15:people>`,
		`<zz:people xmlns:zz="w"><zz:person zz:author="449-87-4100"/></zz:people>`,
	} {
		if got := auxiliaryTextOf(t, doc); !strings.Contains(got, "449-87-4100") {
			t.Errorf("prefix-dependent extraction: %q yielded %q", doc, got)
		}
	}
}

// auxiliaryTextOf runs extractAuxiliaryPartText over body, through a real zip entry so the test
// exercises the same path production does rather than a string helper beside it.
func auxiliaryTextOf(t *testing.T, body string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("part.xml")
	if err != nil {
		t.Fatalf("creating the zip entry: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("writing the zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the zip: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("reading the zip back: %v", err)
	}
	got, err := extractAuxiliaryPartText(zr.File[0])
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	return got
}
