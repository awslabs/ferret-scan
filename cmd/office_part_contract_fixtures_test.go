// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Container builders for the redaction contract table in office_part_contract_test.go.
//
// Written by hand with archive/zip rather than committed as binary fixtures, for two reasons. A
// reviewer can see exactly what part a row plants into, which is the whole subject of the test; and a
// new row costs a few lines instead of a new binary blob nobody can diff.
//
// The obvious risk is that a hand-built container is not what a real producer emits, and that a test
// built on one asserts something about the fixture rather than about the tool. This repo has been
// bitten by that before. Three things hold it down:
//
//  1. Each package declares its parts in [Content_Types].xml and links them through the relationship
//     graph, exactly as a producer does — so the parts are REACHABLE, not orphans that a real consumer
//     would ignore.
//  2. TestOfficeContractFixturesAreWellFormed asserts that every member parses, that the planted part
//     is declared, and that every planted value is reported in plain text.
//  3. The CONTROL rows (body, header, footer, cell, slide) were already covered before this change, so
//     a generator that produced documents the tool cannot read would fail them first. A table where
//     only the new rows fail is a tool problem; one where the controls fail too is a fixture problem.
//
// The behaviour itself was established against real LibreOffice-produced .docx/.xlsx/.pptx during
// development. These fixtures exist to keep it fixed on CI, which has no office suite.

const (
	wNS   = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	relNS = `xmlns="http://schemas.openxmlformats.org/package/2006/relationships"`
	relT  = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	aNS   = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"`
	pNS   = `xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"`
	sNS   = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`
)

// writeContainer writes members to a zip at path. Order is preserved so a producer-like layout is
// reproducible, and so a failure is easier to read.
func writeContainer(t *testing.T, path string, members [][2]string) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- path is from t.TempDir()
	if err != nil {
		t.Fatalf("creating %s: %v", path, err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for _, m := range members {
		w, err := zw.Create(m[0])
		if err != nil {
			t.Fatalf("adding %s: %v", m[0], err)
		}
		if _, err := io.WriteString(w, m[1]); err != nil {
			t.Fatalf("writing %s: %v", m[0], err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing %s: %v", path, err)
	}
	return path
}

func wordPara(text string) string {
	return fmt.Sprintf(`<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, text)
}

// buildDocx builds a .docx whose `where` part holds value.
//
// bodyText always carries ordinary prose so the document is never empty; rows that need the value in
// the body too (the coPlantBody cases) get it added there as well, which is what makes the value
// REPORTED for a part that is deliberately outside the scan path.
func buildDocx(t *testing.T, dir, where, value string) string {
	t.Helper()

	bodyText := "Quarterly staffing review."
	coPlant := where == "customxml" || where == "settings"
	if where == "body" || coPlant {
		bodyText = fmt.Sprintf("Quarterly staffing review. Employee SSN: %s", value)
	}

	var overrides, rels, extra strings.Builder
	addPart := func(name, contentType, relType, target, body string) {
		fmt.Fprintf(&overrides, `<Override PartName="/%s" ContentType="%s"/>`, name, contentType)
		if relType != "" {
			fmt.Fprintf(&rels, `<Relationship Id="rId%d" Type="%s/%s" Target="%s"/>`,
				100+rels.Len()%800, relT, relType, target)
		}
		extra.WriteString("\x00" + name + "\x00" + body)
	}

	const wml = "application/vnd.openxmlformats-officedocument.wordprocessingml"
	switch where {
	case "header":
		addPart("word/header1.xml", wml+".header+xml", "header", "header1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:hdr `+wNS+`>`+wordPara("Header SSN: "+value)+`</w:hdr>`)
	case "footer":
		addPart("word/footer1.xml", wml+".footer+xml", "footer", "footer1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:ftr `+wNS+`>`+wordPara("Footer SSN: "+value)+`</w:ftr>`)
	case "comments":
		addPart("word/comments.xml", wml+".comments+xml", "comments", "comments.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:comments `+wNS+`><w:comment w:id="1" w:author="Reviewer">`+
				wordPara("Reviewer note SSN: "+value)+`</w:comment></w:comments>`)
	case "footnotes":
		addPart("word/footnotes.xml", wml+".footnotes+xml", "footnotes", "footnotes.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:footnotes `+wNS+`><w:footnote w:id="1">`+
				wordPara("Footnote SSN: "+value)+`</w:footnote></w:footnotes>`)
	case "endnotes":
		addPart("word/endnotes.xml", wml+".endnotes+xml", "endnotes", "endnotes.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:endnotes `+wNS+`><w:endnote w:id="1">`+
				wordPara("Endnote SSN: "+value)+`</w:endnote></w:endnotes>`)
	case "customxml":
		addPart("customXml/item1.xml", "application/xml", "customXml", "../customXml/item1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><Root><EmployeeRef>`+value+`</EmployeeRef></Root>`)
	case "settings":
		addPart("word/settings.xml", wml+".settings+xml", "settings", "settings.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:settings `+wNS+
				`><w:zoom w:percent="100"/><w:proofState w:spelling="clean"/><w:note>`+value+`</w:note></w:settings>`)
	case "charts":
		addPart("word/charts/chart1.xml", "application/vnd.openxmlformats-officedocument.drawingml.chart+xml",
			"chart", "charts/chart1.xml", chartPartXML(value))
	case "people":
		// Comment author display names. The value is in an ATTRIBUTE, which is why a character-data
		// pass saw nothing here.
		addPart("word/people.xml", wml+".people+xml", "people", "people.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w15:people xmlns:w15="http://schemas.microsoft.com/office/word/2012/wordml">`+
				`<w15:person w15:author="`+value+`"><w15:presenceInfo w15:providerId="None" w15:userId="`+value+`"/></w15:person></w15:people>`)
	case "diagrams":
		addPart("word/diagrams/data1.xml", "application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml",
			"diagramData", "diagrams/data1.xml", diagramPartXML(value))
	case "glossary":
		addPart("word/glossary/document.xml", wml+".document.glossary+xml", "glossaryDocument",
			"glossary/document.xml",
			`<?xml version="1.0" encoding="UTF-8"?><w:glossaryDocument `+wNS+`><w:docParts><w:docPart><w:docPartBody>`+
				wordPara("Saved building block SSN: "+value)+`</w:docPartBody></w:docPart></w:docParts></w:glossaryDocument>`)
	case "link":
		// An EXTERNAL relationship, which is how a hyperlink target is stored. No content-type
		// override: a .rels part is located by convention, and TargetMode="External" means the
		// target is not a part at all — which is precisely why nothing read it.
		fmt.Fprintf(&rels, `<Relationship Id="rIdLink" Type="%s/hyperlink" Target="https://intranet.invalid/employee/%s" TargetMode="External"/>`, relT, value)
	}

	documentXML := `<?xml version="1.0" encoding="UTF-8"?><w:document ` + wNS + `><w:body>` +
		wordPara(bodyText) + `</w:body></w:document>`

	docRels := `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` + rels.String() + `</Relationships>`
	contentTypes := `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="` + wml + `.document.main+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		overrides.String() + `</Types>`

	members := [][2]string{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rId1" Type="` + relT + `/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"word/document.xml", documentXML},
		{"word/_rels/document.xml.rels", docRels},
		{"docProps/core.xml", corePropsXML()},
	}
	members = append(members, splitExtraParts(extra.String())...)
	return writeContainer(t, filepath.Join(dir, "contract.docx"), members)
}

// buildXlsx builds a .xlsx whose `where` part holds value.
func buildXlsx(t *testing.T, dir, where, value string) string {
	t.Helper()

	cell := "Quarterly staffing review"
	if where == "cell" {
		cell = "Employee SSN: " + value
	}

	sheet := `<?xml version="1.0" encoding="UTF-8"?><worksheet ` + sNS +
		`><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>` + cell + `</t></is></c></row></sheetData></worksheet>`

	var overrides, sheetRels, wbRels, extra strings.Builder
	addWbPart := func(name, contentType, relType, target, body string) {
		fmt.Fprintf(&overrides, `<Override PartName="/%s" ContentType="%s"/>`, name, contentType)
		fmt.Fprintf(&wbRels, `<Relationship Id="rId%d" Type="%s/%s" Target="%s"/>`,
			200+wbRels.Len()%700, relT, relType, target)
		extra.WriteString("\x00" + name + "\x00" + body)
	}
	switch where {
	case "tables":
		// Column headings a user typed, held in a `name` ATTRIBUTE.
		addWbPart("xl/tables/table1.xml",
			"application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml", "table",
			"tables/table1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><table `+sNS+` id="1" displayName="Roster" ref="A1:B2">`+
				`<tableColumns count="1"><tableColumn id="1" name="`+value+`"/></tableColumns></table>`)
	case "charts":
		addWbPart("xl/charts/chart1.xml",
			"application/vnd.openxmlformats-officedocument.drawingml.chart+xml", "chart",
			"charts/chart1.xml", chartPartXML(value))
	}
	if where == "comments" {
		fmt.Fprintf(&overrides, `<Override PartName="/xl/comments1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml"/>`)
		fmt.Fprintf(&sheetRels, `<Relationship Id="rIdC" Type="%s/comments" Target="../comments1.xml"/>`, relT)
		extra.WriteString("\x00xl/comments1.xml\x00" +
			`<?xml version="1.0" encoding="UTF-8"?><comments ` + sNS +
			`><authors><author>Reviewer</author></authors><commentList><comment ref="A1" authorId="0"><text><t>Comment SSN: ` +
			value + `</t></text></comment></commentList></comments>`)
	}

	contentTypes := `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
		`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		overrides.String() + `</Types>`

	members := [][2]string{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rId1" Type="` + relT + `/officeDocument" Target="xl/workbook.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8"?><workbook ` + sNS +
			` xmlns:r="` + relT + `"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rId1" Type="` + relT + `/worksheet" Target="worksheets/sheet1.xml"/>` +
			wbRels.String() + `</Relationships>`},
		{"xl/worksheets/sheet1.xml", sheet},
		{"xl/worksheets/_rels/sheet1.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			sheetRels.String() + `</Relationships>`},
		{"docProps/core.xml", corePropsXML()},
	}
	members = append(members, splitExtraParts(extra.String())...)
	return writeContainer(t, filepath.Join(dir, "contract.xlsx"), members)
}

// buildPptx builds a .pptx whose `where` part holds value.
func buildPptx(t *testing.T, dir, where, value string) string {
	t.Helper()

	slideText := "Quarterly staffing review"
	if where == "slide" || where == "notes-and-slide" {
		slideText = "Employee SSN: " + value
	}
	notesText := "Remember to circulate the deck."
	if where == "notes" || where == "notes-and-slide" {
		notesText = "Speaker note SSN: " + value
	}

	shape := func(text string) string {
		return `<p:sp><p:txBody><a:bodyPr/><a:p><a:r><a:t>` + text + `</a:t></a:r></a:p></p:txBody></p:sp>`
	}
	slide := `<?xml version="1.0" encoding="UTF-8"?><p:sld ` + pNS + ` ` + aNS +
		`><p:cSld><p:spTree>` + shape(slideText) + `</p:spTree></p:cSld></p:sld>`
	notes := `<?xml version="1.0" encoding="UTF-8"?><p:notes ` + pNS + ` ` + aNS +
		`><p:cSld><p:spTree>` + shape(notesText) + `</p:spTree></p:cSld></p:notes>`

	// Parts reached from the PRESENTATION's relationships: comments, tags, authors and diagrams.
	var pOverrides, pRels, pExtra strings.Builder
	addPresPart := func(name, contentType, relType, target, body string) {
		fmt.Fprintf(&pOverrides, `<Override PartName="/%s" ContentType="%s"/>`, name, contentType)
		fmt.Fprintf(&pRels, `<Relationship Id="rId%d" Type="%s" Target="%s"/>`,
			300+pRels.Len()%600, relType, target)
		pExtra.WriteString("\x00" + name + "\x00" + body)
	}
	// presentationExtra is spliced INTO ppt/presentation.xml, for the row that plants there.
	presentationExtra := ""

	const pml = "application/vnd.openxmlformats-officedocument.presentationml"
	const msRel = "http://schemas.microsoft.com/office/powerpoint/2018/10/relationships"
	switch where {
	case "modern-comments":
		addPresPart("ppt/comments/modernComment_1_1.xml", "application/vnd.ms-powerpoint.comments+xml",
			msRel+"/comments", "comments/modernComment_1_1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><p188:cmLst xmlns:p188="http://schemas.microsoft.com/office/powerpoint/2018/8/main" `+
				aNS+`><p188:cm><p188:txBody><a:bodyPr/><a:p><a:r><a:t>Review note SSN: `+value+`</a:t></a:r></a:p></p188:txBody></p188:cm></p188:cmLst>`)
	case "tags":
		// The value is in a `val` ATTRIBUTE: no character data at all in this part.
		addPresPart("ppt/tags/tag1.xml", pml+".tags+xml", relT+"/tags", "tags/tag1.xml",
			`<?xml version="1.0" encoding="UTF-8"?><p:tagLst `+pNS+`><p:tag name="OWNER" val="`+value+`"/></p:tagLst>`)
	case "authors":
		addPresPart("ppt/authors.xml", "application/vnd.ms-powerpoint.authors+xml",
			msRel+"/authors", "authors.xml",
			`<?xml version="1.0" encoding="UTF-8"?><p188:authorLst xmlns:p188="http://schemas.microsoft.com/office/powerpoint/2018/8/main">`+
				`<p188:author id="{1}" name="`+value+`" initials="R" userId="x" providerId="None"/></p188:authorLst>`)
	case "comment-authors":
		addPresPart("ppt/commentAuthors.xml", pml+".commentAuthors+xml",
			relT+"/commentAuthors", "commentAuthors.xml",
			`<?xml version="1.0" encoding="UTF-8"?><p:cmAuthorLst `+pNS+`><p:cmAuthor id="1" name="`+value+`" initials="R" lastIdx="1" clrIdx="0"/></p:cmAuthorLst>`)
	case "diagrams":
		addPresPart("ppt/diagrams/data1.xml",
			"application/vnd.openxmlformats-officedocument.drawingml.diagramData+xml",
			relT+"/diagramData", "diagrams/data1.xml", diagramPartXML(value))
	case "presentation":
		// Presentation-level text. This part was already resolved to follow its relationships, which
		// is exactly why nobody noticed its own text was never read.
		presentationExtra = `<p:custShowLst><p:custShow name="Deck for ` + value + `" id="1"><p:sldLst/></p:custShow></p:custShowLst>`
	}

	contentTypes := `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/ppt/presentation.xml" ContentType="` + pml + `.presentation.main+xml"/>` +
		`<Override PartName="/ppt/slides/slide1.xml" ContentType="` + pml + `.slide+xml"/>` +
		`<Override PartName="/ppt/notesSlides/notesSlide1.xml" ContentType="` + pml + `.notesSlide+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		pOverrides.String() + `</Types>`

	members := [][2]string{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rId1" Type="` + relT + `/officeDocument" Target="ppt/presentation.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"ppt/presentation.xml", `<?xml version="1.0" encoding="UTF-8"?><p:presentation ` + pNS +
			` xmlns:r="` + relT + `"><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst>` +
			presentationExtra + `</p:presentation>`},
		{"ppt/_rels/presentation.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rId1" Type="` + relT + `/slide" Target="slides/slide1.xml"/>` +
			pRels.String() + `</Relationships>`},
		{"ppt/slides/slide1.xml", slide},
		// The notes part is reached from the SLIDE's relationships, which is how a real package
		// links it — the extractor resolves it that way rather than guessing by index.
		{"ppt/slides/_rels/slide1.xml.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships ` + relNS + `>` +
			`<Relationship Id="rIdN" Type="` + relT + `/notesSlide" Target="../notesSlides/notesSlide1.xml"/></Relationships>`},
		{"ppt/notesSlides/notesSlide1.xml", notes},
		{"docProps/core.xml", corePropsXML()},
	}
	members = append(members, splitExtraParts(pExtra.String())...)
	return writeContainer(t, filepath.Join(dir, "contract.pptx"), members)
}

// chartPartXML is a chart part as a producer writes one: an authored title, plus the numeric cache of
// the values plotted.
//
// The cache is deliberately present and deliberately full of PII-shaped numbers. Reading it was
// measured on 452 real containers and produced a 17-digit datum as VIN at confidence 90, 10-digit
// ids as PHONE and 9-digit ids as SSN — so a fixture without it would let that regression back in
// while every row still passed.
func chartPartXML(value string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><c:chartSpace ` +
		`xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" ` + aNS + `>` +
		`<c:title><c:tx><c:rich><a:bodyPr/><a:p><a:r><a:t>Chart SSN: ` + value + `</a:t></a:r></a:p></c:rich></c:tx></c:title>` +
		`<c:plotArea><c:barChart><c:ser><c:val><c:numRef><c:numCache>` +
		`<c:pt idx="0"><c:v>78260869565217395</c:v></c:pt>` +
		`<c:pt idx="1"><c:v>870366751</c:v></c:pt>` +
		`</c:numCache></c:numRef></c:val></c:ser>` +
		`<c:axId val="1829252287"/><c:axId val="1829256815"/></c:barChart></c:plotArea></c:chartSpace>`
}

// diagramPartXML is a SmartArt data part — an org chart is a diagram full of names.
func diagramPartXML(value string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><dgm:dataModel ` +
		`xmlns:dgm="http://schemas.openxmlformats.org/drawingml/2006/diagram" ` + aNS + `>` +
		`<dgm:ptLst><dgm:pt modelId="1"><dgm:t><a:bodyPr/><a:p><a:r><a:t>Diagram SSN: ` + value +
		`</a:t></a:r></a:p></dgm:t></dgm:pt></dgm:ptLst></dgm:dataModel>`
}

func corePropsXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties ` +
		`xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Contract fixture</dc:title></cp:coreProperties>`
}

// splitExtraParts decodes the NUL-delimited (name, body) pairs the builders accumulate.
//
// A small encoding rather than passing a slice around, so each `case` in the switch above stays a
// single call and the part it adds is visible on one line.
func splitExtraParts(encoded string) [][2]string {
	if encoded == "" {
		return nil
	}
	fields := strings.Split(strings.TrimPrefix(encoded, "\x00"), "\x00")
	var out [][2]string
	for i := 0; i+1 < len(fields); i += 2 {
		out = append(out, [2]string{fields[i], fields[i+1]})
	}
	return out
}

// xmlWellFormed reports whether data parses as XML end to end.
func xmlWellFormed(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
