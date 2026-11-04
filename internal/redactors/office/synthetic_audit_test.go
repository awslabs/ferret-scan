// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #886 case C: under synthetic, a .docx wrote one fake per value but its audit log reported a
// separate per-match draw, so 3 of 8 redacted_text values occurred in the file. Synthetic values only.

const (
	auditSSN   = "234-56-0001"
	auditEmail = "dana.whitfield@example.org"
	auditPhone = "312-555-0142"
)

// writeParts writes a .docx holding the given parts verbatim, plus the package scaffolding.
func writeParts(t *testing.T, path string, parts map[string]string) {
	t.Helper()
	const w = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`
	ct := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`
	if _, ok := parts["word/header1.xml"]; ok {
		ct += `<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>`
	}
	ct += `</Types>`
	all := map[string]string{
		"[Content_Types].xml": ct,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
	}
	for name, body := range parts {
		all[name] = strings.ReplaceAll(body, "W_NS", w)
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		f, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(all[n])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func para(runs ...string) string {
	var b strings.Builder
	b.WriteString("<w:p>")
	for _, r := range runs {
		b.WriteString(`<w:r><w:t xml:space="preserve">` + r + `</w:t></w:r>`)
	}
	b.WriteString("</w:p>")
	return b.String()
}

var wtRE = regexp.MustCompile(`<w:t[^>]*>([^<]*)</w:t>`)

// writtenText is the text of every word/*.xml part, runs joined, the way the issue's audit_check reads it.
func writtenText(t *testing.T, path string) string {
	t.Helper()
	parts := readPartsInsideZip(t, path)
	names := make([]string, 0, len(parts))
	for n := range parts {
		if strings.HasPrefix(n, "word/") && strings.HasSuffix(n, ".xml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		for _, m := range wtRE.FindAllStringSubmatch(string(parts[n]), -1) {
			b.WriteString(m[1])
		}
	}
	return b.String()
}

func scopedOffice() *OfficeRedactor {
	r := NewOfficeRedactor(nil, nil)
	r.SetSyntheticScope(redactors.NewSyntheticScope())
	return r
}

func m886(typ, text string, line int) detector.Match {
	return detector.Match{Type: typ, Text: text, Confidence: 90, LineNumber: line, Validator: strings.ToLower(typ)}
}

// Every redacted_text is in the file, and the SSN is one value in the body and the header.
func TestTheAuditRecordsTheReplacementWritten(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "rec.docx"), filepath.Join(dir, "out.docx")
	writeParts(t, in, map[string]string{
		"word/_rels/document.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/></Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document W_NS><w:body>` +
			para("Employee SSN: "+auditSSN) + para("Contact "+auditEmail+" or "+auditPhone) + para("Confirmed again SSN: "+auditSSN) +
			para("Twice on one line SSN "+auditSSN+" and SSN "+auditSSN) + para("Reach "+auditEmail+" any time") +
			`<w:sectPr><w:headerReference w:type="default" r:id="rId9"/></w:sectPr></w:body></w:document>`,
		"word/header1.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr W_NS>` + para("Header SSN: "+auditSSN) + `</w:hdr>`,
	})
	ms := []detector.Match{
		m886("SSN", auditSSN, 1), m886("BUSINESS", auditEmail, 2), m886("PHONE", auditPhone, 2), m886("SSN", auditSSN, 3),
		m886("SSN", auditSSN, 4), m886("SSN", auditSSN, 4), m886("BUSINESS", auditEmail, 5), m886("SSN", auditSSN, 6),
	}
	res, err := scopedOffice().RedactDocument(in, out, ms, redactors.RedactionSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	text := writtenText(t, out)
	for _, v := range []string{auditSSN, auditEmail, auditPhone} {
		if strings.Contains(text, v) {
			t.Fatalf("%s survived:\n%s", v, text)
		}
	}
	ssns := regexp.MustCompile(`\d{3}-\d{2}-\d{4}`).FindAllString(text, -1)
	if len(ssns) != 5 {
		t.Fatalf("%d SSN-shaped values written, want 5: %v", len(ssns), ssns)
	}
	for _, s := range ssns {
		if s != ssns[0] {
			t.Errorf("one SSN was written as %v", ssns)
			break
		}
	}
	if len(res.RedactionMap) == 0 {
		t.Fatal("no audit mapping")
	}
	present := 0
	for _, mp := range res.RedactionMap {
		if strings.Contains(text, mp.RedactedText) {
			present++
		} else {
			t.Errorf("the audit records %s -> %q, which the file does not contain", mp.DataType, mp.RedactedText)
		}
	}
	t.Logf("%d of %d redacted_text present in the written parts", present, len(res.RedactionMap))
}

// One text reported as two types on two lines is two values to the scope, but Office replaces by text:
// the part is written with the first unit's replacement, and the second unit's audit entry must say so
// rather than name its own draw, which the file never received.
func TestTheAuditOfASharedTextIsTheReplacementWritten(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "two.docx"), filepath.Join(dir, "out.docx")
	writeParts(t, in, map[string]string{
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document W_NS><w:body>` +
			para("Passport 512010001") + para("Taxpayer 512010001") + `</w:body></w:document>`,
	})
	ms := []detector.Match{m886("PASSPORT", "512010001", 1), m886("SSN", "512010001", 2)}
	res, err := scopedOffice().RedactDocument(in, out, ms, redactors.RedactionSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	text := writtenText(t, out)
	if strings.Contains(text, "512010001") {
		t.Fatalf("the value survived: %q", text)
	}
	if len(res.RedactionMap) != 2 {
		t.Fatalf("%d mappings, want 2", len(res.RedactionMap))
	}
	for _, mp := range res.RedactionMap {
		if !strings.Contains(text, mp.RedactedText) {
			t.Errorf("the audit records %s -> %q; the file holds %q", mp.DataType, mp.RedactedText, text)
		}
	}
}

// The split-run route reports what the cross-run rewrite wrote.
func TestTheAuditOfASplitValueIsTheReplacementWritten(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "split.docx"), filepath.Join(dir, "out.docx")
	writeParts(t, in, map[string]string{
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document W_NS><w:body>` +
			para("Employee SSN: 234-56", "-0001") + para("Nothing else here.") + `</w:body></w:document>`,
	})
	res, err := scopedOffice().RedactDocument(in, out, []detector.Match{m886("SSN", auditSSN, 1)}, redactors.RedactionSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	text := writtenText(t, out)
	if strings.Contains(text, auditSSN) {
		t.Fatalf("the split SSN survived: %q", text)
	}
	if len(res.RedactionMap) != 1 || !strings.Contains(text, res.RedactionMap[0].RedactedText) {
		t.Fatalf("audit %+v, written %q", res.RedactionMap, text)
	}
}

// writtenFor is the first write a part recorded for a value, whoever asks.
func TestWrittenForIsTheFirstRecordedReplacement(t *testing.T) {
	pending := map[string]*partReplacements{}
	pr := &partReplacements{}
	pending["word/document.xml"] = pr
	pr.add(auditSSN, "666-00-1111")
	pr.add(auditSSN, "999-00-2222") // a later unit with the same text: not what is written
	if got := writtenFor(pending, "word/document.xml", auditSSN, "999-00-2222"); got != "666-00-1111" {
		t.Errorf("writtenFor = %q, want the first recorded replacement", got)
	}
	if got := writtenFor(pending, "word/header1.xml", auditSSN, "fallback"); got != "fallback" {
		t.Errorf("writtenFor of an unrecorded part = %q", got)
	}
}
