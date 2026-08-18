// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// A value inside an EMBEDDED part must be redacted even when the finding that reported it
// is a consolidated cluster.
//
// RedactDocument has TWO consumers of Match.Text: redactOfficeContent, and
// redactEmbeddedParts. The cluster expansion and the bounded-text restore used to live
// INSIDE redactOfficeContent, which takes `matches` as a parameter — so reassigning it
// there normalized only that function's local slice, and RedactDocument then handed the
// ORIGINAL slice to redactEmbeddedParts.
//
// That second consumer builds the residue value set used by both the dispatch gate
// (embedded.go: `ResidueInspectable(child.name) && !partHoldsValue(child.content, values, 0)`)
// and the post-redaction verification. Fed a cluster, the set contains the cluster's
// RENDERED SUMMARY — a string present in no part's bytes — so partHoldsValue proved
// "absence" for every part, the part holding the real values was never dispatched, and the
// fail-closed unredacted-part refusal never fired because its own residue check was looking
// for the same absent string.
//
// Measured on the shipped binary, a .docx with two clustered handles in its body AND in an
// embedded inner.docx:
//
//	2 HIGH findings reported, rc=0, one file written
//	body:  handles removed
//	inner: BOTH handles still present verbatim
//
// A non-clustered SSN in the same fixture was correctly removed from the embedded copy,
// which is what isolates clustering as the cause. Found by an adversarial post-merge sweep;
// the #344 completeness table counted redactor ENTRY POINTS rather than consumers of
// Match.Text, and this is the fourth consumer.

// embeddedDocx builds a .docx whose body holds bodyText and which embeds inner at
// word/embeddings/inner.docx.
func embeddedDocx(t *testing.T, path string, bodyText string, inner []byte) {
	t.Helper()

	const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Default Extension="docx" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`</Relationships>`
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		bodyText + `</w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("[Content_Types].xml", ct)
	write("_rels/.rels", rels)
	write("word/document.xml", doc)
	if inner != nil {
		w, err := zw.Create("word/embeddings/inner.docx")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(inner); err != nil {
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

// innerDocx returns the bytes of a standalone .docx holding bodyText.
func innerDocx(t *testing.T, bodyText string) []byte {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "inner.docx")
	embeddedDocx(t, p, bodyText, nil)
	b, err := os.ReadFile(p) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// residueInEmbedded reports whether any value survives inside the embedded .docx of path.
func residueInEmbedded(t *testing.T, path string, values ...string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	out := map[string]bool{}
	for _, f := range zr.File {
		if filepath.Ext(f.Name) != ".docx" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		nested, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		// Inflate the NESTED package too: grepping its compressed bytes finds nothing
		// whether or not redaction worked, which is how this stayed invisible.
		nz, err := zip.NewReader(bytes.NewReader(nested), int64(len(nested)))
		if err != nil {
			t.Fatalf("embedded part is not a valid zip: %v", err)
		}
		for _, nf := range nz.File {
			nrc, err := nf.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(nrc)
			nrc.Close()
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range values {
				if bytes.Contains(body, []byte(v)) {
					out[v] = true
				}
			}
		}
	}
	return out
}

func TestClusteredValueInEmbeddedPartIsRedacted(t *testing.T) {
	const (
		twitter  = "https://twitter.com/janedoe"
		linkedin = "https://linkedin.com/in/janedoe"
	)
	body := `<w:p><w:r><w:t>Profile: ` + twitter + `</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>connect with me</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>And ` + linkedin + `</w:t></w:r></w:p>`

	dir := t.TempDir()
	src := filepath.Join(dir, "outer.docx")
	embeddedDocx(t, src, body, innerDocx(t, body))

	// The finding as clustering reports it: ONE synthesized match whose Text occurs
	// nowhere, carrying its constituent matches for the expansion to recover.
	members := []detector.Match{
		{Text: twitter, Type: "SOCIAL_MEDIA", LineNumber: 1, Confidence: 90,
			Context: detector.ContextInfo{FullLine: "Profile: " + twitter}},
		{Text: linkedin, Type: "SOCIAL_MEDIA", LineNumber: 3, Confidence: 90,
			Context: detector.ContextInfo{FullLine: "And " + linkedin}},
	}
	matches := []detector.Match{{
		Text:       "twitter: janedoe | linkedin: janedoe", // a rendered summary
		Type:       "SOCIAL_MEDIA_CLUSTER",
		LineNumber: 1,
		Confidence: 95,
		Context:    detector.ContextInfo{FullLine: "Profile: " + twitter},
		Metadata:   map[string]interface{}{redactors.ClusterMembersKey: members},
	}}

	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
		// A fail-closed refusal is an acceptable outcome; silently writing a leaking file
		// is not. Either way there must be no readable output holding the values.
		if _, statErr := os.Stat(out); statErr == nil {
			t.Fatalf("RedactDocument errored (%v) but still wrote %s", err, out)
		}
		return
	}
	if _, err := os.Stat(out); err != nil {
		return // refused to write: also safe
	}

	got := residueInEmbedded(t, out, twitter, linkedin)
	for _, v := range []string{twitter, linkedin} {
		if got[v] {
			t.Errorf("the EMBEDDED part still contains %q — the cluster was reported, so "+
				"redaction was asked to remove it, and the container was written at exit 0 "+
				"with the value in cleartext", v)
		}
	}
}

// The control: an ordinary, non-clustered match in the same shape must keep working. This is
// what isolates clustering as the cause rather than the embedded path being broken outright.
func TestNonClusteredValueInEmbeddedPartStillRedacted(t *testing.T) {
	const ssn = "452-11-8903"
	body := `<w:p><w:r><w:t>Employee SSN ` + ssn + ` on file.</w:t></w:r></w:p>`

	dir := t.TempDir()
	src := filepath.Join(dir, "outer.docx")
	embeddedDocx(t, src, body, innerDocx(t, body))

	matches := []detector.Match{{
		Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100,
		Context: detector.ContextInfo{FullLine: "Employee SSN " + ssn + " on file."},
	}}

	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	_, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple)

	// With no embedded-redaction dispatcher injected, refusing to write is the CORRECT
	// outcome and the one this redactor documents: nil means "do not descend", and a part
	// holding a reported value is then disclosed rather than passed over. The point of this
	// control is that the ORDINARY path reaches that decision — which is exactly what the
	// cluster case did not, because its residue check was looking for a string present in no
	// part and therefore concluded every part was clean.
	if err != nil {
		if _, statErr := os.Stat(out); statErr == nil {
			t.Fatalf("errored (%v) but still wrote %s", err, out)
		}
		return
	}
	if _, statErr := os.Stat(out); statErr != nil {
		return
	}
	if got := residueInEmbedded(t, out, ssn); got[ssn] {
		t.Errorf("a file was written and its embedded part still contains the SSN")
	}
}

// A bounded consolidated text has the same shape as a cluster: its Text does not occur in
// the document either, so the embedded gate must see the RESTORED full line.
func TestBoundedConsolidatedValueInEmbeddedPartIsRedacted(t *testing.T) {
	const secret = "Amazon Confidential and Trademark 452-11-8903"
	body := `<w:p><w:r><w:t>` + secret + `</w:t></w:r></w:p>`

	dir := t.TempDir()
	src := filepath.Join(dir, "outer.docx")
	embeddedDocx(t, src, body, innerDocx(t, body))

	matches := []detector.Match{{
		// The display form: truncated, so it occurs nowhere in the document.
		Text:       "Amazon Confidential [+218 more matches on line]",
		Type:       "INTELLECTUAL_PROPERTY",
		LineNumber: 1,
		Confidence: 90,
		Context:    detector.ContextInfo{FullLine: secret},
		Metadata:   map[string]interface{}{redactors.MatchTextTruncatedKey: true},
	}}

	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
		if _, statErr := os.Stat(out); statErr == nil {
			t.Fatalf("RedactDocument errored (%v) but still wrote %s", err, out)
		}
		return
	}
	if _, err := os.Stat(out); err != nil {
		return
	}
	if got := residueInEmbedded(t, out, secret); got[secret] {
		t.Errorf("the embedded part still contains the consolidated line — a bounded display " +
			"text reaches the embedded gate un-restored, same defect as the cluster case")
	}
}
