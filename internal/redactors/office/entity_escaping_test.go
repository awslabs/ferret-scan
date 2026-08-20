// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Office redaction used to string-match the DECODED value against the RAW part
// bytes, so any value whose stored spelling differed from its decoded form was
// never found — while RedactDocument still returned success.
//
// extractTextFromXML reads part text through encoding/xml, so the value the report
// names is "Fairbanks & Kettleworth", never the "Fairbanks &amp; Kettleworth" that
// is on disk. Measured before the fix, on a .docx whose Company property held an
// ampersand: --enable-redaction exited 0, the audit log recorded
// successful_redactions:4 / failed_redactions:0, and exiftool read the company name
// straight out of the "redacted" copy.
//
// This needs no attacker. XML REQUIRES '&' in character data to be written "&amp;".
//
// The numeric forms generalise it: '&' also introduces character references, so any
// character at any offset can be respelled. "449-87-41&#48;0", "&#52;49-87-4100" and
// the &#x30; hex form are all the same value, which is why enumerating escaped
// spellings as extra replacer keys cannot close this and canonicalising through the
// codec can.

// decodedCharData returns the concatenated, entity-DECODED character data of a part
// inside an OOXML package.
//
// Decoding is the whole point: asserting on the raw bytes is what let this defect
// ship. Grepping the .docx itself is worse still — that searches COMPRESSED bytes
// and always "finds nothing".
func decodedCharData(t *testing.T, pkg []byte, part string) string {
	t.Helper()

	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatalf("opening package: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != part {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening %s: %v", part, err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("reading %s: %v", part, err)
		}

		var sb strings.Builder
		dec := xml.NewDecoder(bytes.NewReader(raw))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("%s is not well-formed XML after redaction: %v", part, err)
			}
			if cd, ok := tok.(xml.CharData); ok {
				sb.Write(cd)
			}
		}
		return sb.String()
	}
	t.Fatalf("part %s not found in package", part)
	return ""
}

// TestEscapedValueIsRedacted is the regression gate. Every case fails before the
// fix, because the stored spelling of the value never occurs literally in the part.
func TestEscapedValueIsRedacted(t *testing.T) {
	cases := []struct {
		name string
		// stored is written verbatim into <w:t>, i.e. the on-disk spelling.
		stored string
		// reported is what the validators see and what the report names, i.e. the
		// decoded form. RedactDocument is given this, exactly as the scanner gives it.
		reported string
		typ      string
	}{
		{
			name:     "predefined entity amp inside the value",
			stored:   "Company: Fairbanks &amp; Kettleworth Holdings",
			reported: "Fairbanks & Kettleworth Holdings",
			typ:      "COMPANY_INFO",
		},
		{
			name:     "predefined entity apos inside the value",
			stored:   "Patient name: Patrick O&apos;Connor",
			reported: "Patrick O'Connor",
			typ:      "PERSON_NAME",
		},
		{
			name:     "decimal character reference mid-value",
			stored:   "Employee SSN: 449-87-41&#48;0 on file",
			reported: "449-87-4100",
			typ:      "SSN",
		},
		{
			name:     "hex character reference mid-value",
			stored:   "Employee SSN: 449-87-41&#x30;0 on file",
			reported: "449-87-4100",
			typ:      "SSN",
		},
		{
			name:     "character reference at the first byte of the value",
			stored:   "Employee SSN: &#52;49-87-4100 on file",
			reported: "449-87-4100",
			typ:      "SSN",
		},
		{
			name:     "every separator respelled",
			stored:   "Employee SSN: 449&#45;87&#45;4100 on file",
			reported: "449-87-4100",
			typ:      "SSN",
		},
		{
			name:     "lt and gt around the value",
			stored:   "Owner &lt;Fairbanks &amp; Kettleworth Holdings&gt; noted",
			reported: "Fairbanks & Kettleworth Holdings",
			typ:      "COMPANY_INFO",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "in.docx")
			if err := os.WriteFile(src, buildPkg(t, tc.stored, nil), 0o600); err != nil {
				t.Fatalf("writing fixture: %v", err)
			}

			out := filepath.Join(dir, "out.docx")
			matches := []detector.Match{{
				Text: tc.reported, Type: tc.typ, Confidence: 100, LineNumber: 1,
				Context: detector.ContextInfo{FullLine: tc.stored},
			}}
			r := NewOfficeRedactor(nil, nil)
			if _, err := r.RedactDocument(src, out, matches, redactors.RedactionSimple); err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}

			pkg, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("reading output: %v", err)
			}
			got := decodedCharData(t, pkg, "word/document.xml")

			if strings.Contains(got, tc.reported) {
				t.Errorf("the reported value survived redaction.\n  stored on disk: %s\n  reported as:    %s\n  decoded output: %s\n"+
					"Only reported findings are redacted, so this value is left in cleartext in a file the tool called successfully redacted.",
					tc.stored, tc.reported, got)
			}
		})
	}
}

// The rewrite must not damage anything it was not asked to change: the part stays
// well-formed, unmatched text survives, and a value with no entities is unaffected.
//
// Without this, "redact everything" would pass the test above.
func TestRewritePreservesTheRestOfThePart(t *testing.T) {
	const stored = "Keep this prose. Company: Fairbanks &amp; Kettleworth Holdings. Keep this too."
	const reported = "Fairbanks & Kettleworth Holdings"

	dir := t.TempDir()
	src := filepath.Join(dir, "in.docx")
	if err := os.WriteFile(src, buildPkg(t, stored, nil), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	out := filepath.Join(dir, "out.docx")
	r := NewOfficeRedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, []detector.Match{{
		Text: reported, Type: "COMPANY_INFO", Confidence: 100, LineNumber: 1,
	}}, redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	pkg, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	// decodedCharData fails the test if the part is no longer well-formed.
	got := decodedCharData(t, pkg, "word/document.xml")

	for _, keep := range []string{"Keep this prose.", "Keep this too."} {
		if !strings.Contains(got, keep) {
			t.Errorf("surrounding text %q was lost; decoded output: %s", keep, got)
		}
	}
	if strings.Contains(got, reported) {
		t.Errorf("the value was not redacted; decoded output: %s", got)
	}
}

// rewritePartText is exercised directly for the properties the end-to-end tests
// cannot reach.
func TestRewritePartText(t *testing.T) {
	t.Run("a value in an ATTRIBUTE is still replaced", func(t *testing.T) {
		// Attribute values are not character data. A CharData-only rewrite would
		// silently stop redacting these, turning a leak fix into a new leak — so the
		// bytes outside character data keep going through the raw replacer.
		in := []byte(`<r><p w:val="449-87-4100"/><t>nothing here</t></r>`)
		got, _ := rewritePartText(in, strings.NewReplacer("449-87-4100", "***-**-4100"))
		if strings.Contains(string(got), "449-87-4100") {
			t.Errorf("attribute-resident value survived: %s", got)
		}
	})

	t.Run("a part encoding/xml refuses falls back to the raw replacer", func(t *testing.T) {
		// "&foo;" is an undefined entity and the tokenizer errors on it. The previous
		// behaviour must be preserved rather than the document failing.
		in := []byte(`<t>449-87-4100 and &foo; trailing</t>`)
		got, rewrites := rewritePartText(in, strings.NewReplacer("449-87-4100", "***-**-4100"))
		if strings.Contains(string(got), "449-87-4100") {
			t.Errorf("value survived in an untokenizable part: %s", got)
		}
		if rewrites != 0 {
			t.Errorf("rewrites = %d, want 0 — the decoded path cannot run on a part that does not tokenize", rewrites)
		}
	})

	t.Run("no match means byte-identical output", func(t *testing.T) {
		in := []byte(`<t>Fairbanks &amp; Kettleworth</t>`)
		got, rewrites := rewritePartText(in, strings.NewReplacer("449-87-4100", "***-**-4100"))
		if !bytes.Equal(got, in) {
			t.Errorf("part was rewritten with no match to make.\n got: %s\nwant: %s", got, in)
		}
		if rewrites != 0 {
			t.Errorf("rewrites = %d, want 0", rewrites)
		}
	})
}

// escapeCharData must escape '&' unconditionally. A decoded value can contain an
// ampersand followed by entity-looking text — "&amp;lt;" decodes to the literal
// "&lt;" — so an escaper that skipped '&' before a known entity name would corrupt
// that value on the way out, and the corruption would only appear in documents that
// were redacted.
func TestEscapeCharDataRoundTrips(t *testing.T) {
	for _, s := range []string{
		"plain text",
		"Fairbanks & Kettleworth",
		"&lt;",  // a LITERAL ampersand followed by "lt;"
		"&amp;", // a literal ampersand followed by "amp;"
		"a < b > c",
		"&&&",
		"O'Connor \"quoted\"",
		"line\nbreak\ttab",
	} {
		var buf bytes.Buffer
		escapeCharData(&buf, s)

		var back strings.Builder
		dec := xml.NewDecoder(strings.NewReader("<t>" + buf.String() + "</t>"))
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("escapeCharData(%q) produced %q, which is not well-formed: %v", s, buf.String(), err)
			}
			if cd, ok := tok.(xml.CharData); ok {
				back.Write(cd)
			}
		}
		if back.String() != s {
			t.Errorf("round trip lost data: %q -> %q -> %q", s, buf.String(), back.String())
		}
	}
}
