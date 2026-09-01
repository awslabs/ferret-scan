// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractsvgtextlib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
)

// #314: an .svg carrying PII in its <text> nodes was never scanned.
//
// The measurement that produced the exclusion, re-taken at a0e983c on a 64KB SVG built
// from integer-coordinate glyph paths (the shape real icon and font SVGs carry):
//
//	943 findings: PHONE 122 HIGH + 695 MEDIUM, CREDIT_CARD 45 MEDIUM + 5 LOW,
//	SSN 3 HIGH + 73 LOW  --  every one of them path coordinates
//
// and on a 7.2MB SVG whose geometry sits in one huge d= attribute, 400,001 findings in
// 19.9 seconds of wall time (80s CPU), the one true SSN among them.
//
// So the flood is real. What was wrong was the response: excluding the part. Measured on
// the same drawing carrying an SSN, an email, a name and a phone in <text>/<title>/<desc>,
// 4 findings standalone and 0 embedded in a .docx -- exit 0, nothing on stderr, exit 0
// again under --fail-on-incomplete, and no redacted copy written at all.
//
// This file pins the rule that lets both be true at once: only prose is collected, so
// the digits that caused the flood are never handed to a validator. After: the 64KB
// glyph SVG reports 0 findings, the 7.2MB one reports 1 in 0.08s, and the
// <text>-carrying drawing reports its 4.

// svgProbe wraps ExtractFromBytes for a table entry.
func svgProbe(t *testing.T, body string) *TextContent {
	t.Helper()
	c, err := ExtractFromBytes("probe.svg", []byte(body))
	if err != nil {
		t.Fatalf("ExtractFromBytes returned an error on well-formed input: %v", err)
	}
	if c == nil {
		t.Fatal("ExtractFromBytes returned nil content with no error")
	}
	return c
}

// TestProseIsCollected covers each element and attribute the allowlist admits.
//
// The `want` strings are what a validator must be able to see; `notWant` is what must
// never reach one. Both halves are asserted for every case, because a rule that
// collects everything passes the first half alone.
func TestProseIsCollected(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    []string
		notWant []string
	}{
		{
			name: "text element",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><text x="5" y="20">Employee SSN: 452-11-9384</text></svg>`,
			want: []string{"Employee SSN: 452-11-9384"},
			// x and y are coordinates and must not be emitted even though they are tiny.
			notWant: []string{"\n5\n", "\n20\n"},
		},
		{
			name:    "tspan inside text",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><text>Desk <tspan>+1 (202) 555-0143</tspan></text></svg>`,
			want:    []string{"+1 (202) 555-0143"},
			notWant: nil,
		},
		{
			name:    "title and desc",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><title>Owner Renee Vasquez</title><desc>renee@examplecorp.com</desc></svg>`,
			want:    []string{"Owner Renee Vasquez", "renee@examplecorp.com"},
			notWant: nil,
		},
		{
			name:    "textPath is camelCase in the spec",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><text><textPath href="#p">SSN 452-11-9384</textPath></text></svg>`,
			want:    []string{"SSN 452-11-9384"},
			notWant: []string{"#p"},
		},
		{
			name:    "metadata RDF",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><metadata><rdf><dc:creator>Renee Vasquez</dc:creator></rdf></metadata></svg>`,
			want:    []string{"Renee Vasquez"},
			notWant: nil,
		},
		{
			name:    "inkscape flowed text",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><flowRoot><flowPara>SSN 452-11-9384</flowPara></flowRoot></svg>`,
			want:    []string{"SSN 452-11-9384"},
			notWant: nil,
		},
		{
			name:    "namespace-prefixed element",
			body:    `<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:text>SSN 452-11-9384</svg:text></svg:svg>`,
			want:    []string{"SSN 452-11-9384"},
			notWant: nil,
		},
		{
			name:    "aria-label on a group",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><g aria-label="Owner Renee Vasquez"><path d="M863 76 1012 109"/></g></svg>`,
			want:    []string{"Owner Renee Vasquez"},
			notWant: []string{"863 76 1012"},
		},
		{
			name:    "xlink:title matches the local name",
			body:    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:title="renee@examplecorp.com"><rect/></a></svg>`,
			want:    []string{"renee@examplecorp.com"},
			notWant: nil,
		},
		{
			name:    "inkscape:label",
			body:    `<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="x"><g inkscape:label="Renee Vasquez layer"/></svg>`,
			want:    []string{"Renee Vasquez layer"},
			notWant: nil,
		},
		{
			name:    "foreignObject XHTML subtree",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div><p>Employee SSN: 452-11-9384</p></div></foreignObject></svg>`,
			want:    []string{"Employee SSN: 452-11-9384"},
			notWant: nil,
		},
		{
			name:    "XML comment",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><!-- TODO ask renee@examplecorp.com --><path d="M863 76 1012 109"/></svg>`,
			want:    []string{"renee@examplecorp.com"},
			notWant: []string{"863 76 1012"},
		},
		{
			name: "multi-line desc is folded onto one line",
			// A value split across output lines is a value no validator can match, and
			// SVG markup is indented, so this is the common case rather than a corner.
			body: "<svg xmlns=\"http://www.w3.org/2000/svg\"><desc>\n    Employee\n    SSN: 452-11-9384\n  </desc></svg>",
			want: []string{"Employee SSN: 452-11-9384"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := svgProbe(t, tc.body)
			// NON-VACUITY: assert something was extracted before asserting about it.
			// A rule that extracts nothing passes every notWant check.
			if c.Nodes == 0 || strings.TrimSpace(c.Text) == "" {
				t.Fatalf("nothing was extracted (nodes=%d, text=%q), so the assertions below prove nothing",
					c.Nodes, c.Text)
			}
			for _, w := range tc.want {
				if !strings.Contains(c.Text, w) {
					t.Errorf("prose %q was not extracted.\ngot:\n%s", w, c.Text)
				}
			}
			for _, n := range tc.notWant {
				if strings.Contains(c.Text, n) {
					t.Errorf("geometry %q reached the extracted text; only prose may.\ngot:\n%s", n, c.Text)
				}
			}
		})
	}
}

// TestGeometryIsNeverCollected is the flood half, and it is the point of the package.
//
// Each body carries the shape that was MEASURED producing false positives at a0e983c.
// The assertion is that the extracted text is empty: not "the validator rejects it"
// but "no validator is ever shown it", which is what makes the result independent of
// every validator's numeric patterns.
func TestGeometryIsNeverCollected(t *testing.T) {
	cases := []struct {
		name string
		body string
		// fp is the substring measured to produce a finding when scanned as text.
		fp string
	}{
		{
			// "0 863 76 1012 109", lifted from a real glyph path in a 20KB icon:
			// one SSN HIGH 100 on its own at a0e983c.
			name: "integer glyph path d=",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><path d="m24 136-191v-63h-136zm587-260v401c0 41-2 82-5 122h-1845c66-84 102-188 102-296 0-98-30-189-80-266 228-32 530-68 778-70h38c465 0 863 76 1012 109"/></svg>`,
			fp:   "863 76 1012",
		},
		{
			name: "polygon points=",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><polygon points="784 474 1269 8.25 75.75"/></svg>`,
			fp:   "784 474 1269",
		},
		{
			// The base64 of an embedded raster: measured VIN MEDIUM 75 on a real file.
			name: "xlink:href data URI",
			body: `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="data:image/png;base64,X5VGY3pL7gmlVe1Yr"/></svg>`,
			fp:   "X5VGY3pL7gmlVe1Yr",
		},
		{
			name: "transform and viewBox",
			body: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 465.73919 466.54269"><g transform="matrix(1.3333 0 0 -1.3333 97.411 1153.7)"/></svg>`,
			fp:   "465.73919",
		},
		{
			// CSS, including an @font-face base64 payload: machine text with the shape
			// of a credential.
			name: "style element CSS",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><style>.a{fill:#0d1117}@font-face{src:url(data:font/woff;base64,AKIAIOSFODNN7EXAMPLE)}</style></svg>`,
			fp:   "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name: "script element",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><script>var k="AKIAIOSFODNN7EXAMPLE";</script></svg>`,
			fp:   "AKIAIOSFODNN7EXAMPLE",
		},
		{
			// A <path> has no character data in a well-formed document, so the
			// allowlist has to drop the malformed case too.
			name: "chardata inside path",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><path>0 863 76 1012 109</path></svg>`,
			fp:   "863 76 1012",
		},
		{
			// The one denylist entry, in the inverted polarity: inside a foreign
			// subtree the default is to collect, so <style> there needs its own rule.
			name: "style inside foreignObject",
			body: `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><style>a{content:"AKIAIOSFODNN7EXAMPLE"}</style></foreignObject></svg>`,
			fp:   "AKIAIOSFODNN7EXAMPLE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ExtractFromBytes("probe.svg", []byte(tc.body))
			if err != nil {
				t.Fatalf("extraction errored on well-formed geometry: %v", err)
			}
			if strings.Contains(c.Text, tc.fp) {
				t.Errorf("the false-positive shape %q reached the extracted text.\n"+
					"That is the flood #314 exists to prevent; it must never be handed to a validator.\ngot:\n%s",
					tc.fp, c.Text)
			}
			if strings.TrimSpace(c.Text) != "" {
				t.Errorf("a geometry-only drawing extracted text %q; it must extract nothing", c.Text)
			}
			// A geometry-only drawing is CLEAN AND FULLY HANDLED, not unexamined.
			// Warning on it would put a NOT-FULLY-EXAMINED line against nearly every
			// .svg in existence: 88 of 90 real files measured carry no prose.
			if c.ExtractionWarning != "" {
				t.Errorf("a geometry-only drawing claimed lost coverage: %q", c.ExtractionWarning)
			}
			if c.ExtractionCause != coverage.CauseUnset {
				t.Errorf("a geometry-only drawing stated cause %v; it was fully read", c.ExtractionCause)
			}
		})
	}
}

// TestProseAndGeometryTogether is the both-directions case in ONE document.
//
// The separate tables above can each pass under a broken rule -- one by collecting
// everything, the other by collecting nothing. Only a document holding both proves the
// rule DISCRIMINATES.
func TestProseAndGeometryTogether(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 465.73919 466.54269">
  <title>Onboarding diagram for Renee Vasquez</title>
  <path d="m24 136-191v-63h-136zm587-260v401c0 41 465 0 863 76 1012 109"/>
  <polygon points="784 474 1269 8.25 75.75"/>
  <text x="10" y="40">Employee SSN: 452-11-9384</text>
</svg>`
	c := svgProbe(t, body)

	for _, prose := range []string{"Onboarding diagram for Renee Vasquez", "Employee SSN: 452-11-9384"} {
		if !strings.Contains(c.Text, prose) {
			t.Errorf("prose %q was dropped.\ngot:\n%s", prose, c.Text)
		}
	}
	for _, geom := range []string{"863 76 1012", "784 474 1269", "465.73919", "136-191"} {
		if strings.Contains(c.Text, geom) {
			t.Errorf("geometry %q survived.\ngot:\n%s", geom, c.Text)
		}
	}
	if c.Nodes != 2 {
		t.Errorf("expected exactly 2 prose nodes (title, text), got %d:\n%s", c.Nodes, c.Text)
	}
}

// TestMislabelledFileIsReported: recovering precision on real drawings must not cost
// recall on a renamed file.
//
// Measured before the NotSVG arm existed: a plain text file holding an SSN and an email
// renamed to .svg reported 2 findings through the plaintext preprocessor, and 0 once
// .svg routed to prose-only extraction. Zero is not a precision win, it is a leak.
func TestMislabelledFileIsReported(t *testing.T) {
	for _, body := range []string{
		"Employee SSN: 452-11-9384\nrenee@examplecorp.com\n",
		`<?xml version="1.0"?><html><body>Employee SSN: 452-11-9384</body></html>`,
		`{"ssn":"452-11-9384"}`,
	} {
		c := svgProbe(t, body)
		if !c.NotSVG {
			t.Errorf("bytes whose root element is not <svg> were treated as an SVG: %q", body)
		}
	}

	// And the converse: a well-formed SVG must NOT take the fallback, or the whole
	// document (geometry included) goes to the validators and the flood returns.
	for _, body := range []string{
		`<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>`,
		"<?xml version=\"1.0\"?>\n<!-- a comment -->\n<svg><text>x</text></svg>",
		`<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg><text>x</text></svg>`,
		`<svg:svg xmlns:svg="http://www.w3.org/2000/svg"><svg:text>x</svg:text></svg:svg>`,
	} {
		c := svgProbe(t, body)
		if c.NotSVG {
			t.Errorf("a well-formed SVG was mistaken for a mislabelled file, which sends its geometry "+
				"to the validators: %q", body)
		}
	}
}

// TestHostileInputTerminates: an .svg is untrusted input. It arrives from the CLI and
// from inside an OOXML part, where its declared size is producer-controlled.
//
// Each case asserts three things: it terminates, it does not panic, and the PII placed
// BEFORE the hostile construct is still recovered -- a bound that silently drops the
// document is the failure this change exists to remove.
func TestHostileInputTerminates(t *testing.T) {
	deep := "<g>" + strings.Repeat("<g>", 200000)
	billion := `<?xml version="1.0"?>
<!DOCTYPE svg [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text><text>&lol9;</text></svg>`

	cases := []struct {
		name string
		body string
		// wantPII is false where the construct legitimately blocks reaching the value.
		wantPII bool
		// wantDisclosed requires the truncation to be SAID, not just survived.
		wantDisclosed bool
	}{
		{
			name:          "unclosed tag",
			body:          `<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text><g><text>more`,
			wantPII:       true,
			wantDisclosed: true,
		},
		{
			// 6.8MB in one d= attribute. The parser must hold it and the extractor must
			// drop it; measured before .svg routed here, this file produced 400,001
			// findings in 19.9s of wall time.
			name:    "huge geometry attribute",
			body:    `<svg xmlns="http://www.w3.org/2000/svg"><path d="` + strings.Repeat("M 863 76 1012 109 ", 200000) + `"/><text>Employee SSN: 452-11-9384</text></svg>`,
			wantPII: true,
		},
		{
			// The value sits BELOW the depth bound, so it is legitimately unreachable --
			// and that must be disclosed rather than read as a clean file.
			name:          "deep nesting bomb",
			body:          `<svg xmlns="http://www.w3.org/2000/svg">` + deep + `<text>Employee SSN: 452-11-9384</text>`,
			wantPII:       false,
			wantDisclosed: true,
		},
		{
			// encoding/xml does not expand DTD entity declarations at all, so this is a
			// non-event rather than a bound to tune. Pinned so a future switch to a
			// parser that DOES expand them fails here.
			name:    "billion laughs",
			body:    billion,
			wantPII: true,
		},
		{
			// Go resolves no external entities. Asserted so the absence stays absent.
			name:    "external entity",
			body:    `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text><text>Employee SSN: 452-11-9384</text></svg>`,
			wantPII: true,
		},
		{
			// encoding/xml rejects a stray close tag even with Strict=false, so this is
			// the resync case: stopping at the error recovered ZERO nodes over a
			// document holding an SSN.
			name:          "stray close tags",
			body:          `<svg xmlns="http://www.w3.org/2000/svg"></g></tspan><text>Employee SSN: 452-11-9384</text></svg>`,
			wantPII:       true,
			wantDisclosed: true,
		},
		{
			// The resync bound, exercised: many errors must terminate, not spin.
			name:          "many syntax errors",
			body:          `<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text>` + strings.Repeat("</q>", 5000) + `</svg>`,
			wantPII:       true,
			wantDisclosed: true,
		},
		{
			name:    "empty document",
			body:    "",
			wantPII: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan *TextContent, 1)
			go func() {
				// A panic here fails the test through the goroutine, which is what we
				// want: the extractor's own recover() turns a panic into an error, and
				// that error must not be how these cases pass.
				c, err := ExtractFromBytes("hostile.svg", []byte(tc.body))
				if err != nil {
					t.Errorf("hostile input produced an error rather than a bounded read: %v", err)
				}
				done <- c
			}()
			var c *TextContent
			select {
			case c = <-done:
			case <-time.After(60 * time.Second):
				t.Fatal("extraction did not terminate within 60s on hostile input")
			}
			if c == nil {
				t.Fatal("nil content returned")
			}
			if got := strings.Contains(c.Text, "452-11-9384"); got != tc.wantPII {
				t.Errorf("PII recovered = %v, want %v.\nA bound that drops the values already read is the "+
					"silent miss this change removes.\ngot text (%d bytes):\n%s", got, tc.wantPII, len(c.Text), c.Text)
			}
			if tc.wantDisclosed {
				if c.ExtractionWarning == "" {
					t.Error("truncation was not disclosed; an unread remainder that says nothing reads as a clean file")
				}
				if c.ExtractionCause != coverage.CauseCutShort {
					t.Errorf("cause = %v, want CauseCutShort: the document was PARTLY read, and a true "+
						"disclosure under a false heading is half a fix", c.ExtractionCause)
				}
			}
			// Entity expansion would show up here as a text far larger than the input.
			if len(c.Text) > 4*len(tc.body)+4096 {
				t.Errorf("extracted text (%d bytes) is disproportionate to the input (%d bytes); "+
					"that is entity expansion", len(c.Text), len(tc.body))
			}
		})
	}
}

// TestSizeBoundTruncatesAndSays covers MaxSVGBytes.
func TestSizeBoundTruncatesAndSays(t *testing.T) {
	// PII first, so the truncation cannot be what removes it.
	head := `<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text><desc>`
	body := head + strings.Repeat("x", MaxSVGBytes) + `</desc></svg>`
	c, err := ExtractFromBytes("big.svg", []byte(body))
	if err != nil {
		t.Fatalf("oversize input errored: %v", err)
	}
	if !strings.Contains(c.Text, "452-11-9384") {
		t.Error("the value read BEFORE the size bound was dropped")
	}
	if !c.Truncated {
		t.Errorf("a %d-byte document was not marked truncated at a %d-byte bound", len(body), MaxSVGBytes)
	}
	if c.ExtractionCause != coverage.CauseCutShort {
		t.Errorf("cause = %v, want CauseCutShort", c.ExtractionCause)
	}
}

// TestExtractTextReadsAFile exercises the filesystem entry point, which the
// preprocessor uses and ExtractFromBytes does not cover.
func TestExtractTextReadsAFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "diagram.svg")
	if err := os.WriteFile(p, []byte(
		`<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text></svg>`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	c, err := ExtractText(p)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if !strings.Contains(c.Text, "452-11-9384") {
		t.Errorf("value not extracted from a file on disk: %q", c.Text)
	}
	if c.Filename != "diagram.svg" {
		t.Errorf("Filename = %q, want diagram.svg", c.Filename)
	}
	if c.Format != "SVG Image" {
		t.Errorf("Format = %q, want SVG Image", c.Format)
	}

	// A path that does not exist must be an ERROR carrying a note, not a silent empty
	// result: the preprocessor propagates the note and the CLI turns it into a
	// coverage disclosure.
	missing, err := ExtractText(filepath.Join(dir, "gone.svg"))
	if err == nil {
		t.Error("a missing file returned no error, so nothing would tell the operator it was not read")
	}
	if missing == nil || missing.ExtractionWarning == "" {
		t.Error("a missing file carried no ExtractionWarning")
	}
	if missing != nil && missing.ExtractionCause != coverage.CauseUnreadable {
		t.Errorf("cause = %v, want CauseUnreadable", missing.ExtractionCause)
	}
}

// TestDeterministicExtraction: the emitted order is document order, so two runs over
// the same bytes must be identical. Line numbers in every finding depend on it.
func TestDeterministicExtraction(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg" aria-label="A"><title>B</title>` +
		`<g inkscape:label="C" xmlns:inkscape="x"><text>D<tspan>E</tspan>F</text></g>` +
		`<!-- G --><desc>H</desc></svg>`
	first := svgProbe(t, body).Text
	for i := 0; i < 20; i++ {
		if got := svgProbe(t, body).Text; got != first {
			t.Fatalf("run %d differed:\n%q\nvs\n%q", i, got, first)
		}
	}
	// The comment's surrounding whitespace is folded away by collapseSpace, same as any
	// other node's.
	if want := "A\nB\nC\nD\nE\nF\nG\nH\n"; first != want {
		t.Errorf("emitted order changed.\ngot:  %q\nwant: %q", first, want)
	}
}

// TestCollapseSpaceIsLinear guards the fold that joins a multi-line node.
//
// It is the one place in this package where a naive implementation (repeated
// concatenation, or a regexp over the whole node per space run) would be quadratic in
// a single node's length, and a <desc> is unbounded.
func TestCollapseSpaceIsLinear(t *testing.T) {
	var prev time.Duration
	for i, n := range []int{1 << 20, 1 << 21, 1 << 22} {
		in := strings.Repeat("a \n\t", n/4)
		start := time.Now()
		out := collapseSpace(in)
		el := time.Since(start)
		if len(out) == 0 {
			t.Fatalf("collapseSpace returned nothing for %d bytes of input", len(in))
		}
		if i > 0 && prev > 0 {
			if ratio := float64(el) / float64(prev); ratio > 3.0 {
				t.Errorf("collapseSpace scaled %.2fx per doubling at n=%d (linear is 2x, quadratic 4x): %v -> %v",
					ratio, n, prev, el)
			}
		}
		prev = el
	}
}

// TestNodesCountIsTheNonVacuityHandle: Nodes is what every caller and test uses to
// prove extraction happened at all, so it must be exact.
func TestNodesCountIsTheNonVacuityHandle(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{
		{`<svg xmlns="http://www.w3.org/2000/svg"><path d="M1 2"/></svg>`, 0},
		{`<svg xmlns="http://www.w3.org/2000/svg"><text>a</text></svg>`, 1},
		{`<svg xmlns="http://www.w3.org/2000/svg"><text>a</text><text>b</text></svg>`, 2},
		// Whitespace-only character data is not a node.
		{"<svg xmlns=\"http://www.w3.org/2000/svg\"><text>  \n  </text></svg>", 0},
		{fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg">%s</svg>`,
			strings.Repeat(`<text>a</text>`, 500)), 500},
	} {
		if got := svgProbe(t, tc.body).Nodes; got != tc.want {
			t.Errorf("Nodes = %d, want %d for %.60s", got, tc.want, tc.body)
		}
	}
}
