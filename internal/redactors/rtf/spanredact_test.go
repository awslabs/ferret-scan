// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rtf

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	rtfextract "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-rtftextlib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestEveryProducerSpellingOfAValueIsActuallyRemoved is the functional property the span map exists to
// deliver, asserted end to end rather than by inspecting the map.
//
// It exists because two mutations SURVIVED the map's own structural tests: emptying an escape's source
// range, and merging spans whose output and source lengths differ. Both left the map self-consistent —
// a test that only validates the spans that EXIST cannot see a missing one, and a test that allows any
// length mismatch "if the source contains a backslash" waves through a wrongly merged span.
//
// The property that catches both: for every way a real producer can spell the value, redacting it must
// make it absent from a RE-EXTRACTION of the redacted bytes, AND its neighbours must survive. That is
// the operator-visible guarantee, and it holds regardless of how the map is represented internally.
//
// One emit site is deliberately NOT covered here, and saying so is better than a test that pretends:
// the literal-escape site (\\ \{ \}). Emptying its source range survives every assertion below,
// because catching it needs a value that CONTAINS a brace or a backslash and no realistic PII value
// does. Its failure mode is also the safe one — a missing span is a GAP, SourceRanges refuses a window
// covering a gap, and the redactor then falls back to refusing the file rather than corrupting it.
// Compare the escape sites that ARE covered, where the same mistake produced a wrong offset.
func TestEveryProducerSpellingOfAValueIsActuallyRemoved(t *testing.T) {
	const value = "452-11-9384"

	spellings := map[string]string{
		"contiguous":                  `Employee SSN: 452-11-9384\par`,
		"split across a run":          `Employee SSN: 452-11-\f1\b 9384\b0\par`,
		"split twice":                 `SSN: 452-\f1\b 11\b0-\i 9384\i0\par`,
		"hex-escaped punctuation":     `SSN: 452\'2d11\'2d9384\par`,
		"hex escape plus a run split": `SSN: 452\'2d11\'2d\f1\b 9384\b0\par`,
		"leading trimmed whitespace":  `\par\par   SSN: 452-11-\f1\b 9384\b0\par`,
		"value twice in one document": `A: 452-11-9384\par B: 452-11-\f1\b 9384\b0\par`,
	}

	for name, body := range spellings {
		src := "{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n\\f0\\fs24 " + body + "\n}\n"

		// Precondition: the extractor must reassemble the value, or this case is testing nothing.
		before, err := rtfextract.ExtractFromBytes("t.rtf", []byte(src))
		if err != nil {
			t.Errorf("%s: extract: %v", name, err)
			continue
		}
		if !strings.Contains(before.Text, value) {
			t.Errorf("%s: the extractor did not reassemble %q, so this spelling cannot be redacted and "+
				"the case proves nothing. Got %q", name, value, before.Text)
			continue
		}

		out, handled := redactViaSpans(src, []detector.Match{{Text: value, Type: "SSN"}}, redactors.RedactionSimple)
		if !handled[value] {
			t.Errorf("%s: the span map could not locate a value the extractor DID produce, so redaction "+
				"falls back to refusing the file", name)
			continue
		}

		// THE PROPERTY: gone from a re-extraction of the redacted bytes.
		after, err := rtfextract.ExtractFromBytes("t.rtf", []byte(out))
		if err != nil {
			t.Errorf("%s: the redacted bytes no longer parse as RTF: %v", name, err)
			continue
		}
		if strings.Contains(after.Text, value) {
			t.Errorf("%s: %q survives a re-extraction of the redacted document.\nsrc:  %s\nout:  %s\ntext: %q",
				name, value, src, out, after.Text)
		}
		// And no fragment left behind. "9384" alone is what a fix that rewrites only the first mapped
		// range leaves in the file.
		if strings.Contains(after.Text, "9384") {
			t.Errorf("%s: the trailing fragment \"9384\" survives — only part of the value was rewritten."+
				"\nout: %s", name, out)
		}
		// Still a document, and the replacement is present.
		if !strings.HasPrefix(out, `{\rtf`) {
			t.Errorf("%s: output is no longer RTF:\n%s", name, out)
		}
		if !strings.Contains(after.Text, "REDACTED") {
			t.Errorf("%s: no replacement token in the extracted text, so the value was deleted rather "+
				"than redacted: %q", name, after.Text)
		}

		// SURROUNDING TEXT MUST SURVIVE. Removing the value is only half the requirement: an
		// over-broad source range removes the value AND its neighbours, which passes every check
		// above while quietly deleting the operator's document.
		//
		// This is not hypothetical. A mutation that merges spans whose output and source lengths
		// differ survived all the assertions above, because such a span can only be taken WHOLE —
		// so the replacement swallowed adjacent characters and the value was still "gone".
		for _, neighbour := range neighbourWords(before.Text, value) {
			if !strings.Contains(after.Text, neighbour) {
				t.Errorf("%s: %q sat next to the value and was deleted with it — the source range is "+
					"wider than the value.\nbefore: %q\nafter:  %q\nout:    %s",
					name, neighbour, before.Text, after.Text, out)
			}
		}
	}
}

// neighbourWords returns whole words adjacent to every occurrence of value in text, excluding any word
// that contains part of the value itself.
//
// Used to prove a redaction removed the value and nothing else. Words rather than single characters,
// because a one-character check passes on an off-by-one that a word does not.
func neighbourWords(text, value string) []string {
	var out []string
	seen := map[string]bool{}
	for from := 0; ; {
		at := strings.Index(text[from:], value)
		if at < 0 {
			break
		}
		at += from
		from = at + len(value)
		for _, half := range []string{text[:at], text[from:]} {
			for _, w := range strings.Fields(half) {
				// A word overlapping the value cannot survive intact, so it is not evidence either way.
				if w == "" || strings.Contains(value, w) || strings.Contains(w, value) || seen[w] {
					continue
				}
				if len(w) < 3 {
					continue // too short to be a reliable signal
				}
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}
