// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractrtftextlib

import (
	"strings"
	"testing"
)

// TestEverySpanRoundTripsToTheSameBytes is the invariant the whole map rests on.
//
// For every recorded span, the extracted text in [OutStart,OutEnd) must be reconstructible from the
// source in [SrcStart,SrcEnd). If that ever drifts, a redactor rewrites the WRONG bytes — silently
// corrupting a document while reporting success, which is worse than the refusal this replaces.
//
// Checked over deliberately awkward documents rather than one happy case: split values, hex escapes,
// unicode escapes, skipped destinations, literal braces, and CRLF.
func TestEverySpanRoundTripsToTheSameBytes(t *testing.T) {
	docs := map[string]string{
		"split across runs":   rtf(`Employee SSN: 452-11-\f1\b 9384\b0\par`),
		"hex escapes":         rtf(`SSN: 452\'2d11\'2d9384\par`),
		"unicode escape":      rtf(`Caf\u233\'e9 owner\par`),
		"literal braces":      rtf(`A \{literal\} brace and a \\ backslash\par`),
		"skipped destination": "{\\rtf1\\ansi{\\fonttbl{\\f0 Helvetica;}}{\\*\\generator X;}\\f0 Real: 452-11-9384\\par\n}\n",
		"crlf in markup":      "{\\rtf1\\ansi\\deff0\\f0 SSN: 452-11-\r\n9384\\par\r\n}\r\n",
		"multiple paragraphs": rtf(`One: 452-11-9384\par Two: bob@example.com\par Three: end\par`),
	}
	for name, doc := range docs {
		tc, err := ExtractFromBytes("t.rtf", []byte(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(tc.Spans) == 0 {
			t.Errorf("%s: no spans recorded, so nothing can be redacted", name)
			continue
		}
		for i, sp := range tc.Spans {
			// Bounds first: an out-of-range span would panic a redactor rather than misbehave.
			if sp.OutStart < 0 || sp.OutEnd > len(tc.Text) || sp.OutStart >= sp.OutEnd {
				t.Errorf("%s span %d: output range [%d,%d) invalid for %d bytes of text",
					name, i, sp.OutStart, sp.OutEnd, len(tc.Text))
				continue
			}
			if sp.SrcStart < 0 || sp.SrcEnd > len(doc) || sp.SrcStart >= sp.SrcEnd {
				t.Errorf("%s span %d: source range [%d,%d) invalid for %d bytes of source",
					name, i, sp.SrcStart, sp.SrcEnd, len(doc))
				continue
			}
			// Spans must be ordered and non-overlapping in the OUTPUT, or SourceRanges' gap detection
			// cannot work.
			if i > 0 && sp.OutStart < tc.Spans[i-1].OutEnd {
				t.Errorf("%s span %d overlaps the previous in output: [%d,%d) after [%d,%d)",
					name, i, sp.OutStart, sp.OutEnd, tc.Spans[i-1].OutStart, tc.Spans[i-1].OutEnd)
			}
			// The load-bearing check: where lengths agree, the bytes must agree too. Where they differ
			// (an escape emitting one rune from several source bytes) the source must at least CONTAIN
			// an escape marker, so the span is not pointing at unrelated markup.
			outBytes := tc.Text[sp.OutStart:sp.OutEnd]
			srcBytes := doc[sp.SrcStart:sp.SrcEnd]
			if len(outBytes) == len(srcBytes) {
				if outBytes != srcBytes {
					t.Errorf("%s span %d: output %q != source %q at equal length — a redactor would "+
						"rewrite the wrong bytes", name, i, outBytes, srcBytes)
				}
			} else if !strings.Contains(srcBytes, `\`) {
				t.Errorf("%s span %d: output %q and source %q differ in length but the source holds no "+
					"escape, so this span is pointing at the wrong place", name, i, outBytes, srcBytes)
			}
		}
	}
}

// TestSourceRangesFindsASplitValue is the case the map exists for.
//
// `452-11-\f1\b 9384` reassembles to `452-11-9384`, which occurs nowhere literally. The map must return
// the two source ranges holding the digits, and must NOT include the control words between them —
// rewriting those would destroy the document's formatting.
func TestSourceRangesFindsASplitValue(t *testing.T) {
	const value = "452-11-9384"
	doc := rtf(`Employee SSN: 452-11-\f1\b 9384\b0\par`)

	tc, err := ExtractFromBytes("t.rtf", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	at := strings.Index(tc.Text, value)
	if at < 0 {
		t.Fatalf("the extractor did not reassemble %q; got %q", value, tc.Text)
	}

	ranges := SourceRanges(tc.Spans, at, at+len(value))
	if ranges == nil {
		t.Fatalf("SourceRanges returned nil for a value the extractor DID produce — a redactor would "+
			"then refuse a file it could have fixed. text=%q spans=%v", tc.Text, tc.Spans)
	}
	if len(ranges) < 2 {
		t.Errorf("expected the value to map to at least 2 source ranges (it is split across a "+
			"formatting run); got %d: %v", len(ranges), ranges)
	}

	// Concatenating the mapped source must reproduce the value exactly — no control-word bytes.
	var got strings.Builder
	for _, r := range ranges {
		got.WriteString(doc[r[0]:r[1]])
	}
	if got.String() != value {
		t.Errorf("mapped source concatenates to %q, want %q — the ranges include markup or miss digits",
			got.String(), value)
	}
}

// TestSourceRangesRefusesAPartiallyMappedWindow: a caller must be able to tell "here are the bytes"
// from "part of this came from nowhere I can point at". Approximating would leave part of a value
// behind, which is the exact failure the map exists to prevent.
func TestSourceRangesRefusesAPartiallyMappedWindow(t *testing.T) {
	spans := []Span{
		{OutStart: 0, OutEnd: 5, SrcStart: 10, SrcEnd: 15},
		// deliberate gap in the output: 5..8 maps to nothing
		{OutStart: 8, OutEnd: 12, SrcStart: 20, SrcEnd: 24},
	}
	if got := SourceRanges(spans, 0, 12); got != nil {
		t.Errorf("a window spanning an unmapped gap returned %v; want nil so the caller refuses", got)
	}
	if got := SourceRanges(spans, 0, 5); got == nil {
		t.Error("a fully mapped window returned nil, so nothing would ever be redactable")
	}
	if got := SourceRanges(spans, 8, 12); got == nil {
		t.Error("a fully mapped window in the second span returned nil")
	}
	// Degenerate windows must not panic or claim coverage.
	for _, w := range [][2]int{{0, 0}, {5, 5}, {12, 3}} {
		if got := SourceRanges(spans, w[0], w[1]); got != nil {
			t.Errorf("SourceRanges(%d,%d) = %v; want nil", w[0], w[1], got)
		}
	}
}

// TestSpansSurviveTrimSpace. parse ends with strings.TrimSpace, which shifts every output offset. If
// the map is not re-based for it, every redaction lands at the wrong place by exactly the leading
// whitespace — the kind of off-by-N that looks fine on a document with none.
func TestSpansSurviveTrimSpace(t *testing.T) {
	// Leading \par produces leading whitespace in the raw output, which TrimSpace then removes.
	doc := rtf(`\par\par   Leading space then SSN: 452-11-9384\par`)
	tc, err := ExtractFromBytes("t.rtf", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	const value = "452-11-9384"
	at := strings.Index(tc.Text, value)
	if at < 0 {
		t.Fatalf("value not extracted; got %q", tc.Text)
	}
	ranges := SourceRanges(tc.Spans, at, at+len(value))
	if ranges == nil {
		t.Fatalf("no source ranges for a value in a trimmed document; spans=%v text=%q", tc.Spans, tc.Text)
	}
	var got strings.Builder
	for _, r := range ranges {
		got.WriteString(doc[r[0]:r[1]])
	}
	if got.String() != value {
		t.Errorf("after TrimSpace the map points at %q instead of %q — the offsets were not re-based",
			got.String(), value)
	}
}
