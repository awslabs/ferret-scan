// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/position"
)

// correlateWithinLine hands the correlator one line instead of the document (#1005). It may only
// answer when that is the answer the whole document gives, in every field redactText reads:
// confidence, method and the document offset. This compares the two over a document built to hit
// the exact matcher (unique value), the fuzzy matcher (a value that occurs twice on its line, which
// de-rates the exact score below the threshold) and the lines at the document's edges.
func TestCorrelateWithinLineAgreesWithWholeDocument(t *testing.T) {
	doc := strings.Join([]string{
		"first alice@corp.example.org line",
		"dup bob@corp.example.org and bob@corp.example.org again",
		"alice@corp.example.org on another line",
		"crlf carol@corp.example.org\r",
		"",
		"last dave@corp.example.org",
	}, "\n")
	cases := []struct {
		line int
		text string
	}{
		{1, "alice@corp.example.org"},
		{2, "bob@corp.example.org"},
		{3, "alice@corp.example.org"},
		{4, "carol@corp.example.org"},
		{6, "dave@corp.example.org"},
	}
	ptr := NewPlainTextRedactor(nil, nil)
	offsets := lineOffsets(doc)
	methods := map[string]bool{}
	for _, tc := range cases {
		m := detector.Match{Text: tc.text, Type: "EMAIL", LineNumber: tc.line}
		start, end, err := ptr.calculateCharacterPositions(m, doc, offsets)
		if err != nil {
			t.Fatalf("line %d: %v", tc.line, err)
		}
		whole, err := ptr.positionCorrelator.CorrelatePosition(
			redactors.TextPosition{Line: tc.line, StartChar: start, EndChar: end}, doc, []byte(doc), "text")
		if err != nil {
			t.Fatalf("line %d: whole-document correlation: %v", tc.line, err)
		}
		got, ok := ptr.correlateWithinLine(m, doc, offsets, start, end)
		if !ok {
			t.Fatalf("line %d: the line window declined a case the exact/fuzzy matchers answer", tc.line)
		}
		methods[whole.Method.String()] = true
		if got.ConfidenceScore != whole.ConfidenceScore || got.Method != whole.Method ||
			got.OriginalPosition.CharOffset != whole.OriginalPosition.CharOffset ||
			got.OriginalPosition.BoundingBox != whole.OriginalPosition.BoundingBox ||
			got.ExtractedPosition != whole.ExtractedPosition {
			t.Errorf("line %d: window %+v / %+v, whole document %+v / %+v",
				tc.line, got, got.OriginalPosition, whole, whole.OriginalPosition)
		}
	}
	// Non-vacuity: both matchers must have been exercised.
	if !methods["exact"] || !methods["fuzzy"] {
		t.Fatalf("fixture covers only %v; it must reach both the exact and the fuzzy matcher", methods)
	}
}

// A heuristic answer reads the rest of the document, so the window must not give one: with fuzzy
// matching off, a repeated value falls through to the heuristic matcher and the caller must get the
// whole-document call.
func TestCorrelateWithinLineDeclinesWhatItCannotAnswer(t *testing.T) {
	doc := "bob@corp.example.org and bob@corp.example.org\n"
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.positionCorrelator.(*position.DefaultPositionCorrelator).EnableFuzzyMatching(false)
	m := detector.Match{Text: "bob@corp.example.org", Type: "EMAIL", LineNumber: 1}
	offsets := lineOffsets(doc)
	start, end, err := ptr.calculateCharacterPositions(m, doc, offsets)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ptr.correlateWithinLine(m, doc, offsets, start, end); ok {
		t.Fatal("the line window answered a heuristic correlation")
	}
}
