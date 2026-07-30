// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestLineMappingOffsetsMatchCalculateAbsoluteOffset is the equivalence gate.
//
// createBasicLineMappings used to call CalculateAbsoluteOffset twice per line;
// it now computes a prefix sum once per document. That is only safe if the two
// produce identical offsets, so this recomputes every mapping the old way and
// compares. CalculateAbsoluteOffset is deliberately still the oracle here even
// though it no longer has production callers — it is the definition the fast path
// has to match.
//
// The inputs cover the shapes where an off-by-one would hide: empty text, no
// trailing newline, consecutive blank lines, and multi-byte runes (offsets are
// byte offsets, so a rune-counting mistake shows up here).
func TestLineMappingOffsetsMatchCalculateAbsoluteOffset(t *testing.T) {
	tp := NewTextPreprocessor()

	inputs := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"single line no newline", "single line"},
		{"three short lines", "a\nb\nc"},
		{"trailing newline", "trailing newline\n"},
		{"leading and interior blanks", "\n\nleading blanks\n\nx\n"},
		{"multibyte runes", "unicode ünïcödé ✓ line\nsecond ✓\n"},
		{"blank line runs", strings.Repeat("data 123-45-6789\nshort\n\n", 200)},
		{"no trailing newline", "no trailing\nnewline here"},
	}

	for _, in := range inputs {
		t.Run(in.name, func(t *testing.T) {
			content := &ProcessedContent{
				Text:      in.text,
				LineCount: len(splitLines(in.text)),
				PageCount: 3,
			}
			tp.createBasicLineMappings(content, "equivalence")

			lines := splitLines(in.text)
			for _, m := range content.PositionMappings {
				line := m.ExtractedPosition.Line
				if line < 1 || line > len(lines) {
					t.Fatalf("mapping line %d out of range 1..%d", line, len(lines))
				}
				want := CalculateAbsoluteOffset(in.text, line, 0)
				if got := m.ExtractedPosition.AbsoluteOffset; got != want {
					t.Errorf("line %d: AbsoluteOffset = %d, want %d (the prefix sum must "+
						"equal what CalculateAbsoluteOffset computes)", line, got, want)
				}
				if got := m.OriginalPosition.CharOffset; got != want {
					t.Errorf("line %d: CharOffset = %d, want %d", line, got, want)
				}
			}
		})
	}
}

// TestCreateBasicLineMappingsIsLinear is the performance regression guard.
//
// CalculateAbsoluteOffset re-runs splitLines over the WHOLE text on every call,
// and createBasicLineMappings called it twice per line — so a 10k-row spreadsheet
// performed 20,000 full-document splits and extraction was quadratic:
//
//	lines    before     after
//	 1250     166ms       1ms
//	 2500     607ms       1ms
//	 5000     2.79s       2ms
//	10000    10.15s       3ms
//
// ~3.6-4.6x per doubling before (linear is 2x), ~1.9x after. Every Office and PDF
// format funnels through this one function, so the same fix covers .xlsx/.docx/
// .pptx/.odt/.ods/.odp/.pdf.
func TestCreateBasicLineMappingsIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard skipped in -short mode")
	}

	tp := NewTextPreprocessor()

	build := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			// Distinct values per line: a repeated line would still exercise the
			// per-line cost here, but distinct data keeps this honest if the
			// function ever starts deduplicating.
			fmt.Fprintf(&sb, "row %d value ssn 4%02d-%02d-%04d email u%d@corp.example\n",
				i, i%100, i%80, i%9000, i)
		}
		return sb.String()
	}

	measure := func(n int) (time.Duration, int) {
		content := &ProcessedContent{Text: build(n), LineCount: n, PageCount: 1}
		start := time.Now()
		tp.createBasicLineMappings(content, "timing")
		return time.Since(start), len(content.PositionMappings)
	}

	const baseLines = 2500
	tBase, nBase := measure(baseLines)
	tBig, nBig := measure(baseLines * 4)

	// Non-vacuity: a timing assertion means nothing if no mappings were produced.
	// One mapping per non-empty line, so these are exact.
	if nBase != baseLines || nBig != baseLines*4 {
		t.Fatalf("expected one mapping per line, got %d at %d lines and %d at %d — the "+
			"timing comparison below would be measuring the wrong thing",
			nBase, baseLines, nBig, baseLines*4)
	}

	t.Logf("%d lines: %v (%d mappings) | %d lines: %v (%d mappings)",
		baseLines, tBase.Round(time.Millisecond), nBase,
		baseLines*4, tBig.Round(time.Millisecond), nBig)

	// Absolute ceiling. Linear is a few ms; the quadratic form took 2.79s at this
	// size. Generous enough for a slow shared CI runner.
	const ceiling = 2 * time.Second
	if tBig > ceiling {
		t.Errorf("4x input took %v (> %v) — CalculateAbsoluteOffset is probably being "+
			"called per line again, which re-splits the whole document each time", tBig, ceiling)
	}

	// Relative growth: 4x input is ~4x under linear, ~16x under quadratic. Only
	// meaningful once the base is large enough to measure above timer noise.
	if tBase > 2*time.Millisecond {
		if ratio := float64(tBig) / float64(tBase); ratio > 12.0 {
			t.Errorf("4x input took %.1fx longer (base=%v big=%v) — superlinear growth "+
				"suggests the per-line whole-document split is back", ratio, tBase, tBig)
		}
	}
}
