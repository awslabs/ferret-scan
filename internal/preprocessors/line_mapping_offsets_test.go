// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"runtime"
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

	// Both a wall-clock duration and the bytes allocated. The growth assertion below uses the
	// ALLOCATION figure, not the duration — see the comment on it.
	measure := func(n int) (time.Duration, uint64, int) {
		content := &ProcessedContent{Text: build(n), LineCount: n, PageCount: 1}

		// build() is outside the measurement window: the input string is many times larger than
		// the mappings, so counting it would swamp the signal and make the ratio ~4x either way.
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		tp.createBasicLineMappings(content, "timing")
		elapsed := time.Since(start)
		runtime.ReadMemStats(&after)

		return elapsed, after.TotalAlloc - before.TotalAlloc, len(content.PositionMappings)
	}

	const baseLines = 2500
	tBase, allocBase, nBase := measure(baseLines)
	tBig, allocBig, nBig := measure(baseLines * 4)

	// Non-vacuity: a timing assertion means nothing if no mappings were produced.
	// One mapping per non-empty line, so these are exact.
	if nBase != baseLines || nBig != baseLines*4 {
		t.Fatalf("expected one mapping per line, got %d at %d lines and %d at %d — the "+
			"timing comparison below would be measuring the wrong thing",
			nBase, baseLines, nBig, baseLines*4)
	}

	t.Logf("%d lines: %v, %dKB allocated (%d mappings) | %d lines: %v, %dKB allocated (%d mappings)",
		baseLines, tBase.Round(time.Millisecond), allocBase/1024, nBase,
		baseLines*4, tBig.Round(time.Millisecond), allocBig/1024, nBig)

	// Absolute ceiling. Linear is a few ms; the quadratic form took 2.79s at this
	// size. Generous enough for a slow shared CI runner.
	const ceiling = 2 * time.Second
	if tBig > ceiling {
		t.Errorf("4x input took %v (> %v) — CalculateAbsoluteOffset is probably being "+
			"called per line again, which re-splits the whole document each time", tBig, ceiling)
	}

	// Relative growth, measured in ALLOCATED BYTES rather than elapsed time.
	//
	// This assertion was a wall-clock ratio with a 2ms noise floor, and it flaked on a macOS CI
	// runner: base=7.44ms big=91.26ms, a 12.3x ratio against a 12.0x limit, while the absolute
	// ceiling above passed with a 22x margin (91ms against 2s). A ratio of two single-digit
	// millisecond samples on a shared runner is scheduler noise, not a signal — 7.44ms is barely
	// above the floor that was supposed to protect it.
	//
	// Allocated bytes measure the same defect without a clock. The regression is
	// CalculateAbsoluteOffset being called per line, and it calls splitLines over the ENTIRE
	// text on every call, which allocates a []string of one header per line. So n calls each
	// allocating O(n) gives O(n²) BYTES, not merely O(n²) time.
	//
	// Measured here, by restoring the two per-line CalculateAbsoluteOffset calls and re-running:
	//
	//	                    2500 lines   10000 lines   ratio
	//	prefix sum (now)        1,716KB       7,958KB   4.6x   (one split + one offsets slice)
	//	per-line split (was)  493,290KB  13,014,252KB  26.4x   (2n splits of n headers each)
	//
	// So the limit at 8x sits between a measured 4.6x and a measured 26.4x, and the absolute
	// figures differ by ~1,600x (1.7MB against 482MB) — this is not a marginal discrimination.
	// Allocation counts do not depend on how loaded the runner is, so there is no noise floor to
	// get wrong: the same mutation is caught identically on an idle laptop and a saturated runner.
	const maxAllocGrowth = 8.0
	if allocBase == 0 {
		t.Fatalf("no allocation recorded for the %d-line case — the growth assertion below "+
			"would divide by zero and pass vacuously", baseLines)
	}
	if ratio := float64(allocBig) / float64(allocBase); ratio > maxAllocGrowth {
		t.Errorf("4x input allocated %.1fx more (base=%dKB big=%dKB, limit %.0fx) — superlinear "+
			"allocation growth means the per-line whole-document split is back",
			ratio, allocBase/1024, allocBig/1024, maxAllocGrowth)
	}
}
