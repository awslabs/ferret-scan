// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractsvgtextlib

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A drawing with many <text> elements must stay sub-quadratic.
//
// This is a real shape, not a synthetic worry: an exported architecture diagram or a
// whiteboard snapshot is thousands of small labels, and 12 of 13 validators in this
// repo have been O(n^2) on dense input at some point. The extractor sits upstream of
// all of them, so a quadratic here multiplies.
//
// Measured through the real binary at the same sizes, prose-only extraction plus full
// validation:
//
//	N=10000  1.18MB  0.590s  10000 findings
//	N=20000  2.36MB  1.062s  20000 findings   1.80x per doubling
//	N=40000  4.73MB  2.078s  40000 findings   1.96x per doubling
//
// Linear is 2.0x, quadratic 4.0x.

// svgWithNTextNodes builds a drawing of n labelled groups.
//
// The values are DISTINCT at every size and every index. Identical repeats are what
// lets a quadratic measure as linear: a deduplicating or caching step collapses the
// work and the curve flattens for a reason that has nothing to do with the algorithm.
// Each group also carries a <path> whose coordinates differ, so the geometry the
// extractor must SKIP grows at the same rate as the prose it must keep -- a rule that
// skipped geometry in quadratic time would show up here.
func svgWithNTextNodes(n int) string {
	var b strings.Builder
	b.Grow(n * 128)
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000">` + "\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b,
			"  <g transform=\"translate(%d,%d)\" aria-label=\"group %d of %d\">"+
				"<path d=\"M%d.%04d %d.%04d C%d.%04d %d.%04d\"/>"+
				"<text x=\"1\" y=\"%d\">Employee SSN: %03d-%02d-%04d</text></g>\n",
			i%997, i%911, i, n,
			i%60, i%9999, i%70, (i*3)%9999, i%50, (i*7)%9999, i%80, (i*11)%9999,
			i%1000,
			100+(i/10000)%800, 10+(i/100)%80, 1000+i%9000)
	}
	b.WriteString("</svg>\n")
	return b.String()
}

// TestManyTextNodesIsSubQuadratic measures the scaling curve at N/2N/4N.
func TestManyTextNodesIsSubQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}

	const base = 4000
	sizes := []int{base, 2 * base, 4 * base}

	type point struct {
		n     int
		bytes int
		nodes int
		el    time.Duration
	}
	var pts []point

	for _, n := range sizes {
		body := svgWithNTextNodes(n)
		// Warm once so the first measurement is not paying for a cold allocator.
		if _, err := ExtractFromBytes("scale.svg", []byte(body)); err != nil {
			t.Fatalf("N=%d: %v", n, err)
		}
		start := time.Now()
		c, err := ExtractFromBytes("scale.svg", []byte(body))
		el := time.Since(start)
		if err != nil {
			t.Fatalf("N=%d: %v", n, err)
		}

		// NON-VACUITY FLOOR, asserted at EVERY size before any timing claim.
		// A rule that extracted nothing would produce a perfectly linear curve.
		if c.Nodes == 0 {
			t.Fatalf("N=%d extracted 0 nodes; the curve below would be measuring nothing", n)
		}
		// One <text> plus one aria-label per group.
		if want := 2 * n; c.Nodes != want {
			t.Fatalf("N=%d extracted %d nodes, want %d; the fixture and the rule disagree, "+
				"so the curve is not measuring what it claims", n, c.Nodes, want)
		}
		// And the values must be DISTINCT in the output, or the fixture is repeating.
		for _, probe := range []string{
			fmt.Sprintf("%03d-%02d-%04d", 100, 10, 1000),
			fmt.Sprintf("group %d of %d", n-1, n),
		} {
			if !strings.Contains(c.Text, probe) {
				t.Fatalf("N=%d: %q missing from the extracted text", n, probe)
			}
		}

		pts = append(pts, point{n: n, bytes: len(body), nodes: c.Nodes, el: el})
	}

	// GROWTH, not just non-zero. A flat node count across sizes is the signature of a
	// cap or an overwrite silently discarding work (see the 2k/4k/8k finding-count
	// case this repo has hit before).
	for i := 1; i < len(pts); i++ {
		if pts[i].nodes <= pts[i-1].nodes {
			t.Errorf("node count did not grow: N=%d gave %d, N=%d gave %d",
				pts[i-1].n, pts[i-1].nodes, pts[i].n, pts[i].nodes)
		}
	}

	for _, p := range pts {
		t.Logf("N=%-6d %8d bytes  %6d nodes  %v", p.n, p.bytes, p.nodes, p.el)
	}

	// The ceiling is deliberately loose. A wall-clock ratio on a shared CI runner is
	// noisy in both directions, and -race compresses it further, so the number has to
	// separate LINEAR from QUADRATIC rather than measure a constant: 2x per doubling
	// is linear, 4x is quadratic, and 3.2x sits between them with room for noise. This
	// is a shape assertion, not a performance budget.
	const ceiling = 3.2
	for i := 1; i < len(pts); i++ {
		prev, cur := pts[i-1].el, pts[i].el
		// Below a millisecond the ratio is measuring the clock, not the algorithm.
		if prev < time.Millisecond {
			t.Logf("N=%d took %v, too fast to form a ratio; skipped", pts[i-1].n, prev)
			continue
		}
		ratio := float64(cur) / float64(prev)
		t.Logf("N=%d -> N=%d: %.2fx (%v -> %v)", pts[i-1].n, pts[i].n, ratio, prev, cur)
		if ratio > ceiling {
			t.Errorf("extraction scaled %.2fx from N=%d to N=%d (%v -> %v); "+
				"linear is 2.0x and quadratic 4.0x, so this is superlinear beyond noise",
				ratio, pts[i-1].n, pts[i].n, prev, cur)
		}
	}
}

// TestDeepButBoundedNestingIsCheap: a document at the depth bound must cost the bound,
// not the document.
//
// MaxDepth stops the DESCENT, and the loop stops with it. Without that, a 200k-deep
// nest would be 200k stack pushes and a slice that grows for the whole file.
func TestDeepButBoundedNestingIsCheap(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg">` + strings.Repeat("<g>", 500000) + "</svg>"
	start := time.Now()
	c, err := ExtractFromBytes("deep.svg", []byte(body))
	el := time.Since(start)
	if err != nil {
		t.Fatalf("deep nest errored: %v", err)
	}
	if !c.Truncated {
		t.Error("a 500,000-deep document was not marked truncated, so the depth bound did not fire")
	}
	t.Logf("500,000 nested <g> in %v (%d bytes)", el, len(body))
	// Generous, because the whole point is that it is not proportional to the file.
	if el > 10*time.Second {
		t.Errorf("the depth bound took %v; it should stop at MaxDepth (%d), not walk the document", el, MaxDepth)
	}
}
