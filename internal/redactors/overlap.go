// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"sort"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// ResolveOverlaps drops any match whose span is fully contained within a
// larger match on the same line, keeping only the wider (more-covering) span.
//
// Why this exists: redaction applies matches one at a time by locating each
// match's text in the (progressively mutated) content. When two matches
// overlap — e.g. a CREDIT_CARD match "4532 0151 1283 0366" and a PHONE match
// "0151 1283 0366" the phone validator also fired on — applying the smaller one
// first rewrites the text so the larger one can no longer be found, and its
// redaction is silently skipped. That left the un-redacted head of the larger
// span (here, the card's BIN) exposed in the output.
//
// Collapsing to the widest span is always leak-safe: the surviving match covers
// the dropped match's region too, so no sensitive sub-span is left in the clear.
//
// Matches are located within their line via detector.Match.Context.FullLine.
// A match whose position cannot be determined (empty FullLine, text not found)
// is kept as-is and never subsumes another, so callers see no behavior change
// for inputs that don't overlap. Input order is preserved for survivors.
//
// Containment is only ever tested between matches from the SAME line of the
// SAME source text. LineNumber alone does not identify a line: an Office
// package reports line numbers per part, so a metadata match in
// docProps/core.xml and a body match in word/document.xml both arrive as
// "line 1" with offsets measured against different strings. Comparing those
// offsets is meaningless, and when the body span happened to fall numerically
// inside the metadata span the body match was dropped — leaving real PII
// (an SSN) in cleartext in the "redacted" output. The line's own text is
// therefore part of its identity: two matches whose FullLine differs are on
// different lines by definition and can never subsume one another.
func ResolveOverlaps(matches []detector.Match) []detector.Match {
	if len(matches) < 2 {
		return matches
	}

	// Assign each match to a concrete occurrence of its text within the line.
	// Repeated (line, text) pairs consume successive occurrences left-to-right so
	// two identical matches don't both claim the first occurrence, and each span
	// carries an interned line id so offsets are only ever compared within one
	// coordinate system.
	//
	// Shared with the reporting path, which needs exactly the same resolution to
	// give two findings on one line distinguishable columns. The id is interned
	// rather than carrying the line text because the containment loop below is
	// O(n²) in the number of matches, and comparing full line strings there made a
	// dense single-line document 48x slower (1.1ms -> 55ms for 800 matches on one
	// long line).
	spans := detector.ResolveLineSpans(matches)

	// Consider wider spans first so a contained match is always tested against
	// the largest span that could subsume it.
	order := make([]int, len(matches))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		sa, sb := spans[order[a]], spans[order[b]]
		return (sa.End - sa.Start) > (sb.End - sb.Start)
	})

	keep := make([]bool, len(matches))
	var accepted []detector.LineSpan
	for _, i := range order {
		s := spans[i]
		if !s.OK {
			// Unresolvable position: keep it, and don't let it subsume others.
			keep[i] = true
			continue
		}
		contained := false
		for _, a := range accepted {
			if a.LineID == s.LineID && a.Start <= s.Start && s.End <= a.End &&
				(a.End-a.Start) > (s.End-s.Start) {
				contained = true
				break
			}
		}
		if contained {
			continue // dropped: fully inside a wider surviving match
		}
		keep[i] = true
		accepted = append(accepted, s)
	}

	out := make([]detector.Match, 0, len(matches))
	for i := range matches {
		if keep[i] {
			out = append(out, matches[i])
		}
	}
	return out
}
