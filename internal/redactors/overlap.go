// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"sort"
	"strings"

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
func ResolveOverlaps(matches []detector.Match) []detector.Match {
	if len(matches) < 2 {
		return matches
	}

	// span records where a match sits within its line, or ok=false when the
	// position could not be resolved.
	type span struct {
		line       int
		start, end int
		ok         bool
	}

	// Assign each match to a concrete occurrence of its text within the line.
	// Repeated (line, text) pairs consume successive occurrences left-to-right
	// so two identical matches don't both claim the first occurrence.
	cursor := make(map[int]map[string]int, len(matches))
	spans := make([]span, len(matches))
	for i := range matches {
		m := &matches[i]
		line := m.Context.FullLine
		if line == "" || m.Text == "" {
			continue
		}
		byText, ok := cursor[m.LineNumber]
		if !ok {
			byText = make(map[string]int)
			cursor[m.LineNumber] = byText
		}
		from := byText[m.Text]
		idx := strings.Index(line[from:], m.Text)
		if idx < 0 {
			// Fall back to the first occurrence rather than losing the match.
			idx = strings.Index(line, m.Text)
			if idx < 0 {
				continue
			}
			spans[i] = span{line: m.LineNumber, start: idx, end: idx + len(m.Text), ok: true}
			continue
		}
		start := from + idx
		spans[i] = span{line: m.LineNumber, start: start, end: start + len(m.Text), ok: true}
		byText[m.Text] = start + len(m.Text)
	}

	// Consider wider spans first so a contained match is always tested against
	// the largest span that could subsume it.
	order := make([]int, len(matches))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		sa, sb := spans[order[a]], spans[order[b]]
		return (sa.end - sa.start) > (sb.end - sb.start)
	})

	keep := make([]bool, len(matches))
	var accepted []span
	for _, i := range order {
		s := spans[i]
		if !s.ok {
			// Unresolvable position: keep it, and don't let it subsume others.
			keep[i] = true
			continue
		}
		contained := false
		for _, a := range accepted {
			if a.line == s.line && a.start <= s.start && s.end <= a.end &&
				(a.end-a.start) > (s.end-s.start) {
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
