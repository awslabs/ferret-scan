// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"strings"
	"unicode/utf8"
)

// ContextSnippetCap bounds the source line a formatter may embed per finding.
//
// # Why a cap is needed at all
//
// The SARIF and gitlab-sast formatters embed `Context.FullLine` verbatim for every
// finding when --show-match is set. On a document whose content sits on ONE long line
// that makes the report quadratic — findings x line length — because every finding
// carries a copy of the same line.
//
// Measured on byte-identical content, 400 findings, --show-match against plain:
//
//	200 separate lines   sarif x1.3   gitlab-sast x1.0
//	the same on 1 line   sarif x15.1  gitlab-sast x12.6
//
// and on a real 892KB single-line export with 2,633 findings: gitlab-sast 3.0MB ->
// 771MB (x254) and sarif 4.8MB -> 1.54GB (x320). json is unaffected (x1) because it
// does not embed the line, which is what localises this to these two formatters. See
// #521.
//
// # Why this number
//
// Measured over 57,790 findings in 1,009 real files, the length of the line carrying a
// finding is p50 647 B, p90 3,424 B, p99 297,353 B, max 1,790,434 B — so the tail is five
// orders of magnitude past the median and no single number is free. Two things were
// measured against each other: how much ordinary output changes, and whether the ratio
// that defines the defect actually comes down.
//
//	cap     findings with a trimmed snippet    worst --show-match/plain ratio
//	 256 B                    75.4%                        (below 512)
//	 512 B                    56.3%                            1.79x
//	1024 B                    38.8%                            2.43x
//	2048 B                    24.0% (interpolated)             3.73x
//	4096 B                     8.6%                            6.31x
//
// 4096 is the tempting choice because it leaves 91.4% of output byte-identical — but the
// ratio stays above 6x, so it does not actually fix the thing that was filed. 1024 does:
// it is twice the p50, so the MEDIAN line is still shown whole, and it brings the worst
// ratio to 2.43x with headroom under the 4x bound the formatter test enforces.
//
// It is also proportionate to the repo's existing precedent. consolidatedTextCap in the
// intellectual-property validator bounds a match's DISPLAY TEXT at 256 B; 1024 for the
// surrounding line is the same order, four times larger for a value that is four times the
// job.
//
// This bounds DISPLAY only. The finding's own Text, line number and offsets are untouched,
// so nothing about detection or redaction depends on it.
const ContextSnippetCap = 1024

// snippetEllipsis marks a trimmed edge.
//
// Bounding is always visible, never silent — the same contract
// boundedConsolidatedText holds in the intellectual-property validator. A consumer
// that sees a snippet must be able to tell whether it is the whole line.
const snippetEllipsis = "..."

// BoundedContextSnippet returns the part of line worth showing for a finding whose
// matched text is match, capped at ContextSnippetCap bytes.
//
// A line already within the cap is returned UNCHANGED, which is the common case: 61.2% of
// real findings are unaffected, including the median line.
//
// When trimming is needed the window is centred on the match, because a snippet whose
// purpose is to show the match in context is useless if it shows a different part of the
// line. Both edges are marked when they are cut.
func BoundedContextSnippet(line, match string) string {
	if len(line) <= ContextSnippetCap {
		return line
	}

	// Where the match sits decides which part of the line to keep. A match that is not
	// findable in the line (a consolidated or bounded display text, or line drift) falls
	// back to the head of the line, which is the same choice the callers' own fallbacks
	// make elsewhere.
	at := strings.Index(line, match)
	if match == "" || at < 0 {
		return trimAt(line, 0, ContextSnippetCap) + snippetEllipsis
	}

	// A match longer than the cap cannot be shown whole. Keep its head: the alternative
	// is showing none of it, and the value is what the reader is looking for.
	if len(match) >= ContextSnippetCap {
		return trimAt(line, at, at+ContextSnippetCap) + snippetEllipsis
	}

	// Centre the remaining budget on the match, then push the window back inside the line
	// if centring ran past either end — so a match near the start or end of a long line
	// still gets a full-width snippet rather than a half-empty one.
	spare := ContextSnippetCap - len(match)
	start := at - spare/2
	if start < 0 {
		start = 0
	}
	end := start + ContextSnippetCap
	if end > len(line) {
		end = len(line)
		start = end - ContextSnippetCap
		if start < 0 {
			start = 0
		}
	}

	out := trimAt(line, start, end)
	if start > 0 {
		out = snippetEllipsis + out
	}
	if end < len(line) {
		out += snippetEllipsis
	}
	return out
}

// trimAt slices line[from:to], moving both bounds outward-safe so a multi-byte UTF-8
// sequence is never split. Splitting one would emit invalid UTF-8 into a JSON document,
// which encoding/json escapes into U+FFFD and which some SARIF consumers reject.
func trimAt(line string, from, to int) string {
	if from < 0 {
		from = 0
	}
	if to > len(line) {
		to = len(line)
	}
	for from < to && !utf8.RuneStart(line[from]) {
		from++
	}
	for to > from && to < len(line) && !utf8.RuneStart(line[to]) {
		to--
	}
	return line[from:to]
}
