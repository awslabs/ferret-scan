// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// MatchTextTruncatedKey is the metadata key a validator sets (true) when it
// bounded a consolidated finding's Text for display instead of carrying the
// full matched span. The INTELLECTUAL_PROPERTY validator sets it when a
// same-line legal-notice consolidation would otherwise emit the entire
// (pathologically long) line as Match.Text.
const MatchTextTruncatedKey = "match_text_truncated"

// RestoreBoundedMatchText returns a copy of matches where any match flagged
// with metadata[MatchTextTruncatedKey]=true has its Text restored to the full
// line it was consolidated from (Context.FullLine, trimmed).
//
// Why this exists: redaction locates each match by searching for Match.Text in
// the document (plaintext findMatchPosition, office redactMatch). A bounded
// display text like "Amazon Confidential and Trademark [+218 more matches on
// line]" does not occur in the document, so the match would be silently
// skipped and the ENTIRE line of sensitive content would survive redaction.
// Restoring the full-line span before masking reproduces the pre-bounding
// behavior byte-for-byte: the whole consolidated legal notice is masked.
//
// Fail-safe direction: this can only WIDEN what gets redacted (the full line
// contains every original fragment), never narrow it. Matches without the
// flag, or without a usable FullLine, are passed through unchanged. The input
// slice and its Match structs are not mutated — callers (worker pool,
// formatters) still see the bounded display text.
func RestoreBoundedMatchText(matches []detector.Match) []detector.Match {
	restored := -1
	for i := range matches {
		if isBoundedMatch(&matches[i]) {
			restored = i
			break
		}
	}
	if restored == -1 {
		return matches // common case: nothing to restore, zero copies
	}

	out := make([]detector.Match, len(matches))
	copy(out, matches)
	for i := restored; i < len(out); i++ {
		if isBoundedMatch(&out[i]) {
			out[i].Text = strings.TrimSpace(out[i].Context.FullLine)
		}
	}
	return out
}

// isBoundedMatch reports whether the match carries a bounded (truncated)
// display text that must be restored to its full-line span for redaction.
func isBoundedMatch(m *detector.Match) bool {
	if m.Metadata == nil || m.Context.FullLine == "" {
		return false
	}
	truncated, ok := m.Metadata[MatchTextTruncatedKey].(bool)
	return ok && truncated && strings.TrimSpace(m.Context.FullLine) != ""
}
