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

// ClusterMembersKey is the metadata key a validator sets to the constituent matches a
// consolidated finding replaced, so redaction can still reach the real spans.
//
// The SOCIAL_MEDIA validator sets it when clustering collapses several handles into one
// SOCIAL_MEDIA_CLUSTER finding. Validators write the literal "cluster_members" rather
// than importing this package (they must not — see the note in
// socialmedia.leanClusterMembers), so the two must stay in sync.
const ClusterMembersKey = "cluster_members"

// ExpandClusterMatches returns a copy of matches with every consolidated cluster
// replaced by the constituent matches it was built from.
//
// Why this exists: a cluster's Text is a RENDERED SUMMARY, not a span of the document —
// "twitter: janedoe | linkedin: janedoe" occurs nowhere in the file. Every redactor
// locates a match by searching for its Text, so the cluster masks nothing, and the real
// spans were already dropped when the validator replaced them. Measured on a 3-line
// fixture with two clustered handles: one HIGH finding at 95% and a "redacted" file
// BYTE-IDENTICAL to the input, for simple, synthetic AND format_preserving. See #289.
//
// Unlike RestoreBoundedMatchText, restoring to Context.FullLine is NOT sufficient here: a
// cluster spans several lines (twitter on line 1, linkedin on line 3) while LineNumber and
// FullLine carry only the primary sub-match's line, so a full-line restore would mask one
// line and leave the rest in the clear.
//
// Fail-safe direction, matching its sibling: this can only WIDEN what gets redacted. A
// cluster whose members are missing or empty is passed through unchanged rather than
// dropped, so a cluster is never silently removed from the redaction input — it simply
// keeps today's behaviour of matching nothing. The input slice and its Match structs are
// not mutated, so formatters still report the single consolidated finding and the finding
// count does not change.
func ExpandClusterMatches(matches []detector.Match) []detector.Match {
	first := -1
	for i := range matches {
		if len(clusterMembers(&matches[i])) > 0 {
			first = i
			break
		}
	}
	if first == -1 {
		return matches // common case: no clusters, zero copies
	}

	out := make([]detector.Match, 0, len(matches)+4)
	out = append(out, matches[:first]...)
	for i := first; i < len(matches); i++ {
		if members := clusterMembers(&matches[i]); len(members) > 0 {
			out = append(out, members...)
			continue
		}
		out = append(out, matches[i])
	}
	return out
}

// clusterMembers returns the constituent matches recorded on a consolidated finding, or
// nil when it is not a cluster.
//
// Members carrying an empty Text are skipped: they cannot be located, and passing one on
// would only add a match that silently redacts nothing.
func clusterMembers(m *detector.Match) []detector.Match {
	if m.Metadata == nil {
		return nil
	}
	raw, ok := m.Metadata[ClusterMembersKey].([]detector.Match)
	if !ok {
		return nil
	}
	out := make([]detector.Match, 0, len(raw))
	for i := range raw {
		if raw[i].Text != "" {
			out = append(out, raw[i])
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
