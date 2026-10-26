// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// GroupKind says how the members of an OverlapGroup relate, which decides how the group is
// rendered (replacement.RenderGroup).
type GroupKind int

const (
	// GroupSingle is one match that strictly intersects no other match on its line, or one whose
	// position could not be resolved.
	GroupSingle GroupKind = iota

	// GroupContained has exactly one member whose span is the whole union, and every other member
	// strictly inside it: a PHONE inside a spaced card, a name inside a street address.
	GroupContained

	// GroupIdentical has two or more members whose span IS the union -- the same bytes reported by
	// more than one check, PASSPORT and SSN on one 9-digit number -- plus any member inside it.
	GroupIdentical

	// GroupPartial is a union no single member covers: two spans that cross, or a chain of them.
	GroupPartial
)

// String names the kind for logs and audit metadata.
func (k GroupKind) String() string {
	switch k {
	case GroupSingle:
		return "single"
	case GroupContained:
		return "contained"
	case GroupIdentical:
		return "identical"
	case GroupPartial:
		return "partial"
	default:
		return "unknown"
	}
}

// Metadata keys a writer records on the one RedactionMapping it emits for a multi-member group,
// so the audit trail shows every finding the write covered and not only the label it printed.
const (
	// OverlapGroupKindKey holds GroupKind.String().
	OverlapGroupKindKey = "overlap_group"
	// OverlapMemberTypesKey holds the members' types as a sorted []string, one entry per member.
	OverlapMemberTypesKey = "overlap_member_types"
)

// OverlapGroup is ONE write: the matches on one line whose spans strictly intersect, directly or
// through a chain, rendered once over the union of their bytes.
type OverlapGroup struct {
	Kind GroupKind

	// Members are indices into the slice ResolveOverlaps was given, ascending.
	Members []int

	// Spans are the members' positions within their shared line, parallel to Members. Meaningful
	// only when Resolved.
	Spans []detector.LineSpan

	// Start and End bound the union within the line, half-open.
	Start, End int

	// Resolved is false for a match whose position on its line could not be determined (no
	// FullLine, or a Text the line does not contain). Such a match is always a GroupSingle: with no
	// position it can neither be shown to overlap anything nor be merged with it.
	Resolved bool

	// Representative is the input index of the member whose label (simple) and generator
	// (synthetic) the group renders with. For GroupContained it is the widest member, as before;
	// otherwise the best member by Confidence (highest), then Type (lexicographically first), then
	// input index -- an ordering that does not depend on input order or on how many other matches
	// the file holds. For GroupIdentical it is chosen among the members that span the union.
	Representative int

	// Text is the bytes the group's single write replaces: the union, cut from the members' shared
	// line. For an unresolved single match it is the match's own Text.
	Text string
}

// IsGroup reports whether the write covers more than one finding.
func (g OverlapGroup) IsGroup() bool { return len(g.Members) > 1 }

// MemberTypes returns one type per member, sorted, for the audit trail.
func (g OverlapGroup) MemberTypes(matches []detector.Match) []string {
	out := make([]string, 0, len(g.Members))
	for _, i := range g.Members {
		out = append(out, matches[i].Type)
	}
	sort.Strings(out)
	return out
}

// Unit returns the match a writer locates and logs for this group: the representative, carrying
// the union as its Text. For a single match it is that match unchanged.
func (g OverlapGroup) Unit(matches []detector.Match) detector.Match {
	m := matches[g.Representative]
	if g.IsGroup() {
		m.Text = g.Text
		m.SecureText = nil
	}
	return m
}

// IsSecretsMember reports whether a match counts as a SECRETS-check finding inside a group.
//
// Attribution is Match.Validator, the only check attribution a Match carries today (the
// secrets validator writes "secrets"). A match with NO attribution counts as SECRETS: when
// nothing says what a value is, it is treated as the most sensitive thing it could be, so
// a group never copies a byte of it into the output.
func IsSecretsMember(m detector.Match) bool {
	return m.Validator == "" || strings.EqualFold(m.Validator, "secrets")
}

// ResolveOverlaps partitions matches into overlap groups: one per write a redactor must make.
//
// # Why one write per group
//
// Redactors used to apply matches one at a time, each located by searching for its Text in content
// earlier writes had already changed. When two matches on a line share bytes, the first write
// destroys the text the second one needs, the second is skipped, and whatever part of it the first
// did not cover stays in cleartext:
//
//	Residence: 77 August Lane, Boise ID 83702
//	US_STREET_ADDRESS "77 August Lane"   PERSON_NAME "Lane, Boise"
//	plaintext wrote  Residence: 77 August [PERSON-NAME-REDACTED] ID 83702   (head stranded)
//	Office wrote     Residence: [US_STREET_ADDRESS-REDACTED], Boise ID 83702 (tail stranded)
//
// with exit 0 and an audit reporting failed_redactions 0. Collapsing CONTAINMENT to the widest span,
// which is all this function used to do, cannot fix that: neither span contains the other. And
// for two matches on the SAME bytes (PASSPORT and SSN on one 9-digit number) it kept both, so which
// one was written decided whether format_preserving kept the last four digits -- and that was
// decided by sort.Slice's tie order, which changes at 13 elements, i.e. by how many unrelated
// findings the file happened to hold (#773).
//
// So the unit of work is the group: every match on a line whose span strictly intersects another's,
// transitively, written ONCE over the union of their bytes, located from the members' original
// offsets. How the group is rendered is replacement.RenderGroup's rule; this function only decides
// what belongs together.
//
// # What groups
//
// Only spans that strictly intersect on the SAME line. Touching spans ([0,5) and [5,9)) do not:
// each value is whole and is written by its own rendering, exactly as before. Matches on different
// lines never group, and a LineNumber alone does not identify a line: an Office package numbers
// lines per part, so a metadata match in docProps/core.xml and a body match in word/document.xml
// both arrive as "line 1" with offsets measured against different strings. Comparing those once
// dropped a body SSN whose span happened to fall numerically inside a metadata span. The line's text
// is therefore part of its identity. A match whose position cannot be resolved (empty FullLine, Text
// absent from it) is a single group of its own and never absorbs anything.
//
// # Positions
//
// detector.ResolveLineSpans places each match on a concrete occurrence of its Text within its line,
// consuming successive occurrences for repeated values. Its cursor is per TEXT, which is right for
// one check reporting a value twice but wrong when two checks report the same value: the second
// check's matches find the occurrences already consumed and fall back to the first one, so on
// `512010001 and 512010001` reported by PASSPORT and SSN both SSN matches resolved to the first
// occurrence and the second PASSPORT stood alone. Positions are therefore resolved per TYPE, so
// each check walks the line's occurrences independently and the same bytes reported by two checks
// land in one group, once per occurrence. The reporting path's columns are untouched.
//
// Groups are returned in input order of their first member, so writers that keep first-seen order
// (Office's per-part value table) see the same order as before for every match that groups with
// nothing.
func ResolveOverlaps(matches []detector.Match) []OverlapGroup {
	if len(matches) == 0 {
		return nil
	}
	spans := resolveSpansPerType(matches)

	// Resolvable matches, ordered by line, then start, then widest first: the order a single sweep
	// needs to build connected components of the "strictly intersects" relation.
	resolvable := make([]int, 0, len(matches))
	groupOf := make([]int, len(matches))
	for i := range matches {
		groupOf[i] = -1
		if spans[i].OK {
			resolvable = append(resolvable, i)
		}
	}
	sort.Slice(resolvable, func(a, b int) bool {
		sa, sb := spans[resolvable[a]], spans[resolvable[b]]
		if sa.LineID != sb.LineID {
			return sa.LineID < sb.LineID
		}
		if sa.Start != sb.Start {
			return sa.Start < sb.Start
		}
		if sa.End != sb.End {
			return sa.End > sb.End
		}
		return resolvable[a] < resolvable[b]
	})

	var components [][]int
	curLine, curEnd := 0, -1
	for _, i := range resolvable {
		s := spans[i]
		if len(components) > 0 && s.LineID == curLine && s.Start < curEnd {
			last := len(components) - 1
			components[last] = append(components[last], i)
			if s.End > curEnd {
				curEnd = s.End
			}
			continue
		}
		components = append(components, []int{i})
		curLine, curEnd = s.LineID, s.End
	}
	for gi, members := range components {
		for _, i := range members {
			groupOf[i] = gi
		}
	}

	groups := make([]OverlapGroup, 0, len(components)+len(matches)-len(resolvable))
	built := make([]bool, len(components))
	for i := range matches {
		gi := groupOf[i]
		if gi < 0 {
			groups = append(groups, OverlapGroup{
				Kind:           GroupSingle,
				Members:        []int{i},
				Spans:          []detector.LineSpan{spans[i]},
				Representative: i,
				Text:           matches[i].Text,
			})
			continue
		}
		if built[gi] {
			continue
		}
		built[gi] = true
		groups = append(groups, buildGroup(matches, spans, components[gi]))
	}
	return groups
}

// buildGroup classifies one connected component and picks its representative.
func buildGroup(matches []detector.Match, spans []detector.LineSpan, component []int) OverlapGroup {
	members := append([]int(nil), component...)
	sort.Ints(members)

	g := OverlapGroup{Members: members, Spans: make([]detector.LineSpan, len(members)), Resolved: true}
	g.Start, g.End = spans[members[0]].Start, spans[members[0]].End
	for k, i := range members {
		s := spans[i]
		g.Spans[k] = s
		if s.Start < g.Start {
			g.Start = s.Start
		}
		if s.End > g.End {
			g.End = s.End
		}
	}
	line := matches[members[0]].Context.FullLine
	g.Text = line[g.Start:g.End]

	if len(members) == 1 {
		g.Kind = GroupSingle
		g.Representative = members[0]
		return g
	}

	var spanning []int
	for _, i := range members {
		if spans[i].Start == g.Start && spans[i].End == g.End {
			spanning = append(spanning, i)
		}
	}
	switch len(spanning) {
	case 0:
		g.Kind = GroupPartial
		g.Representative = bestMember(matches, members)
	case 1:
		g.Kind = GroupContained
		g.Representative = spanning[0]
	default:
		g.Kind = GroupIdentical
		g.Representative = bestMember(matches, spanning)
	}
	return g
}

// bestMember picks the representative: highest Confidence, then Type, then input index.
//
// Nothing here depends on the order matches arrived in or on how many there are, which is the
// point: the label of a group must be a property of the group. The Phase 3 same-span arbitration
// (docs/proposals/ARCHITECTURE_AND_PLAN.md) may later change which LABEL wins; it cannot change
// which bytes a group copies, because that is decided per byte by every member (RenderGroup).
func bestMember(matches []detector.Match, candidates []int) int {
	best := candidates[0]
	for _, i := range candidates[1:] {
		a, b := matches[i], matches[best]
		switch {
		case a.Confidence > b.Confidence:
			best = i
		case a.Confidence < b.Confidence:
		case a.Type < b.Type:
			best = i
		case a.Type == b.Type && i < best:
			best = i
		}
	}
	return best
}

// resolveSpansPerType places every match on its line, resolving each TYPE's matches on their own so
// two checks reporting the same value both walk its occurrences (see ResolveOverlaps), with line
// ids interned once across all of them so offsets from different types remain comparable.
func resolveSpansPerType(matches []detector.Match) []detector.LineSpan {
	out := make([]detector.LineSpan, len(matches))

	byType := make(map[string][]int)
	var typeOrder []string
	for i := range matches {
		t := matches[i].Type
		if _, seen := byType[t]; !seen {
			typeOrder = append(typeOrder, t)
		}
		byType[t] = append(byType[t], i)
	}

	// Line ids are interned across ALL types, so offsets from two types' resolutions can be compared.
	// The key holds the whole line text, so a lookup hashes the line; the memo for the immediately
	// preceding line keeps a dense single line linear, for the reason detector.ResolveLineSpans gives
	// for its own identical memo (matches from one line arrive together, and Go's string equality
	// short-circuits on a shared data pointer).
	type lineKey struct {
		number int
		text   string
	}
	lineIDs := make(map[lineKey]int)
	var (
		lastLine   string
		lastNumber int
		lastID     int
	)
	lineID := func(m *detector.Match) int {
		if lastID != 0 && m.LineNumber == lastNumber && m.Context.FullLine == lastLine {
			return lastID
		}
		key := lineKey{number: m.LineNumber, text: m.Context.FullLine}
		id, ok := lineIDs[key]
		if !ok {
			id = len(lineIDs) + 1
			lineIDs[key] = id
		}
		lastLine, lastNumber, lastID = m.Context.FullLine, m.LineNumber, id
		return id
	}

	for _, t := range typeOrder {
		idxs := byType[t]
		sub := make([]detector.Match, len(idxs))
		for k, i := range idxs {
			sub[k] = matches[i]
		}
		spans := detector.ResolveLineSpans(sub)
		for k, i := range idxs {
			s := spans[k]
			if !s.OK {
				continue
			}
			s.LineID = lineID(&matches[i])
			out[i] = s
		}
	}
	return out
}
