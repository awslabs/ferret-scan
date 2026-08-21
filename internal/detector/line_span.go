// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import "strings"

// LineSpan is where a match sits within its own line.
//
// LineID identifies the containing line by BOTH its reported number and its text.
// Offsets carrying different LineIDs are in different coordinate systems and must
// never be compared: an Office package numbers lines per part, so a metadata match
// in docProps/core.xml and a body match in word/document.xml both arrive as
// "line 1" with offsets measured against different strings. Comparing those once
// dropped a body match whose span happened to fall numerically inside a metadata
// span, leaving an SSN in cleartext.
type LineSpan struct {
	LineID int // 0 when unresolved; only compare offsets within one LineID
	Start  int // 0-based byte offset within the line
	End    int // 0-based, exclusive
	OK     bool
}

// ResolveLineSpans assigns every match to a concrete occurrence of its text within
// its line.
//
// Repeated (line, text) pairs consume successive occurrences left to right, so two
// identical values on one line resolve to DIFFERENT offsets instead of both
// claiming the first. A bare strings.Index cannot do this, which is why two
// findings for the same value on one line were indistinguishable in every reported
// field and why SARIF pointed both at the first occurrence.
//
// A match whose position cannot be resolved (empty line, empty text, text absent)
// gets OK=false rather than a guessed offset. When the cursor has consumed every
// occurrence the first one is reused, so a match is never dropped for want of a
// position — but the cursor is deliberately NOT advanced in that case, matching the
// long-standing behaviour of the redaction overlap pass.
//
// The returned slice is parallel to matches.
func ResolveLineSpans(matches []Match) []LineSpan {
	spans := make([]LineSpan, len(matches))
	if len(matches) == 0 {
		return spans
	}

	// The line id is interned rather than carried as a string: callers run O(n²)
	// containment loops over these spans, and comparing full line strings there
	// made a dense single-line document 48x slower. Interning pays the string hash
	// once per match and reduces the hot comparison to an int.
	type lineKey struct {
		number int
		text   string
	}
	lineIDs := make(map[lineKey]int, len(matches))
	cursor := make(map[int]map[string]int, len(matches))

	// Memo for the immediately preceding line.
	//
	// The map key contains the whole line TEXT, so every lookup hashes the line: that
	// is O(line length) per match, and therefore O(matches x line length) for a dense
	// single line — quadratic. Measured in isolation on one line, 4x input cost 18.5x,
	// where linear is 4x. The interning below removes quadratic string COMPARISON from
	// the containment loop, but it cannot remove the hashing, because the hash is what
	// builds the id.
	//
	// Matches from one line arrive together, so remembering just the last line collapses
	// the common case to a length check plus a pointer compare: every match on a line
	// shares the identical FullLine string, and Go's string equality short-circuits on
	// equal length and equal data pointer without reading the bytes. A line change still
	// pays one hash, which is O(total content) overall — linear.
	var (
		lastLine   string
		lastNumber int
		lastID     int
	)

	// Match indices grouped by line, in arrival order.
	//
	// Grouping is what lets a DENSE line be resolved with one pass over it instead of one pass per
	// distinct value (see resolveByIndex). It costs nothing extra: the interning above already has
	// to visit every match, and the memo means a line is hashed once rather than once per match.
	perLine := make(map[int][]int, len(lineIDs))
	lineText := make(map[int]string, len(lineIDs))

	for i := range matches {
		m := &matches[i]
		line := m.Context.FullLine
		if line == "" || m.Text == "" {
			continue
		}

		var lineID int
		if lastID != 0 && m.LineNumber == lastNumber && line == lastLine {
			lineID = lastID
		} else {
			k := lineKey{number: m.LineNumber, text: line}
			var ok bool
			lineID, ok = lineIDs[k]
			if !ok {
				lineID = len(lineIDs) + 1 // 1-based; 0 is the zero value of LineSpan.LineID
				lineIDs[k] = lineID
			}
			lastLine, lastNumber, lastID = line, m.LineNumber, lineID
		}

		perLine[lineID] = append(perLine[lineID], i)
		lineText[lineID] = line
	}

	for lineID, idxs := range perLine {
		line := lineText[lineID]
		if useIndex(line, matches, idxs) {
			resolveByIndex(line, lineID, matches, idxs, spans)
			continue
		}
		resolveByRescan(line, lineID, matches, idxs, spans, cursor)
	}

	return spans
}

// resolveByRescan is the original strategy: each (line, text) keeps a cursor and every match
// searches forward from it.
//
// Kept, and still the default for ordinary input, because it walks the line only as far as the
// match and allocates nothing per line. Its weakness is one specific shape — see useIndex.
func resolveByRescan(line string, lineID int, matches []Match, idxs []int, spans []LineSpan, cursor map[int]map[string]int) {
	byText, ok := cursor[lineID]
	if !ok {
		byText = make(map[string]int)
		cursor[lineID] = byText
	}

	for _, i := range idxs {
		text := matches[i].Text
		from := byText[text]
		idx := strings.Index(line[from:], text)
		if idx < 0 {
			// Fall back to the first occurrence rather than losing the position.
			idx = strings.Index(line, text)
			if idx < 0 {
				continue
			}
			spans[i] = LineSpan{LineID: lineID, Start: idx, End: idx + len(text), OK: true}
			continue
		}
		start := from + idx
		spans[i] = LineSpan{LineID: lineID, Start: start, End: start + len(text), OK: true}
		byText[text] = start + len(text)
	}
}

// useIndex reports whether indexing the line beats rescanning it, by estimating both.
//
// Rescanning costs roughly one traversal of the line per DISTINCT value, because each value's
// cursor starts at zero and strings.Index walks from the line start to that value — averaging half
// the line, so about distinct/2 traversals.
//
// Indexing costs one traversal per distinct value LENGTH: the single pass tests, at each byte, one
// candidate substring per length, and hashing a candidate of length L is O(L). So the estimate is
// the SUM of the distinct lengths.
//
// Comparing the two directly is what keeps this from being a regression on ordinary input. A line
// with a handful of matches has few distinct values but a similar number of distinct lengths, so
// rescanning wins and is chosen; a line with thousands of distinct values of a few shapes — the
// machine-generated case — inverts that by orders of magnitude. For 16,000 IP addresses of 9
// distinct lengths the estimates are ~99 against ~8,000.
func useIndex(line string, matches []Match, idxs []int) bool {
	// Below this there is nothing to amortise a line pass against, and the map allocations would
	// dominate a cost that is already microseconds.
	const minMatches = 64
	if len(idxs) < minMatches || len(line) < 1024 {
		return false
	}

	distinct := make(map[string]struct{}, len(idxs))
	lengths := make(map[int]struct{}, 8)
	for _, i := range idxs {
		t := matches[i].Text
		distinct[t] = struct{}{}
		lengths[len(t)] = struct{}{}
	}

	sumLengths := 0
	for l := range lengths {
		sumLengths += l
	}
	return sumLengths < len(distinct)/2
}

// resolveByIndex locates every occurrence of every match value on this line in ONE pass, then hands
// them out in arrival order.
//
// This is the "multi-pattern single pass" the complexity guard for this function named as the only
// way to make the many-distinct-values shape linear. The trick that makes one pass enough is to key
// on LENGTH rather than on value: at each byte, for each distinct value length present, look up that
// candidate substring in a set. The cost is therefore independent of how MANY values there are,
// which is the term that made rescanning quadratic.
//
// The hand-out rules reproduce resolveByRescan exactly, because consumers depend on them:
//
//   - repeated values consume successive occurrences left to right;
//   - an occurrence that starts before the previous one ended is skipped, matching a cursor that
//     advances past the whole match (so "aa" in "aaa" yields one occurrence, not two);
//   - when the occurrences are exhausted the FIRST is reused and nothing advances;
//   - a value that does not appear at all leaves OK=false rather than a guessed offset.
func resolveByIndex(line string, lineID int, matches []Match, idxs []int, spans []LineSpan) {
	distinct := make(map[string]struct{}, len(idxs))
	lengths := make([]int, 0, 8)
	seenLen := make(map[int]struct{}, 8)
	for _, i := range idxs {
		t := matches[i].Text
		distinct[t] = struct{}{}
		if _, ok := seenLen[len(t)]; !ok {
			seenLen[len(t)] = struct{}{}
			lengths = append(lengths, len(t))
		}
	}

	occurrences := make(map[string][]int, len(distinct))
	for pos := 0; pos < len(line); pos++ {
		remaining := len(line) - pos
		for _, l := range lengths {
			if l > remaining {
				continue
			}
			candidate := line[pos : pos+l]
			if _, ok := distinct[candidate]; ok {
				occurrences[candidate] = append(occurrences[candidate], pos)
			}
		}
	}

	next := make(map[string]int, len(distinct))
	end := make(map[string]int, len(distinct))
	for _, i := range idxs {
		text := matches[i].Text
		found := occurrences[text]
		if len(found) == 0 {
			continue // absent from the line: no position is better than a wrong one
		}

		p := next[text]
		for p < len(found) && found[p] < end[text] {
			p++
		}
		if p >= len(found) {
			// Exhausted. Reuse the first occurrence and do NOT advance, matching the
			// long-standing behaviour of the redaction overlap pass.
			//
			// Not advancing is unobservable HERE — next[text] is already past the end, so every
			// later match of this value takes this branch too — but it is observable in
			// resolveByRescan, where leaving the cursor alone is what lets the fallback keep
			// returning the first occurrence. The two are written the same way on purpose, so
			// neither can be "simplified" into disagreeing with the other.
			first := found[0]
			spans[i] = LineSpan{LineID: lineID, Start: first, End: first + len(text), OK: true}
			continue
		}

		start := found[p]
		spans[i] = LineSpan{LineID: lineID, Start: start, End: start + len(text), OK: true}
		next[text] = p + 1
		end[text] = start + len(text)
	}
}

// AssignLineColumns records each match's position on its line as 1-based byte
// columns, for every match that does not already carry one.
//
// This is what makes two findings for the same value on one line distinguishable.
// Without it they differ in no reported field, so:
//
//   - SARIF gave both the FIRST occurrence's region, double-annotating those
//     characters and never annotating the second occurrence's (see #321);
//   - gitlab-sast hashed (file, line, type) into its vulnerability id, so the two
//     collapsed to one id and GitLab dropped half the findings on ingest (#328).
//
// Matches that already have a StartColumn are left alone, so a validator that knows
// its own offset — most already compute one and discard it — can set it directly and
// this becomes a no-op for that match.
func AssignLineColumns(matches []Match) {
	spans := ResolveLineSpans(matches)
	for i := range matches {
		if matches[i].StartColumn > 0 {
			continue // already positioned by the producer
		}
		if !spans[i].OK {
			continue // no position is better than a wrong one
		}
		matches[i].StartColumn = spans[i].Start + 1
		matches[i].EndColumn = spans[i].End + 1
	}
}
