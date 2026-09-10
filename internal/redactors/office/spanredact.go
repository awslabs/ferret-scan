// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"bytes"
	"encoding/xml"
	"io"
	"sort"
	"strings"
)

// charSpan maps one character-data token's place in the run-joined text back to its bytes on disk.
//
// [runStart,runEnd) of the concatenated character data came from [srcStart,srcEnd) of the part. Both
// ranges are half-open. The two are NOT the same length when the token holds escaped text — `&amp;` is
// five source bytes and one decoded byte — which is why nothing here does offset arithmetic across the
// boundary. See the note on rewriteSpan.
type charSpan struct {
	runStart, runEnd int
	srcStart, srcEnd int
}

// partSpans tokenises an XML part once and returns the run-joined text with a span per character-data
// token.
//
// runText is byte-identical to decodedPartText's second return value, deliberately: that is the view the
// depth-1 residue guard judges and the view the scanner's extractor models, so a value visible to the
// guard is locatable here. The two are pinned together by TestPartSpansAgreeWithDecodedPartText.
//
// Offsets come from dec.InputOffset() read either side of Token(), which brackets a token's byte span
// exactly -- the same idiom rewritePartText already uses.
//
// ok is false for a part encoding/xml refuses, which is the same signal decodedPartText gives and leaves
// the caller's behaviour unchanged for such a part.
func partSpans(content []byte, accept func(path []string) bool) (runText string, spans []charSpan, ok bool) {
	var runs strings.Builder
	runs.Grow(len(content) / 2)

	var path []string
	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, false
		}
		end := int(dec.InputOffset())

		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
		case xml.CharData:
			if len(t) == 0 {
				continue
			}
			// accept keeps this view inside the elements the redactor is ALLOWED to rewrite.
			//
			// Not cosmetic. docProps' vt:blob holds base64, and this repo deliberately REFUSES a value
			// found there rather than rewriting it, because a replacement inside base64 produces invalid
			// base64. With an unfiltered view the locate fallback claimed such a part, the value was
			// rewritten, and the file was written where it must be refused --
			// TestResidueRefusalNamesTypesNotValues caught exactly that during development.
			//
			// nil accepts everything, which is what a residue-style view wants: it must be able to see a
			// value anywhere, including in a family nothing may rewrite.
			if accept != nil && !accept(path) {
				continue
			}
			runStart := runs.Len()
			runs.Write(t)
			spans = append(spans, charSpan{
				runStart: runStart,
				runEnd:   runs.Len(),
				srcStart: start,
				srcEnd:   end,
			})
		}
	}
	return runs.String(), spans, true
}

// spanEdit is one contiguous replacement in the part's source bytes.
type spanEdit struct {
	srcStart, srcEnd int
	with             []byte
}

// subEdit is a replacement inside ONE token's decoded text, in that token's own coordinates.
type subEdit struct {
	lo, hi int
	with   string
}

// redactAcrossRuns removes reported values that are split across adjacent character-data tokens, which
// no per-token replacer can reach.
//
// # The defect
//
// rewritePartText matches each token's decoded text independently, so a value stored as
//
//	<w:t xml:space="preserve">SSN: </w:t><w:r><w:t>456-78</w:t></w:r><w:r><w:t>-1234</w:t></w:r>
//
// is in no single token and is never matched -- while the SCANNER, whose extractor strips tags and
// inserts nothing between runs, reports it at confidence 100. Before this the file was refused by the
// fail-closed residue guard: honest, but it also denied redaction to every OTHER value in the same
// document, so one split value cost the whole file (#627).
//
// # Why whole tokens are re-escaped rather than spliced precisely
//
// A token's decoded length and its source length differ whenever it holds an entity or a character
// reference, so mapping a decoded offset to a source offset INSIDE a token is not offset arithmetic. The
// RTF span map (#604) handles that by treating a non-1:1 span as atomic and taking it whole, and that
// rule would CORRUPT office: for `<w:t>Smith &amp; Co SSN: 456-7&#56;</w:t>` the token is 30 source
// bytes against 22 decoded, so "take it whole" deletes `Smith & Co SSN: ` along with the value.
//
// So this rebuilds the token's decoded text with the affected range replaced, re-escapes ALL of it, and
// splices over the token's whole source span. That is exactly what rewritePartText already does for a
// single-token rewrite (it writes escapeCharData(replaced) over [start,end)), so the convention is
// established rather than invented, and both paths therefore normalise a token's escaping identically.
//
// # Order
//
// Edits are applied right-to-left by source offset, so an earlier edit's length change cannot invalidate
// a later edit's offsets. Within one token the sub-edits are applied right-to-left for the same reason.
//
// Returns the rewritten part and the number of split occurrences removed.
func redactAcrossRuns(content []byte, values []string, repl map[string]string, accept func(path []string) bool) ([]byte, int) {
	if len(values) == 0 {
		// Nothing was reported as split for this part, which is the overwhelmingly common case. Returning
		// before tokenising keeps this pass free for a document with no split values.
		return content, 0
	}
	runText, spans, ok := partSpans(content, accept)
	if !ok || len(spans) < 2 || runText == "" {
		// Fewer than two tokens cannot hold a split value, and an untokenisable part is left to the
		// existing path -- both are the no-op case, returned without copying.
		return content, 0
	}

	// Sub-edits per token index. A token can be touched by more than one occurrence, and by occurrences
	// of different values, so they accumulate rather than being applied as they are found.
	subs := map[int][]subEdit{}
	occurrences := 0

	// covered tracks which runText bytes an accepted occurrence already owns, so two overlapping values
	// cannot both rewrite the same region and produce nonsense. Values arrive longest-first from the
	// caller, so the longer value wins -- the same precedence the strings.Replacer path has.
	covered := make([]bool, len(runText))

	for _, v := range values {
		if v == "" {
			continue
		}
		with, hasRepl := repl[v]
		if !hasRepl {
			continue
		}
		for from := 0; ; {
			i := strings.Index(runText[from:], v)
			if i < 0 {
				break
			}
			a := from + i
			b := a + len(v)
			from = a + 1 // overlapping occurrences of the same value are considered, not skipped

			k0, k1 := spanRange(spans, a, b)
			if k0 < 0 || k0 == k1 {
				// Not found in any span, or entirely inside one token.
				//
				// A single-token match is rewritePartText's job, and this skip is a SEPARATION OF
				// CONCERNS rather than a correctness guard: a mutation removing it SURVIVES the suite,
				// and honestly so. Handling such a match here produces the same bytes -- the value is
				// masked once either way, and both paths re-escape through escapeCharData -- so the only
				// difference is doing the work twice. Recorded rather than papered over with an assertion
				// that would be testing a distinction without a difference.
				continue
			}
			if anyCovered(covered, a, b) {
				continue
			}

			for k := k0; k <= k1; k++ {
				lo, hi := overlap(spans[k], a, b)
				if lo == hi {
					continue
				}
				// The replacement lands in the FIRST token; the rest of the value is deleted. Putting it
				// in one place keeps the masked value contiguous and leaves the markup between the runs
				// -- fonts, language, spellcheck state -- untouched.
				sub := subEdit{lo: lo - spans[k].runStart, hi: hi - spans[k].runStart}
				if k == k0 {
					sub.with = with
				}
				subs[k] = append(subs[k], sub)
			}
			for i := a; i < b; i++ {
				covered[i] = true
			}
			occurrences++
		}
	}

	if occurrences == 0 {
		return content, 0
	}

	edits := make([]spanEdit, 0, len(subs))
	for k, list := range subs {
		edits = append(edits, rewriteSpan(runText, spans[k], list))
	}
	return applyEdits(content, edits), occurrences
}

// spanRange returns the first and last span indices touched by [a,b) of the run text, or (-1,-1).
func spanRange(spans []charSpan, a, b int) (int, int) {
	first := sort.Search(len(spans), func(i int) bool { return spans[i].runEnd > a })
	if first == len(spans) || spans[first].runStart >= b {
		return -1, -1
	}
	last := first
	for last+1 < len(spans) && spans[last+1].runStart < b {
		last++
	}
	return first, last
}

// overlap returns the intersection of a span with [a,b), in run-text coordinates.
func overlap(s charSpan, a, b int) (int, int) {
	lo, hi := s.runStart, s.runEnd
	if a > lo {
		lo = a
	}
	if b < hi {
		hi = b
	}
	if hi < lo {
		hi = lo
	}
	return lo, hi
}

// anyCovered reports whether [a,b) intersects a region an accepted occurrence already owns.
func anyCovered(covered []bool, a, b int) bool {
	for i := a; i < b && i < len(covered); i++ {
		if covered[i] {
			return true
		}
	}
	return false
}

// rewriteSpan builds the replacement bytes for one token: its decoded text with every sub-edit applied,
// re-escaped in full.
//
// Sub-edits are applied right-to-left so an earlier one's length change cannot move a later one.
func rewriteSpan(runText string, s charSpan, list []subEdit) spanEdit {
	decoded := runText[s.runStart:s.runEnd]

	sort.Slice(list, func(i, j int) bool { return list[i].lo > list[j].lo })
	for _, e := range list {
		if e.lo < 0 || e.hi > len(decoded) || e.lo > e.hi {
			continue // defensive: a bad range is skipped rather than allowed to slice out of bounds
		}
		decoded = decoded[:e.lo] + e.with + decoded[e.hi:]
	}

	var buf bytes.Buffer
	buf.Grow(len(decoded) + len(decoded)/8)
	escapeCharData(&buf, decoded)
	return spanEdit{srcStart: s.srcStart, srcEnd: s.srcEnd, with: buf.Bytes()}
}

// applyEdits splices every edit into content, right to left.
func applyEdits(content []byte, edits []spanEdit) []byte {
	sort.Slice(edits, func(i, j int) bool { return edits[i].srcStart > edits[j].srcStart })

	out := make([]byte, 0, len(content)+len(content)/8)
	out = append(out, content...)
	for _, e := range edits {
		if e.srcStart < 0 || e.srcEnd > len(out) || e.srcStart > e.srcEnd {
			continue // defensive, for the same reason as rewriteSpan
		}
		tail := append([]byte(nil), out[e.srcEnd:]...)
		out = append(out[:e.srcStart], e.with...)
		out = append(out, tail...)
	}
	return out
}

// runJoinedIndex caches each XML part's run-joined text for one document.
//
// Built lazily and only on the fallback path below, which is entered once per distinct value that the
// space-separated view could not locate. Without the cache that path is O(values x parts x part size);
// with it, each part is tokenised at most once per document.
type runJoinedIndex struct {
	byPart map[string]string
}

func newRunJoinedIndex() *runJoinedIndex { return &runJoinedIndex{byPart: map[string]string{}} }

// partsHoldingRunJoined returns the XML parts whose RUN-JOINED text contains value, in deterministic
// order.
//
// This is the fallback for a value the redactor's own extraction cannot see.
// OfficeRedactor.extractTextFromXML trims each character-data token and writes a SPACE between text
// elements, so a value split across adjacent runs reads "456-78 -1234" there and strings.Index can never
// find it -- while the SCANNER's extractor joins runs with nothing, sees "456-78-1234", and reports it at
// confidence 100. The two views of the same document disagree, and locateMatch was failing on that
// disagreement rather than on anything about the value (#627).
//
// Deliberately additive: the space-separated view and its textPositions are untouched, so every value
// that locates today still locates the same way and no offset moves. This only answers "which part holds
// it" for values that found nothing at all.
func (idx *runJoinedIndex) partsHoldingRunJoined(files map[string][]byte, value string, accept func(path []string) bool) []string {
	if value == "" {
		return nil
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic: the parts list reaches the audit record

	var holding []string
	for _, name := range names {
		if !strings.HasSuffix(name, ".xml") && !strings.HasSuffix(name, ".rels") {
			continue
		}
		runText, cached := idx.byPart[name]
		if !cached {
			if rt, _, ok := partSpans(files[name], accept); ok {
				runText = rt
			}
			idx.byPart[name] = runText
		}
		if runText != "" && strings.Contains(runText, value) {
			holding = append(holding, name)
		}
	}
	return holding
}
