// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audio

import (
	"bytes"
	"sort"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// occurrence is one span of the file to overwrite, with the bytes to write there.
type occurrence struct {
	start int
	end   int
	repl  []byte
	wide  bool // the value was found UTF-16LE encoded, so a mask must keep that width
	count int  // how many matches contributed to this span, after merging
}

// planOverwrites computes every span to overwrite, resolving overlaps.
//
// # Why this cannot be a sequential search-and-replace
//
// Reported matches OVERLAP. On a real .wav the scan reports both
//
//	SSN          "452-11-9384"
//	AUTHOR_INFO  "Contact Jane Doe SSN 452-11-9384"
//
// Replacing them one at a time against the buffer being modified loses the second one:
// masking the SSN destroys the tail of the AUTHOR_INFO string, so searching for
// AUTHOR_INFO next finds nothing, is recorded as "not located", and "Jane Doe" — which is
// only reported as part of that longer value — stays in the file. Measured before this
// existed: SSN, phone and email removed from all four formats, "Jane Doe" left in cleartext,
// exit 0.
//
// Worse, a residue check that searches the OUTPUT for each reported value is fooled the same
// way: the AUTHOR_INFO string is genuinely absent, because its own substring was altered. So
// the verification agreed with the bug.
//
// Sorting longest-first is not sufficient either. It fixes CONTAINMENT but not PARTIAL
// overlap: for "…SSN 452" and "452-11-9384" the first masks only the head of the second, and
// the untouched tail is still cleartext. This is the same mechanism as #191 — a destructive
// sequential replace over partially overlapping matches.
//
// So every occurrence is located in the ORIGINAL bytes, before anything is written, and
// overlapping spans are merged into one. A merged span is masked rather than
// format-preserved, because it covers parts of two values of different types and no single
// format-preserving rendering is correct for both.
// It also reports, per match, how many occurrences of that match were located, so the caller
// can record a mapping only for values it actually wrote over — never one it merely tried.
func planOverwrites(orig []byte, ranges []byteRange, matches []detector.Match, strategy redactors.RedactionStrategy) (plan []occurrence, perMatch []int) {
	var found []occurrence
	perMatch = make([]int, len(matches))

	for mi, m := range matches {
		if m.Text == "" {
			continue
		}
		repl := sameLengthReplacement(m.Text, m.Type, strategy)

		narrow := []byte(m.Text)
		narrowRepl := []byte(repl)
		// Both UTF-16 byte orders: ID3v2 declares UTF-16LE (with a BOM) or UTF-16BE (0x02,
		// no BOM) per frame, and a value stored in the order not searched is a value left
		// behind.
		wideEncodings := []struct {
			pat  []byte
			repl []byte
		}{}
		for _, enc := range []func(string) []byte{toUTF16LE, toUTF16BE} {
			pat := enc(m.Text)
			if len(pat) == 0 {
				continue
			}
			wr := enc(repl)
			if len(wr) != len(pat) {
				wr = maskFor(len(pat), true)
			}
			wideEncodings = append(wideEncodings, struct {
				pat  []byte
				repl []byte
			}{pat, wr})
		}

		for _, rg := range ranges {
			if rg.start < 0 || rg.end > len(orig) || rg.start >= rg.end {
				continue
			}
			region := orig[rg.start:rg.end]

			if len(narrow) > 0 && len(narrow) == len(narrowRepl) {
				for _, at := range indexAll(region, narrow) {
					found = append(found, occurrence{
						start: rg.start + at,
						end:   rg.start + at + len(narrow),
						repl:  narrowRepl,
						count: 1,
					})
					perMatch[mi]++
				}
			}
			for _, enc := range wideEncodings {
				for _, at := range indexAll(region, enc.pat) {
					found = append(found, occurrence{
						start: rg.start + at,
						end:   rg.start + at + len(enc.pat),
						repl:  enc.repl,
						wide:  true,
						count: 1,
					})
					perMatch[mi]++
				}
			}
		}
	}

	return mergeOccurrences(found), perMatch
}

// indexAll returns every start offset of pat within region, without overlapping itself.
func indexAll(region, pat []byte) []int {
	if len(pat) == 0 {
		return nil
	}
	var out []int
	off := 0
	for off <= len(region)-len(pat) {
		i := bytes.Index(region[off:], pat)
		if i < 0 {
			break
		}
		out = append(out, off+i)
		off += i + len(pat)
	}
	return out
}

// mergeOccurrences unions overlapping or touching spans.
//
// Touching spans (end == next.start) are merged too. Two adjacent reported values are
// adjacent cleartext; masking them as one span is no less correct and avoids leaving a
// format-preserved rendering next to a masked one, which reads as though only half the field
// was handled.
func mergeOccurrences(in []occurrence) []occurrence {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		// Longest first at the same start, so the wider span drives the merge.
		return in[i].end > in[j].end
	})

	out := []occurrence{in[0]}
	for _, cur := range in[1:] {
		last := &out[len(out)-1]
		if cur.start > last.end {
			out = append(out, cur)
			continue
		}
		// Overlapping or touching: widen the existing span.
		merged := *last
		if cur.end > merged.end {
			merged.end = cur.end
		}
		merged.count = last.count + cur.count
		merged.wide = last.wide && cur.wide
		merged.repl = nil // recomputed below, since the span changed
		*last = merged
	}

	// Any span built from more than one match gets a mask sized to the final span. A
	// format-preserving replacement is only meaningful for exactly one value of one type.
	for i := range out {
		if out[i].count == 1 && len(out[i].repl) == out[i].end-out[i].start {
			continue
		}
		out[i].repl = maskFor(out[i].end-out[i].start, out[i].wide)
	}
	return out
}

// maskFor builds a mask of exactly n bytes.
//
// A wide span is masked with the UTF-16LE pattern so the field stays valid UTF-16: writing n
// single-byte '*' into a UTF-16 field would pair them into unrelated code units, which is
// still length-preserving but leaves a field a decoder renders as unexpected glyphs rather
// than as an obvious redaction.
func maskFor(n int, wide bool) []byte {
	if n <= 0 {
		return nil
	}
	if wide && n%2 == 0 {
		return bytes.Repeat([]byte{maskByte, 0x00}, n/2)
	}
	return bytes.Repeat([]byte{maskByte}, n)
}

// applyOverwrites writes the planned spans into buf and returns how many were applied.
func applyOverwrites(buf []byte, plan []occurrence) int {
	applied := 0
	for _, o := range plan {
		if o.start < 0 || o.end > len(buf) || o.start >= o.end || len(o.repl) != o.end-o.start {
			continue
		}
		copy(buf[o.start:o.end], o.repl)
		applied++
	}
	return applied
}
