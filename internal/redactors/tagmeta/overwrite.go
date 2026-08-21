// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package tagmeta locates and overwrites reported values inside the metadata regions of a
// binary container, without changing the file's length.
//
// # Why this is shared rather than per-format
//
// Every container this tool redacts byte-for-byte — RIFF/WAVE, ID3, FLAC, ISO base media
// (.m4a/.mp4/.mov) — stores tag text behind a length: a chunk size, a synchsafe frame size, a
// 24-bit block length, an atom size. Writing a replacement of a different length means
// rewriting every enclosing size, and in ISO base media also every sample offset in stco,
// because moving bytes moves the media. A corrupt file that looks redacted is worse than an
// honest refusal.
//
// So the replacement is always exactly len(original) bytes, and the logic that gets that right
// — locating every occurrence in the ORIGINAL bytes, merging overlapping spans, and verifying
// the result — is identical for all of them. It lived in package audio until video needed the
// same guarantees. Two copies of an overlap-merge would drift, and the failure mode of a drift
// here is a value left in cleartext in a file reported as clean.
package tagmeta

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// MaskByte is what a value becomes when no length-preserving replacement fits. '*' matches
// what FormatPreserving already uses, so a masked value looks the same whichever path
// produced it.
const MaskByte = '*'

// Region is a half-open [Start, End) span of an in-memory buffer that holds metadata.
//
// Buffer-relative, and deliberately int rather than int64: this is a slice index. A walk over
// a FILE speaks int64 (see Span), and converting at that boundary is where the bounds check
// belongs.
type Region struct {
	Start int
	End   int
	Label string // which container structure it came from, for the audit trail
}

// Occurrence is one span of the buffer to overwrite, with the bytes to write there.
//
// Exported because a streaming caller applies these to a file rather than to the buffer they
// were planned against: it needs the offsets to seek.
type Occurrence struct {
	Start int
	End   int
	Repl  []byte
	Wide  bool // the value was found UTF-16 encoded, so a mask must keep that width
	Count int  // how many matches contributed to this span, after merging
}

// Plan computes every span to overwrite, resolving overlaps.
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
func Plan(orig []byte, regions []Region, matches []detector.Match, strategy redactors.RedactionStrategy) (plan []Occurrence, perMatch []int) {
	var found []Occurrence
	perMatch = make([]int, len(matches))

	for mi, m := range matches {
		if m.Text == "" {
			continue
		}
		repl := SameLengthReplacement(m.Text, m.Type, strategy)

		narrow := []byte(m.Text)
		narrowRepl := []byte(repl)
		// Both UTF-16 byte orders: ID3v2 declares UTF-16LE (with a BOM) or UTF-16BE (0x02,
		// no BOM) per frame, and a value stored in the order not searched is a value left
		// behind.
		wideEncodings := []struct {
			pat  []byte
			repl []byte
		}{}
		for _, enc := range []func(string) []byte{UTF16LE, UTF16BE} {
			pat := enc(m.Text)
			if len(pat) == 0 {
				continue
			}
			wr := enc(repl)
			if len(wr) != len(pat) {
				wr = MaskFor(len(pat), true)
			}
			wideEncodings = append(wideEncodings, struct {
				pat  []byte
				repl []byte
			}{pat, wr})
		}

		for _, rg := range regions {
			if rg.Start < 0 || rg.End > len(orig) || rg.Start >= rg.End {
				continue
			}
			region := orig[rg.Start:rg.End]

			if len(narrow) > 0 && len(narrow) == len(narrowRepl) {
				for _, at := range indexAll(region, narrow) {
					found = append(found, Occurrence{
						Start: rg.Start + at,
						End:   rg.Start + at + len(narrow),
						Repl:  narrowRepl,
						Count: 1,
					})
					perMatch[mi]++
				}
			}
			for _, enc := range wideEncodings {
				for _, at := range indexAll(region, enc.pat) {
					found = append(found, Occurrence{
						Start: rg.Start + at,
						End:   rg.Start + at + len(enc.pat),
						Repl:  enc.repl,
						Wide:  true,
						Count: 1,
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
// Touching spans (End == next.Start) are merged too. Two adjacent reported values are
// adjacent cleartext; masking them as one span is no less correct and avoids leaving a
// format-preserved rendering next to a masked one, which reads as though only half the field
// was handled.
func mergeOccurrences(in []Occurrence) []Occurrence {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Start != in[j].Start {
			return in[i].Start < in[j].Start
		}
		// Longest first at the same start, so the wider span drives the merge.
		return in[i].End > in[j].End
	})

	out := []Occurrence{in[0]}
	for _, cur := range in[1:] {
		last := &out[len(out)-1]
		if cur.Start > last.End {
			out = append(out, cur)
			continue
		}
		// Overlapping or touching: widen the existing span.
		merged := *last
		if cur.End > merged.End {
			merged.End = cur.End
		}
		merged.Count = last.Count + cur.Count
		merged.Wide = last.Wide && cur.Wide
		merged.Repl = nil // recomputed below, since the span changed
		*last = merged
	}

	// Any span built from more than one match gets a mask sized to the final span. A
	// format-preserving replacement is only meaningful for exactly one value of one type.
	for i := range out {
		if out[i].Count == 1 && len(out[i].Repl) == out[i].End-out[i].Start {
			continue
		}
		out[i].Repl = MaskFor(out[i].End-out[i].Start, out[i].Wide)
	}
	return out
}

// MaskFor builds a mask of exactly n bytes.
//
// A wide span is masked with the UTF-16LE pattern so the field stays valid UTF-16: writing n
// single-byte '*' into a UTF-16 field would pair them into unrelated code units, which is
// still length-preserving but leaves a field a decoder renders as unexpected glyphs rather
// than as an obvious redaction.
func MaskFor(n int, wide bool) []byte {
	if n <= 0 {
		return nil
	}
	if wide && n%2 == 0 {
		return bytes.Repeat([]byte{MaskByte, 0x00}, n/2)
	}
	return bytes.Repeat([]byte{MaskByte}, n)
}

// Apply writes the planned spans into buf and returns how many were applied.
func Apply(buf []byte, plan []Occurrence) int {
	applied := 0
	for _, o := range plan {
		if o.Start < 0 || o.End > len(buf) || o.Start >= o.End || len(o.Repl) != o.End-o.Start {
			continue
		}
		copy(buf[o.Start:o.End], o.Repl)
		applied++
	}
	return applied
}

// ResidualAnywhere counts reported values still present ANYWHERE in buf.
//
// This is the check a caller wants before writing a file. Residual, below, searches only the
// regions it was handed — which are the regions the overwrite pass already rewrote — so it is
// structurally unable to see a value that survives outside them. Measured on a real .m4a whose
// Artist tag exiftool had written in two places:
//
//	Residual(output, mapped_ranges, [card]) = 0   // blind
//	ResidualAnywhere(output, [card])        = 1   // present at offset 11613
//
// The mapped range covered [10892,11268); the surviving copy sat at 11613. The occurrence inside
// the range was overwritten, the one outside was not, and the redactor wrote the file and reported
// success with the value still in it. Residual's own doc comment claims to cover "a value ... in a
// second region", which it cannot.
//
// Whole-buffer search is strictly stronger and cannot pass while a value survives anywhere, which
// is the property the caller needs: the output is about to be handed to someone as sanitized.
//
// A value that appears in the media STREAM rather than in metadata will also be counted here, and
// that is the honest outcome: a same-length tag overwrite cannot remove it, so writing the file
// would be a false claim either way.
func ResidualAnywhere(buf []byte, matches []detector.Match) int {
	residual := 0
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		if bytes.Contains(buf, []byte(m.Text)) ||
			containsWide(buf, UTF16LE(m.Text)) ||
			containsWide(buf, UTF16BE(m.Text)) {
			residual++
		}
	}
	return residual
}

// containsWide is bytes.Contains guarded against an empty needle, which would match everything.
func containsWide(buf, needle []byte) bool {
	return len(needle) > 0 && bytes.Contains(buf, needle)
}

// Residual counts reported values still present in the given regions of buf.
//
// Searched in both encodings, exactly as the overwrite is, so the check cannot pass because it
// looked for something narrower than what was written.
//
// NOT SUFFICIENT AS A PRE-WRITE GATE. regions are the spans the overwrite already rewrote, so a
// value surviving outside them is invisible here — see ResidualAnywhere above, which is what a
// caller should use before writing. This remains for callers that genuinely mean "within these
// spans", such as asserting a specific block was cleaned.
//
// A caller must treat a non-zero result as a refusal to write the file at all. Counting
// replacements is not enough: a value can occur twice in one region, or in a second region, or
// in an encoding the search did not try, and every one of those looks like a success from the
// mapping count alone. Verifying the bytes is the only assertion a partial job cannot satisfy.
func Residual(buf []byte, regions []Region, matches []detector.Match) int {
	residual := 0
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		narrow := []byte(m.Text)
		wideLE := UTF16LE(m.Text)
		wideBE := UTF16BE(m.Text)
		for _, rg := range regions {
			if rg.Start < 0 || rg.End > len(buf) || rg.Start >= rg.End {
				continue
			}
			region := buf[rg.Start:rg.End]
			if bytes.Contains(region, narrow) {
				residual++
				break
			}
			if len(wideLE) > 0 && bytes.Contains(region, wideLE) {
				residual++
				break
			}
			if len(wideBE) > 0 && bytes.Contains(region, wideBE) {
				residual++
				break
			}
		}
	}
	return residual
}

// SameLengthReplacement produces a replacement with exactly len(original) bytes.
//
// FormatPreserving is tried first so a redacted .mp3 reads like a redacted .docx. It is
// length-preserving by construction, but that is verified rather than assumed, and the
// replacement must also DIFFER from the input: a masking scheme can return its argument
// unchanged at some input size, and writing that back is a redaction that redacts nothing.
// legacyole records that this was not hypothetical — preserveEmail returned "a@b.co"
// unchanged for a single-character local part.
func SameLengthReplacement(original, dataType string, strategy redactors.RedactionStrategy) string {
	if strategy == redactors.RedactionFormatPreserving || strategy == redactors.RedactionSimple {
		fp := replacement.FormatPreserving(original, dataType)
		if len(fp) == len(original) && fp != original {
			return fp
		}
	}
	return strings.Repeat(string(MaskByte), len(original))
}

// UTF16BE encodes a string as UTF-16 big-endian, with surrogate pairs for anything outside
// the BMP.
//
// ID3v2.4 encoding byte 0x02 is UTF-16BE with no BOM, so a comment frame written that way
// holds the value in this encoding and in no other. A search that covered only UTF-8 and
// UTF-16LE would not find it — and not finding it means leaving it in cleartext, which is the
// same failure this package exists to close.
//
// utf16.Encode rather than a hand-rolled loop: a wrong encoding would either miss the value
// (a leak) or match unrelated bytes (corruption), and hand-rolling gets the surrogate cases
// wrong. legacyole learned this the same way — its wide pass used to bail out on any
// non-ASCII rune, so "José Ramírez" was searched only as UTF-8 and never found.
func UTF16BE(s string) []byte {
	if s == "" {
		return nil
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	return out
}

// UTF16LE encodes a string as UTF-16 little-endian. See UTF16BE for why both orders exist.
func UTF16LE(s string) []byte {
	if s == "" {
		return nil
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// OverallConfidence averages the mapping confidences, matching what the other redactors
// report.
func OverallConfidence(mappings []redactors.RedactionMapping) float64 {
	if len(mappings) == 0 {
		return 1.0
	}
	total := 0.0
	for _, m := range mappings {
		total += m.Confidence
	}
	return total / float64(len(mappings))
}

// ResidualInReader streams a written file and counts reported values still present in it.
//
// The streaming counterpart of ResidualAnywhere, for the video path, which never holds the whole
// file in memory. It exists for the same reason: the video redactor's own residual check searches
// only the tag BLOCKS it parsed, so a value living anywhere else — an XMP packet, a second metadata
// location, the stream itself — is invisible to it, and the redactor wrote the file and reported
// success with a reported SSN still in it (#449).
//
// Reads in fixed chunks with an overlap of maxNeedle-1 bytes, so a value straddling a chunk boundary
// is still found. Memory is bounded by chunkBytes regardless of file size, which is what makes this
// affordable on a movie: it costs one extra sequential read, not a buffer the size of the input.
//
// A value in the media stream rather than in metadata is counted too. That is deliberate: a
// same-length tag overwrite cannot remove it, so writing the file would be a false claim of
// sanitization either way, and the caller must refuse rather than pretend.
func ResidualInReader(r io.ReaderAt, size int64, matches []detector.Match) (int, error) {
	if size <= 0 || len(matches) == 0 {
		return 0, nil
	}

	// Every encoding of every value, deduplicated, so one value counted once.
	type needleSet struct {
		forms [][]byte
	}
	sets := make([]needleSet, 0, len(matches))
	maxNeedle := 0
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		forms := [][]byte{[]byte(m.Text)}
		if w := UTF16LE(m.Text); len(w) > 0 {
			forms = append(forms, w)
		}
		if w := UTF16BE(m.Text); len(w) > 0 {
			forms = append(forms, w)
		}
		for _, f := range forms {
			if len(f) > maxNeedle {
				maxNeedle = len(f)
			}
		}
		sets = append(sets, needleSet{forms: forms})
	}
	if len(sets) == 0 {
		return 0, nil
	}

	const chunkBytes = 1 << 20
	overlap := maxNeedle - 1
	if overlap < 0 {
		overlap = 0
	}

	found := make([]bool, len(sets))
	remaining := len(sets)

	buf := make([]byte, chunkBytes+overlap)
	var off int64
	for off < size && remaining > 0 {
		// Start each window `overlap` bytes before the new data so a straddling value is whole
		// somewhere in exactly one window.
		start := off - int64(overlap)
		if start < 0 {
			start = 0
		}
		want := int64(len(buf))
		if start+want > size {
			want = size - start
		}
		n, err := r.ReadAt(buf[:want], start)
		if n > 0 {
			window := buf[:n]
			for i := range sets {
				if found[i] {
					continue
				}
				for _, f := range sets[i].forms {
					if bytes.Contains(window, f) {
						found[i] = true
						remaining--
						break
					}
				}
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, fmt.Errorf("failed to re-read the redacted file at offset %d: %w", start, err)
		}
		if n == 0 {
			break
		}
		off = start + int64(n)
	}

	residual := 0
	for _, f := range found {
		if f {
			residual++
		}
	}
	return residual, nil
}
