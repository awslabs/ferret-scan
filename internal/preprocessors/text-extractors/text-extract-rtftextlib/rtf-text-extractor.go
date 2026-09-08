// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package textextractrtftextlib extracts the prose from a Rich Text Format document.
//
// # Why this exists
//
// An .rtf is ASCII markup, so the byte-sniffing plaintext path claimed it and handed the whole
// document — control words included — to every validator. That is not a theoretical mismatch. Measured
// at f91ad60 on a file produced by macOS `textutil`, the engine behind TextEdit and Pages:
//
//	src.html:  Employee SSN: 452-11-<b>9384</b>
//	real.rtf:  0 findings          <- reported as a successfully scanned, clean file
//	real.txt:  2 findings          <- SSN and the card number, from identical content
//
//	exit code with --fail-on-incomplete: 0
//
// A real producer splits a value across formatting runs, so the bytes reaching the validators are
//
//	Employee SSN: 452-11-\f1\b 9384
//
// and no SSN pattern can match across the control words. The tool reports the file as clean, which by
// the sink rule is a disclosure: only reported findings reach the redactor, so the value stays
// cleartext in a file the operator was told was fine.
//
// # What the issue got wrong, and why it matters for the design
//
// Issue #421 is titled "an SSN in an RTF file is reported as an unsupported type". Measured at HEAD,
// that is false in three ways, and each one changes the fix:
//
//   - `.rtf` IS scanned — `files_processed: 1, files_skipped: 0`. It is not refused, it is scanned
//     wrongly, so this is a text-extraction bug rather than a registration gap.
//   - A plain-ASCII RTF with no formatting runs reports NORMALLY. The defect needs a real producer.
//   - `.ps`/`.eps` are scanned too, contrary to the issue's note.
//
// The trigger is narrower and more common than "any RTF": any value a producer split across runs. A
// completely UNFORMATTED textutil file still loses a value, because the trailing `\` line-break escape
// alone is enough to break a match.
//
// There is a second, quieter half the issue does not mention: silent BAND DEMOTION. When the label and
// the value land on different source lines the value loses its proximity boost, so a bold textutil file
// reports SSN at MEDIUM where its decoded twin reports HIGH — and a `--confidence high` run drops it
// entirely, on a file that was nominally scanned.
//
// # What is extracted, and what is refused
//
// An allowlist by construction: this reader emits only character data from document destinations. RTF
// keeps its metadata, fonts, colours, stylesheets and embedded binaries in named destinations, and every
// one of those is skipped wholesale rather than filtered afterwards, so a construct nobody anticipated
// is dropped by default rather than reaching a validator.
//
// Deliberately NOT extracted, each measured or specified:
//
//   - `\*\pict` — an embedded image, carried as megabytes of hex. Feeding hex to the validators is the
//     documented way an image becomes a HIGH-band finding. (Note the issue's "Hazard 2" claims this
//     already happens on the plaintext path and produces findings; measured, a 302KB RTF with a 300KB
//     hex `\pict` yields exactly 1 finding — the planted SSN — and 0 false positives. The hazard is
//     real for THIS reader if it did not skip the destination, which is why it does.)
//   - `\fonttbl`, `\colortbl`, `\stylesheet`, `\listtable`, `\rsidtbl` — machine tables. Font names are
//     not prose and produce PERSON_NAME hits.
//   - `\info` — title, author, company. Deliberately left to the OFFICE METADATA path rather than
//     folded into body text, so a finding's provenance stays honest: an author name reported as
//     document body would misattribute where it came from.
//   - `\*\...` — any destination marked ignorable by the specification. The spec says a reader that
//     does not understand it must skip it, and that is exactly the safe default here.
package textextractrtftextlib

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
)

// TextContent is the extracted prose plus what the caller needs to report coverage.
//
// Shaped to match the SVG extractor's return so processRTF can mirror processSVG: the fields the
// router carries for coverage disclosure are the same ones, and a second shape would drift.
type TextContent struct {
	// Spans maps the extracted Text back to the source bytes, for redaction. See Span.
	Spans []Span

	Text   string
	Format string

	// ExtractionWarning and ExtractionCause carry a partial or failed read to the coverage
	// report. Without them a file that could not be parsed reports zero findings with nothing
	// said, which is the silence this package exists to remove.
	ExtractionWarning string
	ExtractionCause   coverage.Cause

	// NotRTF reports that the file is NAMED .rtf but carries no RTF signature.
	//
	// A flag rather than an error, and the reason is measured on the SVG precedent: prose-only
	// extraction of a MISLABELLED file loses recall outright. #573 measured a plain text file
	// holding an SSN and an email renamed to .svg — 2 findings through the plaintext path, 0 once
	// the name routed it to a prose-only reader. Recovering precision on real documents must not
	// cost recall on a renamed one, so the caller scans the raw bytes instead.
	NotRTF bool
}

// Span maps a run of extracted text back to the source bytes it came from.
//
// It exists so a value the producer SPLIT across formatting runs can still be redacted. macOS textutil
// writes `452-11-9384` as `452-11-\f1\b 9384`, so the extractor reassembles it and the value is
// reported — but the reassembled form occurs nowhere in the file, and a byte substitution finds nothing
// to replace. Before this map, redaction of such a file was refused outright rather than done wrong.
//
// Half-open on both sides: [OutStart, OutEnd) in the extracted text corresponds to
// [SrcStart, SrcEnd) in the original RTF.
type Span struct {
	OutStart, OutEnd int
	SrcStart, SrcEnd int
}

// SourceRanges returns the source byte ranges covering [outStart, outEnd) of the extracted text, in
// order, clipped to the requested window.
//
// Returns nil when the window is not fully covered — a caller must be able to tell "here are the bytes
// to rewrite" from "part of this value came from somewhere I cannot point at", because rewriting a
// partially-mapped value would leave some of it behind. That is the failure this whole map exists to
// avoid, so it is reported rather than approximated.
func SourceRanges(spans []Span, outStart, outEnd int) [][2]int {
	if outEnd <= outStart {
		return nil
	}
	var ranges [][2]int
	covered := outStart
	for _, sp := range spans {
		if sp.OutEnd <= outStart || sp.OutStart >= outEnd {
			continue
		}
		if sp.OutStart > covered {
			return nil // a gap: something in this window came from no recorded source range
		}
		// Clip the span to the requested window, in output coordinates, then map to source.
		lo, hi := sp.OutStart, sp.OutEnd
		if lo < outStart {
			lo = outStart
		}
		if hi > outEnd {
			hi = outEnd
		}
		// Only a span whose output and source lengths agree can be offset arithmetically. A \uN escape
		// emits one rune from many source bytes, so its length differs and it is taken WHOLE rather
		// than sliced — slicing it would compute a source offset inside a control word.
		if sp.OutEnd-sp.OutStart == sp.SrcEnd-sp.SrcStart {
			ranges = append(ranges, [2]int{sp.SrcStart + (lo - sp.OutStart), sp.SrcStart + (hi - sp.OutStart)})
		} else {
			ranges = append(ranges, [2]int{sp.SrcStart, sp.SrcEnd})
		}
		covered = sp.OutEnd
		if covered >= outEnd {
			break
		}
	}
	if covered < outEnd {
		return nil
	}
	return ranges
}

// shiftSpans re-bases output offsets after TrimSpace and drops what falls outside the trimmed text.
//
// Clipping a span has to move BOTH ends of the mapping. Trimming three leading spaces off a span means
// its source range starts three bytes later too — adjusting only the output offset leaves the map
// silently off by the trimmed width, which is exactly the off-by-N a document with no leading
// whitespace would never reveal. Measured before the fix: a value's mapped source came back as
// "  Leading space then SSN: 452-11-9384" instead of "452-11-9384".
//
// A span that needs clipping but is NOT length-preserving is DROPPED rather than guessed at: its output
// and source lengths differ (an escape), so there is no per-byte correspondence to clip along. Dropping
// it makes SourceRanges refuse any window covering it, which is the safe direction.
func shiftSpans(spans []Span, lead, trimmedLen int) []Span {
	out := spans[:0]
	for _, sp := range spans {
		sp.OutStart -= lead
		sp.OutEnd -= lead
		if sp.OutEnd <= 0 || sp.OutStart >= trimmedLen {
			continue
		}
		oneToOne := sp.OutEnd-sp.OutStart == sp.SrcEnd-sp.SrcStart
		if sp.OutStart < 0 {
			if !oneToOne {
				continue
			}
			sp.SrcStart += -sp.OutStart
			sp.OutStart = 0
		}
		if sp.OutEnd > trimmedLen {
			if !oneToOne {
				continue
			}
			sp.SrcEnd -= sp.OutEnd - trimmedLen
			sp.OutEnd = trimmedLen
		}
		if sp.OutStart >= sp.OutEnd || sp.SrcStart >= sp.SrcEnd {
			continue
		}
		out = append(out, sp)
	}
	return out
}

// maxRTFBytes bounds the input this reader will parse.
//
// 64MB. RTF is a text format and a document of prose does not approach this; a file that does is
// carrying embedded binaries, which are skipped rather than parsed, so the cap protects the parser
// rather than the caller's patience. Refused loudly — a silent truncation would report partial
// coverage as complete, which is the failure this whole package exists to remove.
const maxRTFBytes = 64 << 20

// skippedDestinations are the control words whose entire group is discarded.
//
// Matched on the destination NAME at the point it opens, not by scanning for the word anywhere, so a
// document whose prose happens to contain "pict" is unaffected.
var skippedDestinations = map[string]bool{
	"fonttbl": true, "colortbl": true, "stylesheet": true, "listtable": true,
	"listoverridetable": true, "rsidtbl": true, "generator": true, "info": true,
	"pict": true, "object": true, "objdata": true, "datafield": true,
	"themedata": true, "colorschememapping": true, "latentstyles": true,
	"datastore": true, "mmathPr": true, "template": true, "xmlnstbl": true,
	"filetbl": true, "revtbl": true, "protusertbl": true, "upr": true,
	"bkmkstart": true, "bkmkend": true, "field": true, "fldinst": true,
}

// breakingWords are control words that end a run of text and therefore emit whitespace.
//
// This is the half that fixes the defect. A producer writes `452-11-\f1\b 9384`, and the naive repair
// — deleting control words — would join the digits into `452-11-9384`, which is right here but wrong in
// general: `\par` and `\cell` separate genuinely different fields, and joining them across a table row
// would fabricate values that appear nowhere in the document. So a word that means "same run, different
// formatting" is dropped and a word that means "new paragraph, cell or line" emits a separator.
//
// Getting this backwards in either direction is a defect: drop too much and adjacent fields fuse into a
// value nobody wrote; separate too much and the split value this package exists to reassemble stays
// split.
var breakingWords = map[string]bool{
	"par": true, "line": true, "cell": true, "row": true, "sect": true, "page": true,
	"tab": true, "nestcell": true, "nestrow": true, "lastrow": true,
	"column": true, "softline": true, "softpage": true, "pard": true, "sectd": true,
	"trowd": true, "intbl": true, "plain": true, "header": true, "footer": true,
}

// ExtractText reads filePath and returns its prose.
func ExtractText(filePath string) (*TextContent, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filePath, err)
	}
	if info.Size() > maxRTFBytes {
		return nil, fmt.Errorf("rtf file too large to parse: %d bytes exceeds %d", info.Size(), maxRTFBytes)
	}
	data, err := os.ReadFile(filePath) // #nosec G304 -- a path the caller already resolved and stat'd
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filePath, err)
	}
	return ExtractFromBytes(filePath, data)
}

// ExtractFromBytes extracts prose from RTF bytes already in memory, for embedded parts.
func ExtractFromBytes(name string, data []byte) (*TextContent, error) {
	if len(data) > maxRTFBytes {
		return nil, fmt.Errorf("rtf content too large to parse: %d bytes exceeds %d", len(data), maxRTFBytes)
	}
	if !looksLikeRTF(data) {
		// Reported, not refused. See TextContent.NotRTF.
		return &TextContent{NotRTF: true}, nil
	}
	out, warnings, spans := parse(string(data))
	tc := &TextContent{Text: out, Format: "Rich Text Format", Spans: spans}
	if len(warnings) > 0 {
		tc.ExtractionWarning = strings.Join(warnings, "; ")
		tc.ExtractionCause = coverage.CauseCutShort
	}
	return tc, nil
}

// looksLikeRTF checks the signature the specification requires.
//
// Checked on the BYTES rather than trusting the extension, so a file named .rtf that is not RTF is
// refused here and reported as unparseable, instead of being silently handed back as empty text — which
// would read as "scanned, nothing found".
func looksLikeRTF(data []byte) bool {
	const sig = `{\rtf`
	if len(data) < len(sig) {
		return false
	}
	// Tolerate a UTF-8 BOM, which some producers emit ahead of the signature.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return strings.HasPrefix(string(data), sig)
}

// parse walks the document once, emitting character data from document destinations only.
//
// Single pass, O(n) in the input, with a bounded group stack. The validators downstream have been
// audited for quadratic behaviour and an extractor that rescanned per group would reintroduce it.
func parse(s string) (string, []string, []Span) {
	var (
		out       strings.Builder
		warnings  []string
		depth     int
		skipDepth = -1 // depth at which the current skipped destination opened; -1 = not skipping
		i         int
		// unicodeSkip is how many following characters a \uN escape replaces, from \ucN.
		// Defaults to 1 per the specification.
		unicodeSkip  = 1
		pendingBreak bool
	)
	out.Grow(len(s) / 2)

	// spans map runs of extracted output back to the source bytes they came from, so a redactor can
	// find a value in the ORIGINAL markup even when the producer split it across formatting runs.
	// Without this a reassembled value occurs nowhere literally and cannot be substituted -- which is
	// why redaction of such a file was refused outright rather than done wrong.
	//
	// Recorded per RUN rather than per byte: adjacent emits that are contiguous in both the output and
	// the source extend the previous span instead of appending, so the slice is proportional to the
	// number of formatting runs rather than to the document size. A newline inserted for pendingBreak
	// belongs to no source range and is attributed to the emit that triggered it, which is harmless
	// because a redactor only ever looks up ranges inside a matched value and a match never begins
	// with the separator.
	var spans []Span

	emit := func(str string, srcStart, srcEnd int) {
		if str == "" {
			return
		}
		if pendingBreak {
			// The separator is DELIBERATELY not recorded. It corresponds to a control word
			// (\par, \cell, ...), not to content, so there are no source bytes a redactor could
			// overwrite with part of a value. Leaving it unmapped makes SourceRanges refuse any window
			// that crosses a paragraph break — which is correct: a value spanning one cannot be
			// substituted in place, and refusing beats rewriting the wrong bytes.
			out.WriteByte('\n')
			pendingBreak = false
		}
		start := out.Len()
		out.WriteString(str)
		if srcEnd <= srcStart {
			// No source bytes to point at. Recorded as nothing rather than as an empty range, so the
			// gap is visible to SourceRanges instead of being an invalid span.
			return
		}
		// Merge only when BOTH sides are length-preserving, so every merged span keeps
		// OutEnd-OutStart == SrcEnd-SrcStart and can therefore be sliced by offset arithmetic. An
		// escape (\'hh emits one byte from four, \uN one rune from several) is never merged: doing so
		// produced spans whose output was "-11" while their source was "11", and slicing those computes
		// an offset inside a control word.
		oneToOne := len(str) == srcEnd-srcStart
		if n := len(spans); oneToOne && n > 0 &&
			spans[n-1].OutEnd == start && spans[n-1].SrcEnd == srcStart &&
			spans[n-1].OutEnd-spans[n-1].OutStart == spans[n-1].SrcEnd-spans[n-1].SrcStart {
			spans[n-1].OutEnd = out.Len()
			spans[n-1].SrcEnd = srcEnd
			return
		}
		spans = append(spans, Span{OutStart: start, OutEnd: out.Len(), SrcStart: srcStart, SrcEnd: srcEnd})
	}

	for i < len(s) {
		c := s[i]

		switch c {
		case '{':
			depth++
			i++
			continue
		case '}':
			if skipDepth >= 0 && depth == skipDepth {
				skipDepth = -1
			}
			if depth > 0 {
				depth--
			}
			i++
			continue
		case '\\':
			// The escape's own start, captured BEFORE i advances. The emit sites below need the
			// source range the escape OCCUPIES ([escStart, next)), and i is already past it by then --
			// passing i gave every escape an empty range, so its span was dropped and any value
			// containing one became unmappable and therefore unredactable.
			escStart := i
			word, param, hasParam, next := readControl(s, i)
			i = next

			if skipDepth >= 0 {
				continue
			}

			switch {
			case isIgnorableMarker(s, next-1):
				// \* marks the NEXT destination ignorable. The specification says a reader that
				// does not understand a destination must skip it, so this is the safe default and
				// the property that makes the allowlist hold: a construct nobody anticipated is
				// dropped rather than reaching a validator.
				//
				// Measured need: macOS textutil emits {\*\expandedcolortbl;;}, which is in no
				// vocabulary here, and without this its semicolons leaked into the extracted text.
				skipDepth = depth
			case word == "" && param == "":
				// A literal escape: \\ \{ \} or an escaped newline.
				if next-1 < len(s) {
					switch s[next-1] {
					case '\\', '{', '}':
						emit(string(s[next-1]), escStart, next)
					case '\n', '\r':
						pendingBreak = true
					}
				}
			case word == "'":
				// \'hh — a byte in the document's codepage. Emitted as the Latin-1 rune, which is
				// correct for the ANSI codepages real producers use and never fabricates digits.
				if v, err := strconv.ParseUint(param, 16, 8); err == nil {
					emit(string(rune(v)), escStart, next)
				}
			case word == "u":
				// \uNNNN — a Unicode scalar, optionally negative as a signed 16-bit value.
				if v, err := strconv.ParseInt(param, 10, 32); err == nil {
					r := rune(v)
					if v < 0 {
						r = rune(uint16(v))
					}
					if utf16.IsSurrogate(r) {
						r = 0xFFFD
					}
					emit(string(r), escStart, next)
				}
				i = skipUnicodeFallback(s, i, unicodeSkip)
			case word == "uc":
				if v, err := strconv.Atoi(param); err == nil && v >= 0 {
					unicodeSkip = v
				}
			case word == "bin":
				// A binary blob whose length is declared in the parameter. Skipped by LENGTH rather
				// than scanned for a closing brace, because its bytes may contain braces.
				if hasParam {
					if n, err := strconv.Atoi(param); err == nil && n > 0 {
						if i+n <= len(s) {
							i += n
						} else {
							warnings = append(warnings,
								"rtf: a \\bin blob declared more bytes than the file contains; the rest of the document was not read")
							i = len(s)
						}
					}
				}
			case skippedDestinations[word]:
				// Skip this destination and everything nested in it.
				skipDepth = depth
			case breakingWords[word]:
				pendingBreak = true
			}
			continue
		}

		if skipDepth >= 0 {
			i++
			continue
		}

		switch c {
		case '\r', '\n':
			// Raw newlines in the markup are formatting, not content. The specification says to
			// ignore them; a producer wraps mid-value, which is one of the ways a value gets split.
			i++
			continue
		default:
			emit(string(c), i, i+1)
			i++
		}
	}

	// TrimSpace shifts every output offset, so the map has to be corrected for it or a redactor would
	// substitute at the wrong place. Computed from the raw string rather than assumed to be zero.
	raw := out.String()
	trimmed := strings.TrimSpace(raw)
	lead := strings.Index(raw, trimmed)
	if trimmed == "" {
		lead = 0
	}
	spans = shiftSpans(spans, lead, len(trimmed))

	return trimmed, warnings, spans
}

// readControl parses one control word or symbol starting at the backslash.
//
// Returns the word, its parameter, whether a parameter was present, and the index just past the
// sequence including the single optional space delimiter the specification allows.
func readControl(s string, i int) (word, param string, hasParam bool, next int) {
	i++ // consume the backslash
	if i >= len(s) {
		return "", "", false, i
	}

	c := s[i]
	if c == '\'' {
		// \'hh — exactly two hex digits.
		if i+2 < len(s) {
			return "'", s[i+1 : i+3], true, i + 3
		}
		return "'", "", false, len(s)
	}
	if !isAlpha(c) {
		// A control SYMBOL: \\ \{ \} \~ \- and the escaped newline. One character, no delimiter.
		return "", "", false, i + 1
	}

	start := i
	for i < len(s) && isAlpha(s[i]) {
		i++
	}
	word = s[start:i]

	pStart := i
	if i < len(s) && (s[i] == '-' || isDigit(s[i])) {
		i++
		for i < len(s) && isDigit(s[i]) {
			i++
		}
		param, hasParam = s[pStart:i], true
	}

	// A single space after a control word is its delimiter and is not content. Any further spaces
	// ARE content, which is why exactly one is consumed.
	if i < len(s) && s[i] == ' ' {
		i++
	}
	return word, param, hasParam, i
}

// skipUnicodeFallback advances past the codepage fallback characters that follow a \u escape.
//
// A producer writes both the Unicode scalar and a legacy approximation of it, so emitting both would
// duplicate the character — and a duplicated digit changes a value. The count comes from \ucN.
func skipUnicodeFallback(s string, i, n int) int {
	for ; n > 0 && i < len(s); n-- {
		switch s[i] {
		case '\\':
			// A fallback written as an escape counts as one character.
			_, _, _, next := readControl(s, i)
			i = next
		case '{', '}':
			// Not a fallback character; stop rather than consuming structure.
			return i
		default:
			i++
		}
	}
	return i
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// isIgnorableMarker reports whether the control symbol at position i is the \* ignorable marker.
//
// Checked on the byte rather than on the parsed word, because \* is a control SYMBOL: readControl
// returns an empty word for it, so it cannot be matched by name.
func isIgnorableMarker(s string, i int) bool {
	return i >= 0 && i < len(s) && s[i] == '*'
}
