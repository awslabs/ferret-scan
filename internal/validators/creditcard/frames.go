// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"regexp"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Card frames: the magnetic-stripe tracks of ISO/IEC 7813 and the chip's Track 2 Equivalent Data
// (EMV tag 57), which carry a PAN together with the data PCI DSS v4.0 Requirement 3.3.1.1 forbids
// keeping after authorisation (#905).
//
// The PAN pattern in NewValidator puts one boundary class on both sides of the number, and that
// class rejects every byte these formats put next to a PAN: Track 1's format code `B` and its `^`
// field separator, tag 57's `D` separator, a TLV length byte glued to the value, and the `%3B`/`%3D`
// of a URL-encoded Track 2. Measured on main with the issue's 40 synthetic files: Track 1, tag 57
// (bare and inside TLV) and URL-encoded Track 2 gave no finding at all, PAN included, and
// --enable-redaction wrote them back unchanged. Track 2 matched through `;` and `=`, but the
// finding's Text was the PAN alone, so its expiry, service code and discretionary data stayed in
// cleartext.
//
// Widening the shared class would have changed every existing PAN finding, so each frame has its
// own matcher here. A frame reports two things:
//
//   - its PAN, when the PAN pattern did not already report one at the same bytes: a Track 2 PAN
//     after `;` or a delimiter is reported there today and is left exactly as it is, so no existing
//     finding moves and none is duplicated;
//   - the frame itself, Text from the first byte of the frame to its last, as trackDataType with
//     Metadata[cardFrameKey] naming the frame and Metadata["card_type"] the PAN's brand, when the
//     frame's structure is valid.
//
// The PAN needs isValidLength and Luhn, as every PAN does. The expiry month, the service code and
// the format's maximum length gate only the frame finding, so a Luhn-valid PAN inside a frame
// whose structure is wrong is still reported. A frame is looked for only on a line holding a run of
// at least 13 digits (hasDigitRun), and each pattern is tried only at a separator that a 13 to 19
// digit run ends at, anchored there and on a window of at most 116 bytes, so a line costs one pass
// whatever it holds.

// cardFrameKey is the Metadata key naming the frame a finding's Text covers. It is set only on
// frame and security-code findings, never on a finding whose Text is a PAN alone.
const cardFrameKey = "card_frame"

// The types of a frame finding and of a security-code finding (#905). Neither is a card brand, so
// neither is in the redactors' creditCardTypes: the card mask writes back every non-digit byte and a
// value's last four digits, which kept a Track 1's cardholder name under format_preserving and
// synthetic while the frame was reported under its PAN's brand. Under their own types simple writes
// their own placeholder, format_preserving masks every byte, and synthetic writes a frame whose PAN
// is Luhn-invalid (replacement's frame arm). --checks CREDIT_CARD still reports both: the check is
// the validator's, not the type's.
const (
	trackDataType    = "CARD_TRACK_DATA"
	securityCodeType = "CARD_SECURITY_CODE"
)

// The values of Metadata[cardFrameKey].
const (
	frameTrack1       = "track1"
	frameTrack2       = "track2"
	frameEMV57        = "emv57"
	frameSecurityCode = "security_code"
)

// Format maximums: Track 1 is at most 79 characters and Track 2 at most 40, sentinels included
// (ISO/IEC 7813); tag 57 holds at most 19 bytes, 38 nibbles, its 'F' pad included (EMV Book 3).
const (
	track1MaxLen     = 79
	track2MaxLen     = 40
	emv57MaxNibbles  = 38
	minFramePANRun   = 13
	tlvMinValueBytes = 0x0B
	tlvMaxValueBytes = 0x13
)

var (
	// track1Tail is Track 1 format B from its first field separator on: `^`, a 2-26 character name,
	// `^`, the expiry (YYMM), the service code and the discretionary data, then the `?` end
	// sentinel. Before the separator come the `%` start sentinel, the `B` format code and the PAN,
	// which appendTrack1 reads leftwards by hand. Both sentinels are optional, since a reader or a
	// log often drops them. Anchored: it is tried only at a `^` that follows a PAN, because the
	// name and the discretionary data may hold a `^` of their own, so an unanchored scan could
	// swallow a real track inside a caret-delimited record (an HL7 segment) that comes first.
	// Groups: 1 name, 2 YY, 3 MM, 4 service code.
	track1Tail = regexp.MustCompile(`^\^([^\^\r\n]{2,26})\^(\d{2})(\d{2})(\d{3})[^?\s]{0,79}\??`)

	// track2Tail is Track 2 from its field separator on: `=`, the expiry (YYMM), the service code
	// and the discretionary digits, then the `?` end sentinel. Before the separator come the `;`
	// start sentinel and the PAN, which appendTrack2 reads leftwards by hand. The sentinels and the
	// separator may be percent-encoded (`%3B`, `%3D`, `%3F`), the way a form post carries them.
	// Groups: 1 YY, 2 MM, 3 service code, 4 discretionary data, 5 end sentinel.
	//
	// Each frame pattern starts at a separator rather than at the PAN because Go's regexp has no
	// DFA: a pattern starting with \d{13,19} keeps a thread alive for every digit of every run on
	// the line (see BenchmarkFrameNearMisses).
	track2Tail = regexp.MustCompile(`^(?:=|%3[Dd])(\d{2})(\d{2})(\d{3})(\d{0,40})(\?|%3[Ff])?`)

	// emv57Tail is the value of EMV tag 57 from its `D` separator on: the expiry, the service code
	// and the discretionary digits, then an `F` pad when the nibble count is odd. The PAN before
	// the separator is read by hand, as for Track 2. Groups: 1 YY, 2 MM, 3 service code,
	// 4 discretionary data, 5 pad.
	emv57Tail = regexp.MustCompile(`^[Dd](\d{2})(\d{2})(\d{3})(\d{0,38})([Ff])?`)

	// emv57ValuePattern is a whole tag 57 value, PAN included, for a value whose bounds a TLV
	// length byte gives. Groups: 1 PAN, 2 YY, 3 MM, 4 service code.
	emv57ValuePattern = regexp.MustCompile(`^(\d{13,19})[Dd](\d{2})(\d{2})(\d{3})\d*[Ff]?$`)
)

// frameHit is one frame found on a line, its offsets in bytes within that line.
type frameHit struct {
	kind             string // frameTrack1, frameTrack2 or frameEMV57
	start, end       int    // the whole frame
	panStart, panEnd int    // its PAN
	valid            bool   // the expiry month, service code and length gates all passed
	testCard         bool   // the service code's first digit is 9, a test card (ISO/IEC 7813)
}

// appendFrameMatches adds the findings of one line's frames. reported is the spans of the PAN
// findings ValidateContent has already made on the line, in order; frames are in order too, so one
// forward pass finds the PANs already reported.
//
// A frame's PAN that was not reported is scored exactly as the PAN pattern scores a PAN: the line's
// keyword impact and the bare-run ceiling apply as they would to the same digits between two spaces.
// The frame finding scores the same PAN with frameImpact instead and no bare-run ceiling, since the
// frame itself names the PAN as a card. A test card's service code holds both at testValueCeiling.
func (v *Validator) appendFrameMatches(matches []detector.Match, frames []frameHit, line string, lineNum int,
	lowerLine string, contextImpact float64, tabularLine bool, labels *bareRunLabels, reported []panSpan,
	originalPath string) []detector.Match {
	impact := v.frameImpact(lowerLine, contextImpact)
	next := 0
	for _, f := range frames {
		pan := line[f.panStart:f.panEnd]
		if !v.isValidLength(pan) || !v.luhnCheck(pan) {
			continue
		}
		vendor := v.detectCardVendor(pan)
		cardType := v.getCreditCardType(pan)
		testCard := f.valid && f.testCard

		for next < len(reported) && reported[next].start < f.panStart {
			next++
		}
		if next >= len(reported) || reported[next].start != f.panStart || reported[next].end != f.panEnd {
			// A frame's PAN is digits only, so it is a bare run (isBareDigitRun).
			held := contextImpact == 0 && !labels.namesCard(v, f.panStart)
			confidence, checks := v.scoreCandidate(pan, pan, contextImpact, tabularLine, held)
			if testCard {
				confidence = markTestCard(confidence, checks)
			}
			matches = append(matches, detector.Match{
				Text:       pan,
				LineNumber: lineNum + 1,
				Type:       cardType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "creditcard",
				Context:    v.buildContextInfoAt(line, f.panStart, f.panEnd),
				Metadata:   cardMetadata(cardType, vendor, checks, contextImpact, originalPath, held),
			})
		}

		if !f.valid {
			continue
		}
		confidence, checks := v.scoreCandidate(pan, pan, impact, tabularLine, false)
		if testCard {
			confidence = markTestCard(confidence, checks)
		}
		meta := cardMetadata(cardType, vendor, checks, impact, originalPath, false)
		meta[cardFrameKey] = f.kind
		// card_type names the brand. vendor is left off: --explain builds its subject from vendor
		// before the type, and "a Visa card track data" misnames a frame as a kind of card.
		delete(meta, "vendor")
		matches = append(matches, detector.Match{
			Text:       line[f.start:f.end],
			LineNumber: lineNum + 1,
			Type:       trackDataType,
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "creditcard",
			Context:    v.buildContextInfoAt(line, f.start, f.end),
			Metadata:   meta,
		})
	}
	return matches
}

// frameImpact is the keyword impact a frame finding takes. The frame names its PAN as a card, so it
// counts as the one positive card word analyzeContextLower rewards: +15, once, whether or not a card
// word is also on the line. As with a card word, a soft negative ("order", "account") no longer
// suppresses, and a hard negative ("test", "sample", "hash") still does, so a Track 1 whose name is
// SAMPLE/JOHN stays at the bottom of LOW (and is still redacted).
func (v *Validator) frameImpact(lowerLine string, lineImpact float64) float64 {
	if lineImpact < 0 && v.hardNegativeKeywordRegex != nil && v.hardNegativeKeywordRegex.MatchString(lowerLine) {
		return -100
	}
	return 15
}

// markTestCard holds a value whose frame says it is a test card (service code 9xx) at
// testValueCeiling and marks it not_test=false, as capPublishedTestPAN does a published test number,
// so cardMetadata publishes the ceiling for the bridge.
func markTestCard(confidence float64, checks map[string]bool) float64 {
	checks["not_test"] = false
	return min(confidence, testValueCeiling)
}

// findFrames returns the frames on line, in order of their first byte, none overlapping another.
// It checks a frame's shape and structure; the caller checks its PAN.
func findFrames(line string) []frameHit {
	if !hasDigitRun(line, minFramePANRun) {
		return nil
	}
	var hits []frameHit
	if strings.IndexByte(line, '^') >= 0 {
		hits = appendTrack1(hits, line)
	}
	if strings.IndexByte(line, '=') >= 0 || strings.Contains(line, "%3D") || strings.Contains(line, "%3d") {
		hits = appendTrack2(hits, line)
	}
	if strings.IndexByte(line, 'D') >= 0 || strings.IndexByte(line, 'd') >= 0 {
		hits = appendEMV57(hits, line)
		hits = appendEMV57TLV(hits, line)
	}
	if len(hits) < 2 {
		return hits
	}
	// A frame inside another one is part of it: keep the outer frame, the earliest and widest.
	sort.SliceStable(hits, func(a, b int) bool {
		if hits[a].start != hits[b].start {
			return hits[a].start < hits[b].start
		}
		return hits[a].end > hits[b].end
	})
	kept := hits[:1]
	for _, h := range hits[1:] {
		if h.start >= kept[len(kept)-1].end {
			kept = append(kept, h)
		}
	}
	return kept
}

// appendTrack1 adds the Track 1 frames on line. The PAN is the 13 to 19 digits that end at the
// first field separator, and the byte before it must be the `B` format code. What precedes the
// format code is checked by hand, since RE2 has no look-behind: `%B` is accepted wherever it sits,
// a bare `B` only when no letter or digit precedes it, so a word ending in B before a digit run is
// not a track.
func appendTrack1(hits []frameHit, line string) []frameHit {
	for i := 0; i < len(line); {
		j := strings.IndexByte(line[i:], '^')
		if j < 0 {
			break
		}
		panEnd := i + j
		i = panEnd + 1
		panStart, ok := panRunBefore(line, panEnd)
		if !ok || panStart == 0 || line[panStart-1] != 'B' {
			continue
		}
		start := panStart - 1
		switch {
		case start > 0 && line[start-1] == '%':
			start--
		case start > 0 && isASCIIAlnum(line[start-1]):
			continue
		}
		// The tail is at most 115 bytes (two separators, a 26-byte name, 7 digits, 79 bytes of
		// data and `?`), so the anchored match reads a bounded window.
		m := track1Tail.FindStringSubmatchIndex(line[panEnd:min(len(line), panEnd+116)])
		if m == nil {
			continue
		}
		shiftMatch(m, panEnd)
		end := m[1]
		hits = append(hits, frameHit{
			kind:     frameTrack1,
			start:    start,
			end:      end,
			panStart: panStart,
			panEnd:   panEnd,
			valid:    end-start <= track1MaxLen && validMonth(line[m[6]:m[7]]) && validServiceCode(line[m[8]:m[9]]),
			testCard: line[m[8]] == '9',
		})
		i = end
	}
	return hits
}

// appendTrack2 adds the Track 2 frames on line. The PAN is the 13 to 19 digits that end at the
// separator. Without a start sentinel, the byte before the PAN must be one the PAN pattern accepts
// as a boundary (or the line's start): those are the Track 2 PANs the PAN pattern already reports,
// so a frame adds no PAN location there.
func appendTrack2(hits []frameHit, line string) []frameHit {
	for i := 0; i < len(line); {
		j := strings.IndexAny(line[i:], "=%")
		if j < 0 {
			break
		}
		panEnd := i + j
		i = panEnd + 1
		panStart, ok := panRunBefore(line, panEnd)
		if !ok {
			continue
		}
		start, sentinel := panStart, true
		switch {
		case panStart >= 1 && line[panStart-1] == ';':
			start = panStart - 1
		case panStart >= 3 && (line[panStart-3:panStart] == "%3B" || line[panStart-3:panStart] == "%3b"):
			start = panStart - 3
		case panStart > 0 && !isPANBoundary(line[panStart-1]):
			continue
		default:
			sentinel = false
		}
		// At most 53 bytes: `%3D`, 7 digits, 40 of data and `%3F`.
		m := track2Tail.FindStringSubmatchIndex(line[panEnd:min(len(line), panEnd+53)])
		if m == nil {
			continue
		}
		shiftMatch(m, panEnd)
		end := m[1]
		// The length limit counts characters as a reader sees them, so `%3B` is one.
		decoded := (panEnd - panStart) + 1 + 7 + (m[9] - m[8])
		if sentinel {
			decoded++
		}
		if m[10] >= 0 {
			decoded++
		}
		hits = append(hits, frameHit{
			kind:     frameTrack2,
			start:    start,
			end:      end,
			panStart: panStart,
			panEnd:   panEnd,
			valid:    decoded <= track2MaxLen && validMonth(line[m[4]:m[5]]) && validServiceCode(line[m[6]:m[7]]),
			testCard: line[m[6]] == '9',
		})
		i = end
	}
	return hits
}

// appendEMV57 adds the bare tag 57 values on line: no letter or digit may touch the value on either
// side, which keeps a PAN-shaped run inside a longer hex string out (appendEMV57TLV reads a value
// inside TLV by its length instead).
func appendEMV57(hits []frameHit, line string) []frameHit {
	for i := 0; i < len(line); {
		j := strings.IndexAny(line[i:], "Dd")
		if j < 0 {
			break
		}
		panEnd := i + j
		i = panEnd + 1
		panStart, ok := panRunBefore(line, panEnd)
		if !ok || (panStart > 0 && isASCIIAlnum(line[panStart-1])) {
			continue
		}
		// At most 47 bytes: `D`, 7 digits, 38 of data and the pad.
		m := emv57Tail.FindStringSubmatchIndex(line[panEnd:min(len(line), panEnd+47)])
		if m == nil {
			continue
		}
		shiftMatch(m, panEnd)
		end := m[1]
		if end < len(line) && isASCIIAlnum(line[end]) {
			continue
		}
		hits = append(hits, emv57Hit(line, panStart, end, panStart, panEnd, m[2:8]))
		i = end
	}
	return hits
}

// shiftMatch moves the offsets of a match made on line[off:] onto line, leaving an unmatched
// group's -1 alone.
func shiftMatch(m []int, off int) {
	for k := range m {
		if m[k] >= 0 {
			m[k] += off
		}
	}
}

// panRunBefore returns the start of the run of 13 to 19 digits that ends at end, the shape every
// frame's PAN has. A shorter run, a longer one, or none is not a PAN. It reads at most 20 bytes, so
// a frame costs the same whatever the line holds before it.
func panRunBefore(line string, end int) (int, bool) {
	start := end
	for start > 0 && end-start < 20 && line[start-1] >= '0' && line[start-1] <= '9' {
		start--
	}
	n := end - start
	return start, n >= 13 && n <= 19
}

// appendEMV57TLV adds the tag 57 values encoded as TLV hex on line: the tag `57`, a length byte L
// from 0x0B to 0x13 (the 11 to 19 bytes a value can hold), then exactly 2L nibbles that must be a
// whole tag 57 value. The length byte is what lets a value glued into a hex dump be read without a
// boundary around it, and a value that does not fill its declared length is not one.
func appendEMV57TLV(hits []frameHit, line string) []frameHit {
	for i := 0; i+4 <= len(line); {
		j := strings.Index(line[i:], "57")
		if j < 0 {
			break
		}
		at := i + j
		i = at + 1
		if at+4 > len(line) {
			break
		}
		n, ok := hexByte(line[at+2], line[at+3])
		if !ok || n < tlvMinValueBytes || n > tlvMaxValueBytes {
			continue
		}
		start, end := at+4, at+4+2*n
		if end > len(line) {
			continue
		}
		m := emv57ValuePattern.FindStringSubmatchIndex(line[start:end])
		if m == nil {
			continue
		}
		shiftMatch(m, start)
		hits = append(hits, emv57Hit(line, start, end, m[2], m[3], m[4:10]))
	}
	return hits
}

// emv57Hit builds a tag 57 frame from a match: groups holds the offsets of the YY, MM and service
// code groups, in pairs.
func emv57Hit(line string, start, end, panStart, panEnd int, groups []int) frameHit {
	mmStart, mmEnd := groups[2], groups[3]
	scStart, scEnd := groups[4], groups[5]
	return frameHit{
		kind:     frameEMV57,
		start:    start,
		end:      end,
		panStart: panStart,
		panEnd:   panEnd,
		valid:    end-start <= emv57MaxNibbles && validMonth(line[mmStart:mmEnd]) && validServiceCode(line[scStart:scEnd]),
		testCard: line[scStart] == '9',
	}
}

// validMonth reports whether a two-digit expiry month is 01 to 12.
func validMonth(mm string) bool {
	if len(mm) != 2 {
		return false
	}
	switch mm[0] {
	case '0':
		return mm[1] >= '1' && mm[1] <= '9'
	case '1':
		return mm[1] >= '0' && mm[1] <= '2'
	}
	return false
}

// validServiceCode reports whether a three-digit service code is one ISO/IEC 7813 defines: first
// digit 1, 2, 5, 6, 7 or 9 (interchange and technology; 9 is a test card), second 0, 2 or 4
// (authorisation processing), third 0 to 7 (range of services and PIN requirements).
func validServiceCode(sc string) bool {
	if len(sc) != 3 {
		return false
	}
	switch sc[0] {
	case '1', '2', '5', '6', '7', '9':
	default:
		return false
	}
	switch sc[1] {
	case '0', '2', '4':
	default:
		return false
	}
	return sc[2] >= '0' && sc[2] <= '7'
}

// hasDigitRun reports whether s holds at least n consecutive ASCII digits: the cheapest test that a
// line can hold a PAN at all, and so a frame.
func hasDigitRun(s string, n int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// isPANBoundary reports whether b is in the boundary class the PAN pattern accepts on either side of
// a number (NewValidator): RE2's \s (tab, newline, form feed, carriage return, space) and the
// punctuation listed after it.
func isPANBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\f', '\r', ',', ';', '|', '"', '\'', '(', ')', '{', '}', '[', ']', '<', '>', '=', ':':
		return true
	}
	return false
}

// isASCIIAlnum reports whether b is an ASCII letter or digit.
func isASCIIAlnum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// hexByte decodes two hex digits.
func hexByte(hi, lo byte) (int, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	return h<<4 | l, ok1 && ok2
}

func hexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}
