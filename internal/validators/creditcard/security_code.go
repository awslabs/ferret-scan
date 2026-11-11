// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Card security codes (#905): the CVV2, CVC2, CID and their kin printed on a card, which PCI DSS
// v4.0 Requirement 3.3.1.2 forbids keeping after authorisation. On main they existed only as
// keywords: "cvv", "cvc" and "ccv" raise a PAN on the same line by +15 and nothing reports the code,
// so `card=4000001234567899 exp=1228 cvv=123` redacted to `card=************7899 exp=1228 cvv=123`
// and all 13 of the issue's code shapes gave 0 code findings.
//
// A code is reported only when it is LABELLED. Three or four digits on their own are any number at
// all, and a positional code (a CSV `cvv` column, `PAN|12/28|123`) needs column attribution this
// validator does not have. Two kinds of label:
//
//   - unambiguous (cvv, cvv2, cvc, cvc2, ccv, cav2, card security code, card verification
//     value/code/number) name a card security code wherever they appear: reported with a card
//     within codeWindow lines at that card's confidence, and without one at unpairedCodeConfidence;
//   - context-only (cid, csc, cvn, cvn2, security code) also name a caller ID, a MIME Content-ID, a
//     report or a date in a registry file, so they are reported only with a card within reach.
//
// The value must follow its label on the same line, separated by optional quotes, at most one of
// `: = #` and white space, and must be exactly three or four digits followed by the end of the
// line, white space, one of `" ' , ; | ) ] } < > &`, or a `.` that does not start a decimal. That
// rule is what keeps `cid:1234@mail.invalid`, `csc : 2014-09-25`, `cvn := 123` and
// `<input name="cvv" maxlength="4">` out.
//
// The finding's Text runs from the label to the value's last digit rather than holding the digits
// alone: redaction places a value at the first occurrence of its Text on the line, so a bare "123"
// would be written over the "123" inside `4000001234567899` and the code would survive. The cost is
// that the label is masked with the value.

// codeWindow is the pairing reach: a card on the code's own line or within this many lines of it.
const codeWindow = 3

// unpairedCodeConfidence is the score of an unambiguous label and its value with no card in reach:
// reported, and so redacted, but LOW. It is also published as the finding's ceiling, so a
// document-level boost cannot promote a code that no card corroborates.
const unpairedCodeConfidence = 40.0

// The labels, longest first where one is a prefix of another. A multi-word label matches with its
// words joined by a space, '_', '-' or nothing ("card_verification_value", "securityCode").
var (
	unambiguousCodeLabels = []string{"cvv2", "cvc2", "cav2", "cvv", "cvc", "ccv",
		"card security code", "card verification value", "card verification code", "card verification number"}
	contextOnlyCodeLabels = []string{"cvn2", "cvn", "cid", "csc", "security code"}
)

// securityCodePattern is a label at the start of its input, its separator and a three- or
// four-digit value. Group 1 is an unambiguous label, group 2 a context-only one, group 3 the value.
// appendCodeCandidates tries it only where a label can start, on a bounded window, and checks both
// edges by hand (RE2 has no look-around): no letter or digit before the label, and a terminator
// (codeValueEnds) after the value.
var securityCodePattern = regexp.MustCompile(
	`^(?:(` + codeLabelAlternation(unambiguousCodeLabels) + `)|(` + codeLabelAlternation(contextOnlyCodeLabels) + `))` +
		`(?:["']\s*[:=#]?\s*["']?|\s+[:=#]?\s*["']?|[:=#]\s*["']?)` +
		`(\d{3,4})`)

// codeMatchWindow bounds the bytes one candidate's match may read: the longest label (24 bytes), its
// separator with generous white space, and the value.
const codeMatchWindow = 128

// codeValueEnds reports whether the value ending at end is complete: the end of the line, white
// space, one of `" ' , ; | ) ] } < > &`, or a `.` that does not start a decimal.
func codeValueEnds(line string, end int) bool {
	if end == len(line) {
		return true
	}
	switch c := line[end]; c {
	case ' ', '\t', '\n', '\f', '\r', '"', '\'', ',', ';', '|', ')', ']', '}', '<', '>', '&':
		return true
	case '.':
		return end+1 == len(line) || line[end+1] < '0' || line[end+1] > '9'
	}
	return false
}

// mayStartCodeLabel reports whether a label can start at line[i]: a 'c' or 's' (either case) that no
// letter or digit precedes, followed by a letter some label continues with. Every label starts
// with "cv", "cc", "ca", "ci", "cs" or "se".
func mayStartCodeLabel(line string, i int) bool {
	if i+1 >= len(line) || (i > 0 && isASCIIAlnum(line[i-1])) {
		return false
	}
	next := line[i+1] | 0x20
	switch line[i] | 0x20 {
	case 'c':
		return next == 'v' || next == 'c' || next == 'a' || next == 'i' || next == 's'
	case 's':
		return next == 'e'
	}
	return false
}

// codeLabelAlternation writes labels as an RE2 alternation that ignores ASCII case. Each letter is
// spelled as a two-letter class rather than with (?i), which in Go also matches U+017F (long s) to
// 's', so the pattern and mayHoldSecurityCode's prefilter read exactly the same bytes.
func codeLabelAlternation(labels []string) string {
	alts := make([]string, len(labels))
	for i, label := range labels {
		words := strings.Fields(label)
		for j, w := range words {
			var b strings.Builder
			for k := 0; k < len(w); k++ {
				if c := w[k]; c >= 'a' && c <= 'z' {
					b.WriteString("[" + string(c) + string(c-'a'+'A') + "]")
				} else {
					b.WriteString(regexp.QuoteMeta(string(c)))
				}
			}
			words[j] = b.String()
		}
		alts[i] = strings.Join(words, `[ _-]?`)
	}
	return strings.Join(alts, "|")
}

// codeCandidate is a labelled code waiting for the cards on the lines after it.
type codeCandidate struct {
	line         string
	lineIdx      int // 0-based
	start, end   int // the label's first byte to the value's last, within line
	label        string
	contextOnly  bool
	hardNegative bool // a hard negative keyword on the code's own line
}

// lineCard is the highest-scoring card finding on one line, for pairing.
type lineCard struct {
	lineIdx    int // 0-based
	confidence float64
	cardType   string
	ceiling    float64 // the card's published confidence ceiling, 0 when it has none
}

// mayHoldSecurityCode reports, in one pass over the lower-cased line, whether it contains a
// fragment every label carries: "cv", "cav2", "cid", "csc", or the "c" of "security" or of
// "verification". A line without one cannot hold a label, and most lines do not.
func mayHoldSecurityCode(lower string) bool {
	for i := 0; i < len(lower); {
		j := strings.IndexByte(lower[i:], 'c')
		if j < 0 {
			return false
		}
		rest := lower[i+j+1:]
		if strings.HasPrefix(rest, "v") || strings.HasPrefix(rest, "av2") || strings.HasPrefix(rest, "id") ||
			strings.HasPrefix(rest, "sc") || strings.HasPrefix(rest, "urity") || strings.HasPrefix(rest, "ation") {
			return true
		}
		i += j + 1
	}
	return false
}

// appendCodeCandidates adds the labelled codes on line. The scan resumes after a reported value
// rather than after the byte that ended it, so `cvv=123,cvc=456` yields both: the comma closes the
// first value and is the second label's left edge.
func (v *Validator) appendCodeCandidates(cands []codeCandidate, line string, lineIdx int, lowerLine string) []codeCandidate {
	hardNegative := -1 // computed once, on the first code found
	for i := 0; i < len(line); i++ {
		if !mayStartCodeLabel(line, i) {
			continue
		}
		m := securityCodePattern.FindStringSubmatchIndex(line[i:min(len(line), i+codeMatchWindow)])
		if m == nil || !codeValueEnds(line, i+m[7]) {
			continue
		}
		shiftMatch(m, i)
		if hardNegative < 0 {
			hardNegative = 0
			if v.hardNegativeKeywordRegex != nil && v.hardNegativeKeywordRegex.MatchString(lowerLine) {
				hardNegative = 1
			}
		}
		labelEnd, contextOnly := m[3], false
		if m[2] < 0 {
			labelEnd, contextOnly = m[5], true
		}
		cands = append(cands, codeCandidate{
			line:         line,
			lineIdx:      lineIdx,
			start:        i,
			end:          m[7],
			label:        canonicalCodeLabel(line[i:labelEnd]),
			contextOnly:  contextOnly,
			hardNegative: hardNegative == 1,
		})
		i = m[7] - 1 // the loop's i++ resumes at the byte after the value
	}
	return cands
}

// codeLabelJoiners removes the space, '_' or '-' a multi-word label may join its words with. Built
// once: a Replacer of single bytes holds a 256-entry table, about 6 KB, and building one per code
// made each code cost more than its finding.
var codeLabelJoiners = strings.NewReplacer(" ", "", "_", "", "-", "")

// canonicalCodeLabel writes a matched label lower-cased with single spaces between its words, so
// "Card_Verification-Value" and "cardverificationvalue" both read "card verification value".
func canonicalCodeLabel(label string) string {
	key := codeLabelJoiners.Replace(strings.ToLower(label))
	switch key {
	case "cardsecuritycode":
		return "card security code"
	case "cardverificationvalue":
		return "card verification value"
	case "cardverificationcode":
		return "card verification code"
	case "cardverificationnumber":
		return "card verification number"
	case "securitycode":
		return "security code"
	}
	return key
}

// bestCard returns the highest-scoring card finding among one line's findings, the first of equals.
// Its cardType is the brand (Metadata["card_type"]), so a code paired with a frame names the frame's
// PAN brand rather than CARD_TRACK_DATA.
func bestCard(lineMatches []detector.Match, lineIdx int) (lineCard, bool) {
	if len(lineMatches) == 0 {
		return lineCard{}, false
	}
	best := lineCard{lineIdx: lineIdx, confidence: -1}
	for _, m := range lineMatches {
		if m.Confidence > best.confidence {
			best.confidence, best.cardType, best.ceiling = m.Confidence, m.Type, 0
			if brand, ok := m.Metadata["card_type"].(string); ok {
				best.cardType = brand
			}
			if c, ok := m.Metadata[confidenceCeilingKey].(float64); ok {
				best.ceiling = c
			}
		}
	}
	return best, true
}

// appendSecurityCodes pairs each candidate with the best card within codeWindow lines and adds the
// codes that are reported. cands and cards are both in line order, so one forward pass pairs them.
//
// A paired code takes its card's confidence and the card's ceiling, so a code beside a published
// test number is held where the number is (#883). A hard negative keyword on the code's own line
// holds it at intrinsicValueFloor, the score the same word gives a card. An unambiguous code with no
// card in reach scores unpairedCodeConfidence; a context-only one is not reported.
func (v *Validator) appendSecurityCodes(matches []detector.Match, cands []codeCandidate, cards []lineCard, originalPath string) []detector.Match {
	lo := 0
	for _, c := range cands {
		for lo < len(cards) && cards[lo].lineIdx < c.lineIdx-codeWindow {
			lo++
		}
		var best lineCard
		paired := false
		for k := lo; k < len(cards) && cards[k].lineIdx <= c.lineIdx+codeWindow; k++ {
			if !paired || cards[k].confidence > best.confidence {
				best, paired = cards[k], true
			}
		}
		if c.contextOnly && !paired {
			continue
		}

		confidence, ceiling := unpairedCodeConfidence, unpairedCodeConfidence
		if paired {
			confidence, ceiling = best.confidence, best.ceiling
		}
		if c.hardNegative && confidence > intrinsicValueFloor {
			// The keyword floor publishes no ceiling, as a card's does not (testValueCeiling).
			confidence, ceiling = intrinsicValueFloor, 0
		}

		meta := map[string]any{
			cardFrameKey:    frameSecurityCode,
			"label":         c.label,
			"paired":        paired,
			"source":        "preprocessed_content",
			"original_file": originalPath,
		}
		if paired {
			meta["paired_card_line"] = best.lineIdx + 1
			meta["paired_card_type"] = best.cardType
		}
		if ceiling > 0 {
			meta[confidenceCeilingKey] = ceiling
		}
		matches = append(matches, detector.Match{
			Text:       c.line[c.start:c.end],
			LineNumber: c.lineIdx + 1,
			// Its own type, outside the card mask (see securityCodeType): --checks CREDIT_CARD
			// reports it, simple and format_preserving mask it whole, and synthetic writes a random
			// string of its length where the card generator wrote the code back unchanged and the
			// output check refused the file.
			Type:       securityCodeType,
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "creditcard",
			Context:    v.buildContextInfoAt(c.line, c.start, c.end),
			Metadata:   meta,
		})
	}
	return matches
}
