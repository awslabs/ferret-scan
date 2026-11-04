// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/bytefold"
	"github.com/awslabs/ferret-scan/v2/internal/tabular"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// This file holds the path that admits a VIN whose OPTIONAL check digit fails and whose WMI is not
// in knownWMIs (#860).
//
// The ISO 3779 position-9 check digit is compulsory only in North America and China (see
// checkDigitRequired); elsewhere, Europe included, a manufacturer may put another character there.
// The scan used to keep such a candidate only when knownWMIs knew its WMI, which is 26 prefixes
// outside North America. Measured with one synthetic VIN per WMI listed in the Wikipedia article
// (revision 1378888660), 852 of 878 VINs from those regions were never reported without a valid
// check digit, not even under a `VIN:` label, because the gate ran before context was scored.
//
// Growing knownWMIs does not fix that: every WMI the table gains also adds +10 to every
// checksum-valid VIN with that prefix, and an all-digit WMI in the table would exempt 17-digit
// numbers from the digit-run rule (isDigitRun). Dropping the WMI requirement admits any
// 17-character token. So the candidate is kept only when the document itself says it is a VIN: a
// label from optionalCheckDigitLabels right beside it, as the header of its column, or as the whole
// of the line above it.
//
// The measurements quoted below were taken for #860 with counterfactual builds of this rule, on
// decoy corpora of 3,300 lines: 300 each of 11 synthetic ID families (EC2/EBS/security-group IDs,
// SteamID64s, 17-digit numbers, millisecond timestamps, 00-prefixed phone numbers, mixed-case
// document IDs, camelCase identifiers, random uppercase tokens, lowercase hex) in one line shape.
// The previous code reports 80 lines of each such corpus, all tokens whose check digit passes by
// chance, and this rule reports the same 80 wherever no VIN label stands beside the token.

// optionalCheckDigitLabels are the labels that vouch for a candidate on the optional-check-digit
// path. The list is code-defined and not configurable, so a discovered config file cannot widen
// what admits a value (#293). It is deliberately NOT positiveKeywords: that list scores a line with
// words such as "make", "model", "year", "title" and "registration", which say a line is about a
// vehicle, not that the token beside them is its VIN. Rescuing on any positive keyword reported 290
// lines of the `make Acme model <token> year 2024 registration pending` corpus, against 80.
//
// Labels are lowercase and matched with kwmatch's label semantics: a space matches zero or more of
// ' ', '\t', '_' and '-', so "vin number" also finds "vin_number", "VIN-Number" and "vinNumber".
// The accented spellings are the same labels as written in French and Spanish.
var optionalCheckDigitLabels = []string{
	"vin", "vins",
	"vin no", "vin nr", "vin number",
	"vehicle identification number", "vehicle identification no", "vehicle id number",
	"chassis number", "chassis no", "chassis nr",
	"frame number", "frame no",
	"fahrgestellnummer", "fahrgestell nr",
	"numero de chassis", "numéro de châssis", "numéro de chassis",
	"numero di telaio",
	"numero de bastidor", "número de bastidor",
}

// labelBoost is what the admitting label adds to a candidate on this path, inside the ±50 context
// cap. The candidate's base is 60 (65, -10 for the failed check digit, +5 for a model year) or 55
// when position 10 is no model year code, as it is on many non-North-American VINs ("Outside of
// North America the 10th digit is usually 0"). A label on the line above, or one positiveKeywords
// does not carry ("Fahrgestellnummer:"), adds no keyword impact, so without the boost those VINs
// scored 60 or 55, the latter LOW and outside a `--confidence high,medium` gate. With it they score
// 85 or 80. The boost applies only here, so no candidate admitted by the check digit or by
// knownWMIs changes its score, and the base stays below the 85 a checksum-verified VIN starts from.
const labelBoost = 25

// analyzeTable is tabular.Analyze, behind a variable so a test can count the calls: a document with
// no candidate on this path must not pay for one.
var analyzeTable = tabular.Analyze

// labelContext is the per-document state of the label test. Every lookup is lazy and cached, the
// table once per document and the line state once per line, so a document with no candidate on this
// path does no extra work and a line packed with candidates stays linear.
type labelContext struct {
	content string
	lines   []string

	table *tabular.Table // nil until a candidate needs its column header

	lineNum    int
	line       string
	lineLower  string
	firstWord  int // offset of the line's first ASCII letter or digit
	boundsDone bool
	bounds     *tabular.LineBounds
	aboveDone  bool
	above      bool
}

// reset points the context at a new line and drops the previous line's state. firstMatch is the
// offset of the line's first regex match, which starts with a letter or digit, so finding firstWord
// reads no further than that.
func (lc *labelContext) reset(lineNum int, line, lineLower string, firstMatch int) {
	lc.lineNum, lc.line, lc.lineLower = lineNum, line, lineLower
	lc.firstWord = firstMatch
	for i := 0; i < firstMatch; i++ {
		if isAlphanumeric(line[i]) {
			lc.firstWord = i
			break
		}
	}
	lc.boundsDone, lc.bounds = false, nil
	lc.aboveDone, lc.above = false, false
}

// vouches reports whether a VIN label vouches for the candidate at line[start:end]. The three
// placements are tried cheapest first, so tabular.Analyze runs only for a candidate that neither an
// adjacent label nor the line above admits.
//
//   - Adjacent: the label is separated from the value by separator bytes only, on either side
//     (`VIN: x`, `"vin": "x"`, `vin=x`, `(VIN x)`, `Chassis no. x`, `x (VIN)`). A byte window is not
//     used: accepting a label anywhere in the 32 bytes before the value reported 290 lines of the
//     `VIN: <valid VIN> updated <token>` corpus, against 80, because it lent the first value's label
//     to the second.
//   - The line above is a bare field label (kwmatch.LooksLikeFieldLabel), as in a form, and the
//     candidate is the first word on its line (only punctuation, a bullet or indentation before
//     it). A label line therefore vouches for the value written under it, not for a token inside
//     the next field's line, as in a form whose VIN field is empty: "VIN" above
//     "Reference: <token>".
//   - The candidate's column header, when the document is a delimited table (tabular).
func (lc *labelContext) vouches(start, end int) bool {
	if labelBefore(lc.line, lc.lineLower, start) || labelAfter(lc.line, lc.lineLower, end) {
		return true
	}
	if start == lc.firstWord && lc.aboveIsLabel() {
		return true
	}
	return lc.headerIsLabel(start)
}

// aboveIsLabel reports whether the line above the current one is a bare VIN field label.
func (lc *labelContext) aboveIsLabel() bool {
	if !lc.aboveDone {
		lc.aboveDone = true
		if lc.lineNum > 0 {
			prev := lc.lines[lc.lineNum-1]
			lc.above = kwmatch.LooksLikeFieldLabel(prev, optionalCheckDigitLabels) && labelLineNamesVIN(prev)
		}
	}
	return lc.above
}

// headerIsLabel reports whether the header of the column holding byte offset start carries a VIN
// label. The header row itself has no header.
func (lc *labelContext) headerIsLabel(start int) bool {
	if lc.table == nil {
		lc.table = analyzeTable(lc.content)
	}
	if !lc.table.IsTable() || lc.lineNum == lc.table.HeaderLine() {
		return false
	}
	if !lc.boundsDone {
		lc.boundsDone = true
		lc.bounds = lc.table.Bounds(lc.line)
	}
	header := lc.table.HeaderAt(lc.bounds, start)
	return header != "" && kwmatch.ContainsAnyLabel(header, optionalCheckDigitLabels)
}

// plausibleUncheckedVIN is the shape a candidate needs before a label may vouch for it. A label
// says the value beside it is a VIN; these guards keep out what a label cannot make one. Each was
// measured by removing it from the rule (300 decoy lines per shape, reported with / without it):
//
//   - the first character is not '0', which is no ISO 3780 region (`vin=0<16 characters>`: 10 /
//     300);
//   - it holds a digit, because a label word can itself be 17 VIN-legal letters
//     (`FAHRGESTELLNUMMER (VIN): x` reported the label word 0 / 300 times);
//   - it is not all hex digits, which also excludes all-digit numbers (`VIN: <17 lowercase hex>`:
//     10 / 185);
//   - it is not mixed case, as document IDs and camelCase identifiers are (`VIN: <mixed-case ID>`:
//     10 / 251). This guard is for this path only: a VIN admitted by its check digit or a known WMI
//     may be written in any case (TestVINValidator_LowercaseAndMixedCase).
//
// The residue with each guard passed the check digit by chance, which the previous code reported
// too. match is the candidate as written (17 bytes from the VIN character class).
func plausibleUncheckedVIN(match string) bool {
	if len(match) != 17 || match[0] == '0' {
		return false
	}
	digit, nonHex, upper, lower := false, false, false, false
	for i := 0; i < len(match); i++ {
		switch c := match[i]; {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
			nonHex = nonHex || c > 'f'
		case c >= 'A' && c <= 'Z':
			upper = true
			nonHex = nonHex || c > 'F'
		}
	}
	return digit && nonHex && !(upper && lower)
}

// isLabelSep reports whether b may stand between a label and its value: whitespace and the
// punctuation of `VIN: x`, `VIN# x`, `vin=x`, `"vin": "x"`, `(VIN x)`, `[VIN] x`, `VIN | x`,
// `VIN - x` and `Chassis no. x`. A comma, semicolon or slash is not one, so in `VINs: x, y` only x
// is vouched for.
func isLabelSep(b byte) bool {
	switch b {
	case ' ', '\t', '\r', ':', '=', '#', '"', '\'', '-', '.', '(', ')', '[', ']', '|':
		return true
	}
	return false
}

// isWordSep is the separator class a space inside a label may match, the one kwmatch's label
// matching uses.
func isWordSep(b byte) bool {
	return b == ' ' || b == '\t' || b == '_' || b == '-'
}

// isWordByte is kwmatch's word byte on lowercased text: '_' is a boundary, so "customer_vin" holds
// the label "vin".
func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

// labelBefore reports whether a VIN label ends where the separator run in front of the value at
// line[start:] begins. lineLower is bytefold.Lower(line), so offsets agree.
func labelBefore(line, lineLower string, start int) bool {
	p := start
	for p > 0 && isLabelSep(lineLower[p-1]) {
		p--
	}
	if p == start || p == 0 {
		// No separator before the value (the regex's \b put a ',' or '/' there), or nothing
		// but separators.
		return false
	}
	for _, label := range optionalCheckDigitLabels {
		s := labelEndsAt(lineLower, p, label)
		if s < 0 {
			continue
		}
		if isBareVIN(label) && !bareVINCounts(line, s, p) {
			continue
		}
		return true
	}
	return false
}

// labelAfter reports whether a VIN label starts where the separator run after the value ending at
// end stops, as in `x (VIN)`. A label followed by ':', '=' or '#' is not counted: it is the key of
// whatever comes next (`ref x VIN: y`), not the label of x. A bare "vin" after the value counts only
// written in capitals, since a key-shaped one is excluded.
func labelAfter(line, lineLower string, end int) bool {
	q := end
	for q < len(lineLower) && isLabelSep(lineLower[q]) {
		q++
	}
	if q == end || q == len(lineLower) {
		return false
	}
	for _, label := range optionalCheckDigitLabels {
		e := labelStartsAt(lineLower, q, label)
		if e < 0 || isKeyFor(lineLower, e) {
			continue
		}
		if isBareVIN(label) && line[q:q+3] != "VIN" {
			continue
		}
		return true
	}
	return false
}

// isBareVIN reports whether label is the bare word "vin" or "vins". Both are also French (and
// Romanian) for wine, so `Commande de vin <ref>` must not vouch for the reference.
func isBareVIN(label string) bool {
	return label == "vin" || label == "vins"
}

// bareVINCounts reports whether the bare "vin"/"vins" at line[s:e] is a VIN label: its stem is
// written in capitals ("VIN", "VINs", "VINS"), or it is a key, the first byte after it that is not
// a space or tab being ':', '=', '#' or a quote (`vin: x`, `vin=x`, `"vin": "x"`, `customer_vin: x`).
// Counting the lowercase word too reported 290 lines of the `Commande de vin <token>` corpus,
// against 80.
func bareVINCounts(line string, s, e int) bool {
	if line[s:s+3] == "VIN" {
		return true
	}
	return isKeyAt(line, e, true)
}

// isKeyFor reports whether the label ending at e is a key: the next byte after it that is not a
// space or tab is ':', '=' or '#'.
func isKeyFor(lineLower string, e int) bool {
	return isKeyAt(lineLower, e, false)
}

// isKeyAt reports whether the first byte at or after i that is not a space or tab is ':', '=' or
// '#', or, when quotes is set, a quote.
func isKeyAt(s string, i int, quotes bool) bool {
	for ; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t':
			continue
		case ':', '=', '#':
			return true
		case '"', '\'':
			return quotes
		}
		return false
	}
	return false
}

// labelLineNamesVIN applies the bare-"vin" rule to a line kwmatch.LooksLikeFieldLabel accepted: the
// line holds one of the longer labels, or a bare "vin"/"vins" that bareVINCounts accepts. A form
// line reading "VIN" or "vin:" qualifies; one reading "vin" does not.
func labelLineNamesVIN(line string) bool {
	lower := strings.ToLower(line)
	for _, label := range optionalCheckDigitLabels {
		if !isBareVIN(label) && kwmatch.ContainsLabelLower(lower, label) {
			return true
		}
	}
	folded := bytefold.Lower(line) // offsets agree with line, which bareVINCounts reads
	for _, label := range []string{"vin", "vins"} {
		if kwmatch.ContainsFunc(folded, label, func(s, e int) bool { return bareVINCounts(line, s, e) }) {
			return true
		}
	}
	return false
}

// labelEndsAt returns the offset at which label occurs in text ending exactly at end, or -1. A space
// in label matches zero or more isWordSep bytes; every other byte matches itself. The occurrence
// must start at a word boundary. Label words hold no separator byte, so consuming a separator run
// greedily needs no backtracking.
func labelEndsAt(text string, end int, label string) int {
	ti, li := end, len(label)
	for li > 0 {
		if label[li-1] == ' ' {
			for li > 0 && label[li-1] == ' ' {
				li--
			}
			for ti > 0 && isWordSep(text[ti-1]) {
				ti--
			}
			continue
		}
		if ti == 0 || text[ti-1] != label[li-1] {
			return -1
		}
		ti--
		li--
	}
	if ti > 0 && isWordByte(text[ti-1]) {
		return -1
	}
	return ti
}

// labelStartsAt returns the end offset of label occurring in text from start, or -1, with
// labelEndsAt's matching rules; the occurrence must end at a word boundary.
func labelStartsAt(text string, start int, label string) int {
	ti, li := start, 0
	for li < len(label) {
		if label[li] == ' ' {
			for li < len(label) && label[li] == ' ' {
				li++
			}
			for ti < len(text) && isWordSep(text[ti]) {
				ti++
			}
			continue
		}
		if ti >= len(text) || text[ti] != label[li] {
			return -1
		}
		ti++
		li++
	}
	if ti < len(text) && isWordByte(text[ti]) {
		return -1
	}
	return ti
}
