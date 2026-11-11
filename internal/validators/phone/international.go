// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"regexp"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// International display forms, phone contexts and the E.164 gate (#889).
//
// The patterns in NewValidator are what main reported, and they still run first and unchanged: the
// findings they produce on a line are main's findings for that line. This file adds what they
// cannot express, and then lets the wider reading win:
//
//   - one international grammar (scanIntl) for "+CC", "00CC" and "(+CC)" numbers with a "(0)" trunk
//     slot, a bracketed area code, groups of any width and "/" as a separator, read in every phone
//     context: after "(", "[" and "/", after "tel:", in a vCard TEL value, and after ":" or "=";
//   - the national "(NNN) NNN-NNNN" forms in those new contexts, and the UK "(0NN) NNNN NNNN" form;
//   - the E.164 gate (e164Codes): an assigned code, a national length the code's plan allows, at
//     most 15 digits;
//   - widest span first: a reading that covers one of main's findings and passes replaces it, so
//     "+1 297 201 0052", "1-888-201-0055" and "297-201-0056 ext 27" are one finding with their prefix
//     or extension, and "0033 1 99 00 47 18" is not truncated after "00".
//
// What it never does is drop a byte main reports. A finding of main's is only ever replaced by a
// reading that contains it, and a reading the gate refuses never displaces one: it is not emitted,
// or, when the only findings it covers are LOW anyway, it replaces them at LOW. Main's own findings
// in the "+" and "00" forms are judged by the same gate and capped at LOW when they fail it, never
// removed: redaction ignores confidence, so a capped finding is still masked (#364).

// e164Code is one assigned country calling code (e164_codes.go).
type e164Code struct {
	region  string // main region: ISO 3166-1 alpha-2, or "001" for a non-geographic code
	lengths uint32 // bit n set: n digits is a possible national (significant) number length
	trunk0  bool   // the plan writes a trunk "0" before a national number, shown as "(0)"
}

// possibleLength reports whether n digits is a national number length the code's plan allows.
func (c e164Code) possibleLength(n int) bool {
	return n > 0 && n < 32 && c.lengths&(1<<uint(n)) != 0
}

// e164MaxDigits is E.164's maximum length: the country code and the national significant number
// together.
const e164MaxDigits = 15

// e164GateCeiling is the confidence of a finding of main's that the gate refuses, and of a reading
// whose phone context names nothing: the top of LOW, as reservedFictionalCeiling and for its reason.
// Low enough that --confidence medium,high never sees it, high enough that it is still reported and
// therefore still redacted.
const e164GateCeiling = reservedFictionalCeiling

// longestAssignedPrefix returns the assigned calling code that begins digits, or "". At most one of
// a run's 1-, 2- and 3-digit prefixes can be a code, because E.164 codes are a prefix code; the
// generator refuses a table where that does not hold.
func longestAssignedPrefix(digits string) string {
	for k := 3; k >= 1; k-- {
		if len(digits) >= k {
			if _, ok := e164Codes[digits[:k]]; ok {
				return digits[:k]
			}
		}
	}
	return ""
}

// countryLabelForCode is the metadata "country" of a number with this calling code. NANP and the UK
// keep the labels this validator has always given their national patterns, so a "+1" or "+44"
// number reads the same whichever pattern found it; every other code reports its main region.
func countryLabelForCode(code string) string {
	switch code {
	case "1":
		return "US/CA"
	case "44":
		return "UK"
	}
	c, ok := e164Codes[code]
	if !ok {
		return "Unknown"
	}
	if c.region == "001" {
		return "International"
	}
	return c.region
}

// gateVerdict is the E.164 gate's verdict on an international reading.
type gateVerdict int

const (
	gatePass gateVerdict = iota
	// gateLength: an assigned code and at most 15 digits, but a national length the code's plan does
	// not list. The weaker of the two failures: the length table is a summary of national plans
	// that change, so a phone word on the line outweighs it for a value main already reports.
	gateLength
	// gateCode: no assigned code, a "(0)" the code's plan does not write, or more than 15 digits.
	// Not a number E.164 can route at all.
	gateCode
)

// judge returns the gate's verdict on a calling code and a national significant number of
// national digits, with trunk set when a "(0)" was written between them.
func judge(code string, national int, trunk bool) gateVerdict {
	c, ok := e164Codes[code]
	if !ok || len(code)+national > e164MaxDigits || (trunk && !c.trunk0) {
		return gateCode
	}
	if !c.possibleLength(national) {
		return gateLength
	}
	return gatePass
}

// intlNumber is an international reading: its calling code as read ("" when none is assigned) and
// the gate's verdict. glued is set when the reading is grouped but its code is not a group of its
// own ("+1130 2010"): E.123 writes the code apart from the rest whenever a number is grouped, so
// only an unseparated number ("+442079460627") reads its code off the front of a longer run.
type intlNumber struct {
	code    string
	verdict gateVerdict
	glued   bool
}

// maxIntlGroups bounds how many digit groups (an area code in brackets counts as one) a reading
// takes after its country code: seven groups, as the issue's grammar has it, and one bracketed area.
const maxIntlGroups = 8

// isDigitByte reports whether b is an ASCII digit.
func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

// isIntlSep reports whether b separates two digit groups of an international number.
func isIntlSep(b byte) bool { return b == ' ' || b == '-' || b == '.' || b == '/' }

// reIntlExtension matches an extension written straight after a number, as the extension
// patterns of NewValidator do.
var reIntlExtension = regexp.MustCompile(`^[-.\s]?(?i:ext\.?|extension|x)[-.\s]?\d{1,6}`)

// scanIntl reads the international number that starts at s, where line[s] is '+', the '(' of
// "(+CC)" or the first '0' of "00". It returns the end of the reading it chose, its parse, and
// ok=false when nothing there is a reading at all.
//
// The grammar is prefix CC [sep] ['(0)' [sep]] ['(' area ')' [sep]] group (sep group)* [ext], the
// prefix one of "+", "00" and "(+CC)", sep one of space, '-', '.' and '/'. The code is exactly the
// first group when that group has 1-3 digits and is followed by a separator or a bracket; otherwise
// (an unseparated number, or a first group longer than a code) it is the group's longest assigned
// prefix.
//
// The greedy reading takes every group. When it fails the gate, the longest shorter reading that
// passes is taken instead, but only one that ends before a space: a reading that ends before
// "-5", ".5" or "/5" has cut a number in two, which is what left subscriber digits in cleartext.
// When no reading passes, the greedy one is returned with its failing verdict.
func scanIntl(line string, s int) (end int, num intlNumber, ok bool) {
	n := len(line)
	p := s
	code := ""
	separated := false
	unassigned := false
	national := 0

	switch {
	case line[p] == '(':
		q := p + 2
		if q >= n || line[p+1] != '+' || !isDigitByte(line[q]) {
			return 0, num, false
		}
		for q < n && isDigitByte(line[q]) {
			q++
		}
		if q-(p+2) > 3 || q >= n || line[q] != ')' {
			return 0, num, false
		}
		code, separated = line[p+2:q], true
		p = q + 1
	case line[p] == '+':
		p++
	default:
		p += 2
	}

	if code == "" {
		q := p
		for q < n && isDigitByte(line[q]) {
			q++
		}
		g := line[p:q]
		if g == "" {
			return 0, num, false
		}
		if len(g) <= 3 && q < n && (isIntlSep(line[q]) || line[q] == '(') {
			code, separated = g, true
		} else if code = longestAssignedPrefix(g); code == "" {
			unassigned = true
			national = len(g)
		} else {
			national = len(g) - len(code)
		}
		p = q
	}

	type cut struct{ end, digits int }
	var cuts [maxIntlGroups + 1]cut
	ncuts := 0
	if national > 0 {
		cuts[0] = cut{p, national}
		ncuts = 1
	}
	groups := ncuts
	slots := separated && national == 0
	trunk, area := false, false
	for groups < maxIntlGroups {
		q := p
		if q < n && isIntlSep(line[q]) {
			q++
		}
		if q >= n {
			break
		}
		if slots && !trunk && !area && strings.HasPrefix(line[q:], "(0)") {
			trunk = true
			p = q + 3
			continue
		}
		if slots && !area && line[q] == '(' {
			r := q + 1
			for r < n && isDigitByte(line[r]) {
				r++
			}
			if r-(q+1) < 1 || r-(q+1) > 5 || r >= n || line[r] != ')' {
				break
			}
			area = true
			national += r - (q + 1)
			groups++
			p = r + 1
			continue
		}
		if !isDigitByte(line[q]) {
			break
		}
		r := q
		for r < n && isDigitByte(line[r]) {
			r++
		}
		national += r - q
		groups++
		slots = false
		p = r
		cuts[ncuts] = cut{p, national}
		ncuts++
	}
	if ncuts == 0 {
		return 0, num, false
	}

	verdictOf := func(c cut) gateVerdict {
		if unassigned {
			return gateCode
		}
		return judge(code, c.digits, trunk)
	}
	chosen := ncuts - 1
	verdict := verdictOf(cuts[chosen])
	if verdict != gatePass {
		for i := ncuts - 2; i >= 0; i-- {
			if line[cuts[i].end] != ' ' {
				continue
			}
			if v := verdictOf(cuts[i]); v == gatePass {
				chosen, verdict = i, v
				break
			}
		}
	}
	end = cuts[chosen].end
	if chosen == ncuts-1 {
		if loc := reIntlExtension.FindStringIndex(line[end:min(end+24, n)]); loc != nil {
			if e := end + loc[1]; e >= n || !isWordByteASCII(line[e]) {
				end = e
			}
		}
	}
	return end, intlNumber{code: assignedOrEmpty(code), verdict: verdict, glued: !separated && chosen > 0}, true
}

// assignedOrEmpty returns code when it is an assigned calling code, else "".
func assignedOrEmpty(code string) string {
	if _, ok := e164Codes[code]; ok {
		return code
	}
	return ""
}

// stripExtension removes a trailing extension ("ext 12", "x456"). Every extension marker carries an
// 'x', so a text without one is returned as it is, without running the regex.
func stripExtension(text string) string {
	if strings.IndexAny(text, "xX") < 0 {
		return text
	}
	return rePhoneExtensionSuffix.ReplaceAllString(text, "")
}

// isIntlText reports whether a match is written in an international form the gate judges.
func isIntlText(text string) bool {
	return strings.HasPrefix(text, "+") || strings.HasPrefix(text, "00") || strings.HasPrefix(text, "(+")
}

// judgeIntlText is the gate's verdict on a whole match in an international form: its calling code
// read as scanIntl reads it, and every digit after the code, less a "(0)" and an extension, as its
// national number. It judges the span as reported, never a shorter reading of it.
func judgeIntlText(text string) intlNumber {
	t := stripExtension(text)
	p := 0
	code := ""
	separated := false
	switch {
	case strings.HasPrefix(t, "(+"):
		q := 2
		for q < len(t) && isDigitByte(t[q]) {
			q++
		}
		if q-2 >= 1 && q-2 <= 3 && q < len(t) && t[q] == ')' {
			code, separated = t[2:q], true
			p = q + 1
		} else {
			return intlNumber{verdict: gateCode}
		}
	case strings.HasPrefix(t, "+"):
		p = 1
	default:
		p = 2
	}
	national := 0
	if code == "" {
		q := p
		for q < len(t) && isDigitByte(t[q]) {
			q++
		}
		g := t[p:q]
		if len(g) >= 1 && len(g) <= 3 && q < len(t) && (isIntlSep(t[q]) || t[q] == '(') {
			code, separated = g, true
		} else if code = longestAssignedPrefix(g); code == "" {
			return intlNumber{verdict: gateCode}
		} else {
			national = len(g) - len(code)
		}
		p = q
	}
	rest := t[p:]
	trunk := false
	if separated {
		r := strings.TrimLeft(rest, " -./")
		if strings.HasPrefix(r, "(0)") {
			trunk = true
			rest = r[3:]
		}
	}
	national += digitCount(rest)
	return intlNumber{code: assignedOrEmpty(code), verdict: judge(code, national, trunk)}
}

// boundary is what precedes a candidate, and what that does to it.
type boundary int

const (
	// boundaryRefuse: a letter, digit or other character a phone number is not written after, or an
	// identifier label ("id:", "token=").
	boundaryRefuse boundary = iota
	// boundaryLegacy: the start of the line, whitespace or one of , ; | " ' < >, the characters the
	// "+"- and "("-led patterns of NewValidator have always accepted.
	boundaryLegacy
	// boundaryOpen: '(', '[' or '/'.
	boundaryOpen
	// boundaryPhone: ':' or '=' after a phone label, a "tel:" URI or the value of a vCard TEL property.
	boundaryPhone
	// boundaryUnlabelled: ':' or '=' after a word that names neither a phone nor an identifier.
	// Reported at LOW: a missing vocabulary word costs confidence, never a leak.
	boundaryUnlabelled
)

// intlPhoneLabelWords are the labels, beyond phoneLabelWords and phoneEvidenceTokens, that name a
// phone in the languages the international forms are written in. Used only for the new ":"/"="
// contexts; the colon rescue of the national patterns already accepts a label it does not know.
var intlPhoneLabelWords = []string{
	"telefon", "téléphone", "tél", "teléfono", "telefone", "telefono", "móvil", "celular",
	"handy", "mobil", "portable", "cellulare", "gsm",
}

// classifyBoundary decides what the byte before a candidate starting at s does to it.
func classifyBoundary(line string, s int) boundary {
	if s == 0 {
		return boundaryLegacy
	}
	switch line[s-1] {
	case ' ', '\t', '\n', '\f', '\r', ',', ';', '|', '"', '\'', '<', '>':
		return boundaryLegacy
	case '(', '[', '/':
		return boundaryOpen
	case ':', '=':
		if isTelURIValue(line, s) || isVCardTelValue(line, s) {
			return boundaryPhone
		}
		return classifyDelimiterLabel(labelBeforeDelimiter(line, s-1))
	}
	return boundaryRefuse
}

// classifyDelimiterLabel classifies the word before a ':' or '='.
func classifyDelimiterLabel(label string) boundary {
	if label == "" {
		return boundaryUnlabelled
	}
	for _, lists := range [][]string{phoneLabelWords, phoneEvidenceTokens, intlPhoneLabelWords} {
		for _, w := range lists {
			if labelMatchesWord(label, w) {
				return boundaryPhone
			}
		}
	}
	for _, w := range identifierLabelWords {
		if labelMatchesWord(label, w) {
			return boundaryRefuse
		}
	}
	return boundaryUnlabelled
}

// labelBeforeDelimiter returns the lower-cased word that ends right before the ':' or '=' at d,
// skipping one closing quote: "phone" in "phone=", "Telefon" in "Telefon:", "bytes_delta" in
// "bytes_delta:". Non-ASCII bytes are word bytes, so "Téléphone" is one word.
func labelBeforeDelimiter(line string, d int) string {
	i := d - 1
	if i >= 0 && (line[i] == '"' || line[i] == '\'') {
		i--
	}
	end := i + 1
	for i >= 0 && (isWordByteASCII(line[i]) || line[i] == '-' || line[i] == '.' || line[i] >= 0x80) {
		i--
	}
	return strings.ToLower(line[i+1 : end])
}

// isTelURIValue reports whether s is the first byte after an RFC 3966 "tel:" scheme: "tel:" in any
// case, itself at the start of the line or after whitespace, a quote, '=', '<', '(' or ':'.
func isTelURIValue(line string, s int) bool {
	if s < 4 || !strings.EqualFold(line[s-4:s], "tel:") {
		return false
	}
	return s == 4 || strings.IndexByte(" \t\"'=<(:", line[s-5]) >= 0
}

// isVCardTelValue reports whether s is where the value of a vCard TEL property starts (RFC 6350,
// RFC 2426): a line "[group.]TEL[;param=value]*:value", the value after the first ':' outside double
// quotes.
func isVCardTelValue(line string, s int) bool {
	i := 0
	j := 0
	for j < len(line) && (isWordByteASCII(line[j]) || line[j] == '-') {
		j++
	}
	if j > 0 && j < len(line) && line[j] == '.' {
		i = j + 1
	}
	if i+3 >= len(line) || !strings.EqualFold(line[i:i+3], "TEL") || (line[i+3] != ';' && line[i+3] != ':') {
		return false
	}
	quoted := false
	for k := i + 3; k < len(line) && k < s; k++ {
		switch line[k] {
		case '"':
			quoted = !quoted
		case ':':
			if !quoted {
				return k+1 == s
			}
		}
	}
	return false
}

// truncatedAt reports whether a span [s, e) of line is a piece of a longer number: it ends right
// before a digit or before '-', '.' or '/' and a digit, or starts right after a digit, a '+' or a
// "(0)". Such a reading leaves the rest of the number in cleartext.
func truncatedAt(line string, s, e int) bool {
	if e < len(line) {
		c := line[e]
		if isDigitByte(c) {
			return true
		}
		if (c == '-' || c == '.' || c == '/') && e+1 < len(line) && isDigitByte(line[e+1]) {
			return true
		}
	}
	if s > 0 && (isDigitByte(line[s-1]) || line[s-1] == '+') {
		return true
	}
	return s >= 3 && line[s-3:s] == "(0)"
}

// nanpPossibleText reports whether a "+1" reading's national number is one the North American plan
// can assign (nanpPossible), its extension left out.
func nanpPossibleText(text string) bool {
	t := stripExtension(text)
	d := make([]byte, 0, 11)
	for i := 0; i < len(t); i++ {
		if isDigitByte(t[i]) {
			d = append(d, t[i])
		}
	}
	if len(d) == 11 && d[0] == '1' {
		d = d[1:]
	}
	return nanpPossible(string(d))
}

// decimalShaped reports whether a "+"-led reading is written the way signed decimals are, not the way
// numbers with dots are. A number written with dots puts one between every group ("+44.20.7946.0958",
// "+1 415.555.0123"), so:
//
//   - two digit runs joined by a single '.' are a decimal: "+9252.619193895", the monotonic clock
//     reading time.Time prints as "m=+9252.619193895", as isDecimalFractionTail reasons for a
//     fractional tail;
//   - a '.' beside a '-' or '/' between the national groups is a coordinate or a range:
//     "+49.78461-159.03771/" is ISO 6709.
//
// A "00"-led text is read the same way, its first group the prefix and the code: "00125.37" and
// "00074.56695-7" are decimals (#938). It refuses new grammar readings in both forms; main's findings
// go through decimalNotPhone, which keeps the EPP form.
func decimalShaped(text string) bool {
	first := 1
	if strings.HasPrefix(text, "00") {
		first = 0
	} else if !strings.HasPrefix(text, "+") {
		return false
	}
	if strings.IndexByte(text, '.') < 0 {
		return false
	}
	// The separators after the first group: a space straight after the code is how every
	// international number is written, so it does not count as mixing.
	seps := make([]byte, 0, 8)
	groups := 0
	for i := first; i < len(text); {
		if !isDigitByte(text[i]) {
			if groups > 0 && !(groups == 1 && text[i] == ' ') {
				seps = append(seps, text[i])
			}
			i++
			continue
		}
		for i < len(text) && isDigitByte(text[i]) {
			i++
		}
		groups++
	}
	if groups == 2 && len(seps) == 1 && seps[0] == '.' {
		return true
	}
	dots, others := 0, 0
	for _, s := range seps {
		switch s {
		case '.':
			dots++
		case '-', '/':
			others++
		}
	}
	return dots > 0 && others > 0
}

// decimalNotPhone reports whether one of main's findings is a decimal rather than a number (#938):
// a "00"-led one decimalShaped reads as one ("00125.37", "00074.56695-7"), or a "+"-led one whose
// first run, longer than any calling code, ends in the decimal point ("+9252.619193895"). A "+"
// reading whose '.' follows a code of 1-3 digits is how EPP (RFC 5733) writes a number,
// "+1.7035550123", and is kept.
func decimalNotPhone(text string) bool {
	if strings.HasPrefix(text, "00") {
		return decimalShaped(text)
	}
	if !strings.HasPrefix(text, "+") || !decimalShaped(text) {
		return false
	}
	i := 1
	for i < len(text) && isDigitByte(text[i]) {
		i++
	}
	return i-1 > 3 && i < len(text) && text[i] == '.'
}

// integerPartOfDecimal reports whether an unseparated match (digits, after an optional '+') is the
// integer part of a decimal: a '.' and a digit straight after it, "0000000001" of "0000000001.1" or
// "+1234567891011" of "+1234567891011.234" (#938). A match with separators is left alone: a number
// written with dots continues with dots, and main's patterns take it whole.
func integerPartOfDecimal(match, line string, end int) bool {
	if end+1 >= len(line) || line[end] != '.' || !isDigitByte(line[end+1]) {
		return false
	}
	for i := 0; i < len(match); i++ {
		if !isDigitByte(match[i]) && !(i == 0 && match[i] == '+') {
			return false
		}
	}
	return true
}

// iso6709MaxLen bounds an ISO 6709 point string: "+DDMMSS.SSSS-DDDMMSS.SSSS+AAAAA.AAACRSWGS_84/" is
// under 50 bytes. It bounds the walk back from a candidate and the parse forward, so the check costs
// a constant per match whatever the line.
const iso6709MaxLen = 80

// inISO6709Point reports whether [s, e) of line lies inside an ISO 6709 point string (#938), the form
// the QuickTime "xyz" location atom, com.apple.quicktime.location.ISO6709 and XMP GPS fields write a
// position in. Its token starts at the sign of the latitude: the run of digits, '.', '+' and '-' that
// s sits in, which a point string is written apart from.
func inISO6709Point(line string, s, e int) bool {
	q := s
	for q > 0 && s-q < iso6709MaxLen {
		c := line[q-1]
		if !isDigitByte(c) && c != '.' && c != '+' && c != '-' {
			break
		}
		q--
	}
	if q < len(line) && (line[q] == '+' || line[q] == '-') {
		if end := iso6709End(line, q); end >= e {
			return true
		}
	}
	return false
}

// iso6709End returns the end of the ISO 6709 point string starting at s (Annex H: latitude, longitude,
// an optional altitude and CRS, and the terminating '/'), or -1. Latitude has 2, 4 or 6 integer digits
// (DD, DDMM, DDMMSS), longitude 3, 5 or 7, each with an optional fraction. To leave a phone number
// written with '/' after the area code ("+49-911/1234567", "+49-911/ 1234567") alone, the '/' must not
// be followed by a digit, and a point with neither a fraction nor more than degrees is not taken.
func iso6709End(line string, s int) int {
	lim := min(len(line), s+iso6709MaxLen)
	p, latInt, latFrac, ok := iso6709Number(line, s, lim)
	if !ok || (latInt != 2 && latInt != 4 && latInt != 6) {
		return -1
	}
	p, lonInt, lonFrac, ok := iso6709Number(line, p, lim)
	if !ok || (lonInt != 3 && lonInt != 5 && lonInt != 7) {
		return -1
	}
	if p < lim && (line[p] == '+' || line[p] == '-') {
		if p, _, _, ok = iso6709Number(line, p, lim); !ok {
			return -1
		}
	}
	if p+3 <= lim && line[p:p+3] == "CRS" {
		d := p + 3
		for p = d; p < lim && isWordByteASCII(line[p]); p++ {
		}
		if p == d {
			return -1
		}
	}
	if p >= lim || line[p] != '/' || (p+1 < len(line) && isDigitByte(line[p+1])) {
		return -1
	}
	if !latFrac && !lonFrac && latInt < 4 {
		return -1
	}
	return p + 1
}

// iso6709Number reads a sign, an integer part and an optional fraction starting at p, before lim. It
// returns where the number ends, how many integer digits it has and whether it has a fraction; a '.'
// with no digit after it is not a number.
func iso6709Number(line string, p, lim int) (end, intDigits int, frac, ok bool) {
	if p >= lim || (line[p] != '+' && line[p] != '-') {
		return p, 0, false, false
	}
	p++
	d := p
	for p < lim && isDigitByte(line[p]) {
		p++
	}
	intDigits = p - d
	if intDigits == 0 {
		return p, 0, false, false
	}
	if p < lim && line[p] == '.' {
		f := p + 1
		for p = f; p < lim && isDigitByte(line[p]); p++ {
		}
		if p == f {
			return p, 0, false, false
		}
		frac = true
	}
	return p, intDigits, frac, true
}

// intlGrammarPattern is the pattern a grammar reading is scored and reported with.
var intlGrammarPattern = phonePattern{
	name:    "International_E164",
	country: "International",
	format:  "+CC [(0)] [(AREA)] NNNN NNNN",
}

// The national forms read in the new contexts: the "("-led NANP patterns of NewValidator, anchored,
// and the UK national form with its area code in brackets. Matched against a short window, so each
// attempt costs a bounded amount whatever the line.
var (
	reUSParenAt         = regexp.MustCompile(`^\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b`)
	reUSParenExtAt      = regexp.MustCompile(`^\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}[-.\s]?(?:ext\.?|extension|x)[-.\s]?\d{1,6}\b`)
	reUSTollFreeParenAt = regexp.MustCompile(`^\((?:800|833|844|855|866|877|888)\)[-.\s]?\d{3}[-.\s]?\d{4}\b`)
	reUKParenAt         = regexp.MustCompile(`^\(0\d{2,4}\)[-.\s]?\d{3,8}(?:[-.\s]\d{3,4})?\b`)
)

// parenWindow bounds the bytes a national bracketed form is matched against; the longest, the NANP
// form with a six-digit extension, is under 40.
const parenWindow = 64

// lineFinding is one of main's findings on the current line (from the patterns of NewValidator).
// The finding itself is stored once, in the caller's slice of matches (lineResolver.ms); this is
// what the resolution needs beside it.
type lineFinding struct {
	start, end   int
	corroborated bool
	replacedBy   int // index of the wide reading that replaced it, or -1
}

// acceptedReading is a wide reading the resolution accepted.
type acceptedReading struct {
	m          detector.Match
	start, end int
}

// rawCand is a match of one of NewValidator's patterns, before main's checks decided whether it is
// reported.
type rawCand struct {
	start, end int
	pattern    int
}

// wideCand is a reading that may replace main's findings or add one: a pattern match wider than a
// finding it contains, a grammar reading, or a national form in a new context.
type wideCand struct {
	start, end int
	pattern    int // index into Validator.patterns, or -1 for a grammar reading
	priority   int // tie order for equal spans: pattern order, grammar readings last
	bound      boundary
	num        intlNumber
	intl       bool
	contained  []int // indexes into the line's findings that the reading contains
}

// lineResolver holds the per-line buffers of the resolution, reused across lines.
type lineResolver struct {
	// raw holds the pattern matches main's checks or dedup set aside; the matches it accepted are
	// found. A finding never contains another (main's dedup refuses a match whose digits contain an
	// accepted one's), so only a set-aside match can be wider than a finding.
	raw     []rawCand
	found   []lineFinding
	ms      []detector.Match // the line's findings, parallel to found
	line    string
	order   []int
	starts  []int // found[order[k]].start
	maxE    []int
	indexed bool
	wide    []wideCand

	// seen holds the texts reported on the line so far (main's findings and the readings accepted,
	// recorded in acceptedTexts), built on the first new reading; skipped the new readings not
	// evaluated because their text is in it.
	seen          map[string]struct{}
	acceptedTexts []string
	skipped       []rawCand
}

func (r *lineResolver) reset() {
	r.raw = r.raw[:0]
	r.found = r.found[:0]
	r.indexed = false
	r.wide = r.wide[:0]
	r.seen = nil
	r.acceptedTexts = r.acceptedTexts[:0]
	r.skipped = r.skipped[:0]
}

// alreadyReported reports whether text is reported on the line already: by one of main's findings
// or by a reading accepted so far.
func (r *lineResolver) alreadyReported(text string) bool {
	if r.seen == nil {
		r.seen = make(map[string]struct{}, len(r.found)+len(r.acceptedTexts)+8)
		for i := range r.found {
			r.seen[r.ms[i].Text] = struct{}{}
		}
		for _, t := range r.acceptedTexts {
			r.seen[t] = struct{}{}
		}
	}
	_, ok := r.seen[text]
	return ok
}

// reported records the text of an accepted reading.
func (r *lineResolver) reported(text string) {
	r.acceptedTexts = append(r.acceptedTexts, text)
	if r.seen != nil {
		r.seen[text] = struct{}{}
	}
}

// index lists the line's findings by start in order, and sets maxE[k] to the largest end among the
// first k of them. Built on the first overlap query, so a line nothing is checked against pays
// nothing for it.
func (r *lineResolver) index() {
	r.indexed = true
	r.order = r.order[:0]
	for i := range r.found {
		r.order = append(r.order, i)
	}
	sort.SliceStable(r.order, func(a, b int) bool {
		fa, fb := &r.found[r.order[a]], &r.found[r.order[b]]
		if fa.start != fb.start {
			return fa.start < fb.start
		}
		return fa.end < fb.end
	})
	r.maxE = r.maxE[:0]
	r.starts = r.starts[:0]
	m := -1
	for _, i := range r.order {
		if r.found[i].end > m {
			m = r.found[i].end
		}
		r.maxE = append(r.maxE, m)
		r.starts = append(r.starts, r.found[i].start)
	}
}

// firstStartingAtOrAfter returns the position in order of the first finding starting at or after s.
func (r *lineResolver) firstStartingAtOrAfter(s int) int {
	lo, hi := 0, len(r.starts)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if r.starts[mid] < s {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo
}

// overlap classifies the line's findings against the span [s, e): the ones it contains, and
// whether any overlaps it without being contained. A span costs a binary search over the index
// plus the findings that start inside it.
func (r *lineResolver) overlap(s, e int) (contained []int, partial bool) {
	if !r.indexed {
		r.index()
	}
	k := r.firstStartingAtOrAfter(s)
	if k > 0 && r.maxE[k-1] > s {
		return nil, true
	}
	for j := k; j < len(r.order); j++ {
		f := &r.found[r.order[j]]
		if f.start >= e {
			break
		}
		if f.end > e {
			return nil, true
		}
		contained = append(contained, r.order[j])
	}
	return contained, false
}

// sameSpan reports whether contained is exactly one finding with the span [s, e).
func (r *lineResolver) sameSpan(contained []int, s, e int) bool {
	for _, i := range contained {
		if r.found[i].start == s && r.found[i].end == e {
			return true
		}
	}
	return false
}

// resolve turns main's findings on a line into the line's findings, appended to dst: the gate judges
// main's international ones, then every wider or new reading is tried, leftmost and widest first.
//
// matches[base:] are main's findings on the line, parallel to r.found; the result is matches with
// that segment rewritten, which on a line nothing widens is matches as it was.
func (v *Validator) resolve(ls *lineScoring, r *lineResolver, originalPath string, matches []detector.Match, base int) []detector.Match {
	line := ls.line
	r.ms = matches[base:]
	r.line = line

	// Main's findings in the "+" and "00" forms that the gate refuses are capped, never removed. A
	// length the table does not list is outweighed by a phone word on the line ("call +1 449-87-4100"),
	// an unassigned code or more than 15 digits never is.
	for i := range r.found {
		m := &r.ms[i]
		if !isIntlText(m.Text) {
			continue
		}
		if num := judgeIntlText(m.Text); num.verdict == gateCode || (num.verdict == gateLength && !r.found[i].corroborated) {
			capAtGate(m)
		}
	}

	// Without a finding nothing can be widened, and without a '+', a '(' or a "00" no grammar reading
	// or bracketed form can start: the line is main's as it stands.
	wideSource := mayHoldWideReading(line)
	if !wideSource && (len(r.found) == 0 || len(r.raw) == 0) {
		return matches
	}

	// Pattern matches main's checks or its first-pattern-wins dedup set aside, wider than a finding
	// they contain: the extension, the "1-" of a toll-free number, the "+1" or "+39" whose tail
	// US_Dashed claimed. A match no longer than the shortest finding cannot contain one, which is
	// every repeat main's dedup set aside on a dense line, so those cost no lookup.
	shortest := -1
	for i := range r.found {
		if l := r.found[i].end - r.found[i].start; shortest < 0 || l < shortest {
			shortest = l
		}
	}
	for _, c := range r.raw {
		if c.end-c.start <= shortest {
			continue
		}
		contained, partial := r.overlap(c.start, c.end)
		if partial || len(contained) == 0 || r.sameSpan(contained, c.start, c.end) {
			continue
		}
		text := line[c.start:c.end]
		w := wideCand{start: c.start, end: c.end, pattern: c.pattern, priority: c.pattern, bound: boundaryLegacy, contained: contained}
		if isIntlText(text) {
			w.intl, w.num = true, judgeIntlText(text)
		}
		r.wide = append(r.wide, w)
	}

	if wideSource {
		v.scanWideReadings(line, r)
	}
	if len(r.wide) == 0 {
		return matches
	}

	sort.SliceStable(r.wide, func(a, b int) bool {
		wa, wb := &r.wide[a], &r.wide[b]
		if wa.start != wb.start {
			return wa.start < wb.start
		}
		if la, lb := wa.end-wa.start, wb.end-wb.start; la != lb {
			return la > lb
		}
		return wa.priority < wb.priority
	})

	// A new reading whose text is already reported on the line is not reported again, as main's
	// dedup never reported a repeat: redaction's completeness sweep masks every occurrence of a
	// reported text (plaintext.redactText, redactverify.SweepRemaining), and the Office redactors
	// replace by value. The skipped spans are kept, because they are occurrences of that text.
	var accepted []acceptedReading
	lastEnd := -1
	for wi := range r.wide {
		w := &r.wide[wi]
		if w.start < lastEnd {
			continue
		}
		if len(w.contained) == 0 && r.alreadyReported(line[w.start:w.end]) {
			r.skipped = append(r.skipped, rawCand{start: w.start, end: w.end, pattern: -1})
			continue
		}
		f, ok := v.evaluateWide(ls, r, w, originalPath)
		if !ok {
			continue
		}
		idx := len(accepted)
		for _, i := range w.contained {
			r.found[i].replacedBy = idx
		}
		accepted = append(accepted, f)
		r.reported(f.m.Text)
		lastEnd = w.end
	}
	if len(accepted) > 0 {
		r.keepRepeatedTexts(accepted, r.skipped)
	}
	return v.assemble(r, accepted, matches, base)
}

// keepRepeatedTexts undoes a replacement where it would uncover a byte. Main reports one finding per
// number on a line, and redaction's completeness sweep masks the other occurrences of its text. A
// finding replaced by a wider reading no longer has its text reported, so an occurrence of that text
// elsewhere on the line that no reported span covers would be left in cleartext ("+1 297 201 0052
// or 297 201 0052"). Such a finding is reported as well as the reading that contains it; the
// redactor writes the two as one overlap group.
//
// The occurrences considered are the line's pattern matches and the skipped repeat readings, which
// is every place main's own dedup could have set a repeat aside. Each costs a binary search over the
// reported spans, so a dense line stays linear.
func (r *lineResolver) keepRepeatedTexts(accepted []acceptedReading, skipped []rawCand) {
	replaced := map[string]bool{}
	for i := range r.found {
		if r.found[i].replacedBy >= 0 {
			replaced[r.ms[i].Text] = true
		}
	}
	if len(replaced) == 0 {
		return
	}
	// What the redactor will cover: every reported span, and every other occurrence (a pattern match
	// or a skipped repeat) of a text that stays reported, which the completeness sweep masks.
	type span struct{ s, e int }
	spans := make([]span, 0, len(r.found)+len(accepted)+len(skipped))
	final := make(map[string]bool, len(r.found)+len(accepted))
	for i := range r.found {
		if r.found[i].replacedBy < 0 {
			spans = append(spans, span{r.found[i].start, r.found[i].end})
			final[r.ms[i].Text] = true
		}
	}
	for i := range accepted {
		spans = append(spans, span{accepted[i].start, accepted[i].end})
		final[accepted[i].m.Text] = true
	}
	line := r.line
	for _, set := range [][]rawCand{skipped, r.raw} {
		for _, c := range set {
			if final[line[c.start:c.end]] {
				spans = append(spans, span{c.start, c.end})
			}
		}
	}
	sort.Slice(spans, func(a, b int) bool { return spans[a].s < spans[b].s })
	maxEnd := make([]int, len(spans))
	m := -1
	for i, sp := range spans {
		if sp.e > m {
			m = sp.e
		}
		maxEnd[i] = m
	}
	covered := func(s, e int) bool {
		k := sort.Search(len(spans), func(i int) bool { return spans[i].s > s })
		return k > 0 && maxEnd[k-1] >= e
	}
	uncovered := map[string]bool{}
	check := func(c rawCand) {
		text := line[c.start:c.end]
		if replaced[text] && !uncovered[text] && !covered(c.start, c.end) {
			uncovered[text] = true
		}
	}
	for _, c := range r.raw {
		check(c)
	}
	for _, c := range skipped {
		check(c)
	}
	if len(uncovered) == 0 {
		return
	}
	for i := range r.found {
		if f := &r.found[i]; f.replacedBy >= 0 && uncovered[r.ms[i].Text] {
			f.replacedBy = -1
		}
	}
}

// mayHoldWideReading is a cheap test for a line on which no grammar reading or bracketed national
// form can start: no '+', no '(' and no "00".
func mayHoldWideReading(line string) bool {
	return strings.ContainsAny(line, "+(") || strings.Contains(line, "00")
}

// scanWideReadings adds the grammar readings and the national bracketed forms of the line to r.wide,
// skipping any that is exactly one of main's findings or cuts across one.
func (v *Validator) scanWideReadings(line string, r *lineResolver) {
	n := len(line)
	add := func(w wideCand) {
		contained, partial := r.overlap(w.start, w.end)
		if partial || r.sameSpan(contained, w.start, w.end) {
			return
		}
		if len(contained) == 0 && r.alreadyReported(line[w.start:w.end]) {
			// A repeat of a text main reports on the line: not evaluated, and not sorted.
			r.skipped = append(r.skipped, rawCand{start: w.start, end: w.end, pattern: -1})
			return
		}
		w.contained = contained
		r.wide = append(r.wide, w)
	}
	for i := 0; i < n; i++ {
		switch c := line[i]; {
		case c == '+' && i+1 < n && isDigitByte(line[i+1]):
			b := classifyBoundary(line, i)
			if b == boundaryRefuse {
				continue
			}
			if end, num, ok := scanIntl(line, i); ok {
				add(wideCand{start: i, end: end, pattern: -1, priority: len(v.patterns), bound: b, num: num, intl: true})
			}
		case c == '(' && i+2 < n && line[i+1] == '+' && isDigitByte(line[i+2]):
			b := classifyBoundary(line, i)
			if b == boundaryRefuse {
				continue
			}
			if end, num, ok := scanIntl(line, i); ok {
				add(wideCand{start: i, end: end, pattern: -1, priority: len(v.patterns), bound: b, num: num, intl: true})
			}
		case c == '(' && i+1 < n && isDigitByte(line[i+1]):
			b := classifyBoundary(line, i)
			if b == boundaryRefuse {
				continue
			}
			window := line[i:min(i+parenWindow, n)]
			try := func(re *regexp.Regexp, pattern int) {
				if loc := re.FindStringIndex(window); loc != nil {
					add(wideCand{start: i, end: i + loc[1], pattern: pattern, priority: pattern, bound: b})
				}
			}
			if b != boundaryLegacy {
				// The "("-led NANP patterns see only the legacy boundaries; these are the others.
				try(reUSParenAt, patternUSStandard)
				try(reUSParenExtAt, patternUSWithExtension)
				try(reUSTollFreeParenAt, patternUSTollFreeParentheses)
			}
			if line[i+1] == '0' {
				try(reUKParenAt, patternUKStandard)
			}
		case c == '0' && i+2 < n && line[i+1] == '0' && isDigitByte(line[i+2]):
			// The "00" form: International_00 is \b-led, so main already reads it after any
			// non-word byte; the grammar reads it after the boundaries a phone number is written
			// after, and its wider reading replaces a truncated one of main's.
			if i > 0 {
				if b := classifyBoundary(line, i); b == boundaryRefuse {
					continue
				}
			}
			if end, num, ok := scanIntl(line, i); ok {
				add(wideCand{start: i, end: end, pattern: -1, priority: len(v.patterns), bound: boundaryLegacy, num: num, intl: true})
			}
			i++ // the second '0' cannot start another "00" reading of the same number
		}
	}
}

// evaluateWide runs main's per-match pipeline on a wide reading, with the gate, the boundary rule
// and the no-truncation rule in front of it. A reading that replaces findings scores at least what
// the best of them scored and counts their corroboration as its own: widening a span is a
// correction of where the number ends, not new doubt about whether it is one.
func (v *Validator) evaluateWide(ls *lineScoring, r *lineResolver, w *wideCand, originalPath string) (acceptedReading, bool) {
	line := ls.line
	if w.bound == boundaryRefuse || truncatedAt(line, w.start, w.end) {
		return acceptedReading{}, false
	}
	text := line[w.start:w.end]
	var pattern phonePattern
	o := &scoreOpts{}
	if w.pattern >= 0 {
		pattern = v.patterns[w.pattern]
		if !pattern.lengthAllowed(text) {
			return acceptedReading{}, false
		}
		// Scored with the pattern that read it. Main scores its own findings with the first pattern
		// whose regex matches anywhere in the text, which for "+39 310 101 1057" is US_Dashed on the
		// tail, and a NANP length check on an Italian number; that is kept for main's findings, whose
		// scores this change does not move, and not repeated for a reading that replaces them.
		o.pattern = &pattern
	} else {
		pattern = intlGrammarPattern
		o.pattern = &intlGrammarPattern
	}
	if v.isEmbeddedInIdentifierAt(text, line, w.start) {
		return acceptedReading{}, false
	}
	if len(w.contained) == 0 {
		// A new reading glued to a letter ("...0958stored") is an identifier's digits or a typo, and
		// is not reported; one that replaces main's head of the same number is reported whole. A
		// trailing ':' is a key in a log line or a table ("005F:00660066 0060:..."), as main's
		// isEmbeddedInIdentifierAt reads it; and a reading the structural check refuses, which main
		// would report at 5 only to keep its reported set, is not a new finding at all.
		if w.end < len(line) {
			if c := line[w.end]; isWordByteASCII(c) || c >= 0x80 || c == ':' || c == '-' {
				return acceptedReading{}, false
			}
		}
		if w.pattern < 0 && (decimalShaped(text) || w.num.glued) {
			// "+9252.619193895" is a signed decimal and "+1130 2010" a time zone offset and a year:
			// neither is how a grouped international number is written.
			return acceptedReading{}, false
		}
		if !v.hasPhoneStructureAt(text, line, w.start) {
			return acceptedReading{}, false
		}
	}
	if w.intl {
		if w.num.verdict == gatePass {
			o.country = countryLabelForCode(w.num.code)
			if w.num.code == "1" && !nanpPossibleText(text) {
				// As for main's NANP patterns: a number the plan cannot assign is not labelled US/CA.
				o.country = "Unknown"
			}
		} else {
			// A reading the gate refuses is never a new finding.
			if len(w.contained) == 0 {
				return acceptedReading{}, false
			}
			o.cap, o.gateFailed = e164GateCeiling, true
			o.country = countryLabelForCode(w.num.code)
		}
	}
	if w.bound == boundaryUnlabelled {
		o.cap, o.labelUnrecognised = e164GateCeiling, true
	}
	// A reading capped at LOW never displaces a finding above LOW. It may replace findings that are
	// LOW already when it covers digits they leave out, so the whole number is masked rather than its
	// head ("+55 11 91010-10509" for main's "+55 11 91010"), and then scores no higher than they did:
	// it is there for the redactor, not as new evidence. A "+" in front of main's "0001101" covers no
	// digit, so it replaces nothing.
	if o.cap > 0 && len(w.contained) > 0 {
		best := 0.0
		for _, i := range w.contained {
			if c := r.ms[i].Confidence; c > o.cap {
				return acceptedReading{}, false
			} else if c > best {
				best = c
			}
		}
		if !coversMoreDigits(line, w, r) {
			return acceptedReading{}, false
		}
		o.cap = best
	}
	for _, i := range w.contained {
		if c := r.ms[i].Confidence; c > o.floor {
			o.floor = c
		}
		if r.found[i].corroborated {
			o.floorCorroborated = true
		}
	}
	m, _, ok := v.scoreMatch(ls, text, w.start, pattern, v.cleanPhoneNumber(text), originalPath, o)
	return acceptedReading{m: m, start: w.start, end: w.end}, ok
}

// coversMoreDigits reports whether the reading's span holds a digit none of the findings it contains
// covers.
func coversMoreDigits(line string, w *wideCand, r *lineResolver) bool {
	for p := w.start; p < w.end; p++ {
		if !isDigitByte(line[p]) {
			continue
		}
		inside := false
		for _, i := range w.contained {
			if f := &r.found[i]; p >= f.start && p < f.end {
				inside = true
				break
			}
		}
		if !inside {
			return true
		}
	}
	return false
}

// assemble rewrites the line's segment of matches in main's order: a finding replaced by a wider
// reading gives its place to that reading, and readings that replaced nothing follow, leftmost first.
func (v *Validator) assemble(r *lineResolver, accepted []acceptedReading, matches []detector.Match, base int) []detector.Match {
	if len(accepted) == 0 {
		return matches
	}
	out := make([]detector.Match, 0, len(r.found)+len(accepted))
	placed := make([]bool, len(accepted))
	for i := range r.found {
		f := &r.found[i]
		if f.replacedBy < 0 {
			out = append(out, r.ms[i])
			continue
		}
		if !placed[f.replacedBy] {
			placed[f.replacedBy] = true
			out = append(out, accepted[f.replacedBy].m)
		}
	}
	for i := range accepted {
		if !placed[i] {
			out = append(out, accepted[i].m)
		}
	}
	return append(matches[:base], out...)
}

// capAtGate lowers a finding the gate refuses to e164GateCeiling and publishes the ceiling, so the
// document bridge's adjustments cannot lift it again.
func capAtGate(m *detector.Match) {
	if m.Confidence > e164GateCeiling {
		m.Confidence = e164GateCeiling
	}
	if c, ok := m.Metadata[confidenceCeilingKey].(float64); !ok || c > e164GateCeiling {
		m.Metadata[confidenceCeilingKey] = e164GateCeiling
	}
	if checks, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		checks["valid_country"] = false
	}
}
