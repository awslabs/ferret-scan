// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "strings"

// A Unix timestamp in seconds is a 10-digit number, and every one from 2001-09-09
// (1000000000) to 2065 (2999999999) starts with 1 or 2, so roughly one in ten passes
// the CMS NPI-Luhn check by chance: 1751328000 (2025-07-01T00:00:00Z) is one of them.
// The check digit cannot tell the two apart, and no other validator claims a
// timestamp, so what the number IS has to be read from the two places a document
// says it: the label written in front of the value and the unit written after it
// (#806).
//
// Both are SLOTS bound to the value, not words anywhere on the line. A line-wide
// "timestamp"/"epoch" keyword was rejected: "Provider NPI 1234567893 record created
// 2025-07-01T00:00:00Z" is a real NPI on a line that talks about time, and the TM-11
// padding test already uses "timestamp unix epoch" as attacker padding that must not
// erase a labelled NPI. A trailing-"00" rule was rejected too: it is a statement
// about the digits, and about one NPI-valid number in a hundred ends in 00.

const (
	// epochSecondsMin and epochSecondsMax bound the Unix-seconds reading of a
	// candidate: 2001-09-09T01:46:40Z to 2033-05-18T03:33:20Z. Every 1-led NPI
	// candidate falls inside; no 2-led one does (2000000000 itself fails the CMS
	// check), so the NPI path is unchanged for every 2-led value.
	epochSecondsMin = 1_000_000_000
	epochSecondsMax = 2_000_000_000

	// The label and unit scans are bounded so the per-match cost stays constant on a
	// dense line, which the complexity guard measures. A run longer than these is
	// not a label or a unit, and the value is left to the existing scoring.
	maxLabelSeparatorBytes = 8
	maxLabelTokenBytes     = 64
	maxUnitLetters         = 16
)

// timeLabelWords name a point in time in the label slot whether they are written as
// a bare word ("ran at 1751328000", "epoch 1751328000") or as a key
// ("ts=1751328000", "created_at": 1751328000). "at" is the head of the created_at /
// updated_at convention and the preposition of "ran at"; iat, nbf and exp are the
// JWT time claims.
var timeLabelWords = map[string]bool{
	"at": true, "ts": true, "tstamp": true, "timestamp": true, "time": true,
	"datetime": true, "date": true, "epoch": true, "epochtime": true, "unix": true,
	"unixtime": true, "iat": true, "nbf": true, "exp": true,
}

// timeFieldWords name a time only when written as a field name: on the left of '=',
// quoted, or joined into a compound key ("last_updated", "epoch_s", "ts_ms"). In
// prose they are something else: "NPI updated: 1234567893" announces a new NPI, and
// the "s" of "the provider's 1234567893" is a possessive.
var timeFieldWords = map[string]bool{
	"created": true, "updated": true, "modified": true, "expires": true, "expiry": true,
	"s": true, "sec": true, "secs": true, "seconds": true,
	"ms": true, "msec": true, "msecs": true, "millis": true, "milliseconds": true,
}

// timeUnitWords, written right after the number, make it a count of time:
// "1751328000 epoch seconds", "1761609639 ms", "1751328000 (unix)". An attached
// suffix ("1751328000s") never reaches here: reNPI needs a word boundary after the
// tenth digit.
var timeUnitWords = map[string]bool{
	"s": true, "sec": true, "secs": true, "seconds": true,
	"ms": true, "msec": true, "msecs": true, "millis": true, "milliseconds": true,
	"epoch": true, "unix": true,
}

// labelFillerWords say nothing about what the value is: "NPI number", "NPI No." and
// "npi_id" all name the NPI, so the head of the label is the word before them.
var labelFillerWords = map[string]bool{
	"number": true, "no": true, "num": true, "nbr": true, "nr": true, "id": true,
}

// writtenAsUnixSeconds reports whether the NPI candidate line[start:end] is written
// as a Unix timestamp in seconds: inside the 2001-2033 window, with a time word in
// its label slot or a time unit in its unit slot, and NOT labelled as an NPI.
//
// The NPI label wins every tie, so "NPI: 1751328000", "npi=1751328000" and
// "NPI 1234567893 seconds" keep today's score and the TM-11 floor. What this drops
// is a value whose own label or unit says it is a time and nothing says it is an
// NPI. That is a statement about what the number is, the same kind of structural
// disambiguation as the phone drop in evaluateNPI, and bound to the value's own
// slots rather than to a word anywhere on the line.
//
// KNOWN RESIDUAL (TM-11): whoever writes the document can erase an UNLABELLED NPI by
// putting a time word in its label slot or a unit after it ("Provider 1234567893
// seconds"). The phone drop already lets one phone word anywhere on the line do the
// same, so this adds no capability an author lacks today, and a labelled NPI is out
// of its reach.
func writtenAsUnixSeconds(line string, start, end int) bool {
	if !inEpochSecondsWindow(line[start:end]) {
		return false
	}

	lbl := labelBefore(line, start)
	segs := labelSegments(lbl.key)
	head := labelHead(segs)
	keyForm := lbl.assign || lbl.quoted || len(segs) > 1
	prevHead := ""
	if !lbl.assign {
		// Prose and "Label: value" can spread the label over two words ("Provider
		// NPI", "NPI updated"). After '=' the key binds alone: in
		// "npi_sync ts=1751328000" the word before ts is a different field.
		prevHead = labelHead(labelSegments(lbl.prev))
	}
	if head == "" {
		// No label, or only filler ("NPI number 1234567893"): the word before names it.
		head, prevHead, keyForm = prevHead, "", false
	}

	if head == "npi" || prevHead == "npi" {
		return false
	}
	if timeLabelWords[head] || (keyForm && timeFieldWords[head]) {
		return true
	}
	return timeUnitWords[unitAfter(line, end)]
}

// inEpochSecondsWindow reports whether a 10-digit run reads as Unix seconds between
// epochSecondsMin and epochSecondsMax.
func inEpochSecondsWindow(digits string) bool {
	if len(digits) != 10 {
		return false
	}
	n := 0
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= epochSecondsMin && n <= epochSecondsMax
}

// valueLabel is the label slot in front of a value.
type valueLabel struct {
	key    string // the token written immediately before the value
	prev   string // the token before key, when only whitespace separates them
	assign bool   // an '=' sits between key and value
	quoted bool   // key is a quoted field name ("ts": ...)
}

// labelBefore reads the label slot that ends at start: up to maxLabelSeparatorBytes
// of separators (whitespace, quotes, ':', '=', '#', brackets, '.', '-'), then the
// token before them. A comma, semicolon or pipe ends the slot, so in a CSV row the
// previous cell's value is not read as this value's label.
func labelBefore(line string, start int) valueLabel {
	var lbl valueLabel
	i, n := start, 0
	for i > 0 && n < maxLabelSeparatorBytes && isLabelSeparator(line[i-1]) {
		if line[i-1] == '=' {
			lbl.assign = true
		}
		i--
		n++
	}
	if i > 0 && isLabelSeparator(line[i-1]) {
		return valueLabel{} // separator run too long to bind a label to this value
	}
	keyEnd := i
	if keyEnd < start && isQuote(line[keyEnd]) {
		lbl.quoted = true
	}
	keyStart, ok := tokenBefore(line, keyEnd)
	if !ok || keyStart == keyEnd {
		return valueLabel{}
	}
	lbl.key = line[keyStart:keyEnd]

	j, w := keyStart, 0
	for j > 0 && w < maxLabelSeparatorBytes && (line[j-1] == ' ' || line[j-1] == '\t') {
		j--
		w++
	}
	if w > 0 {
		if prevStart, ok := tokenBefore(line, j); ok {
			lbl.prev = line[prevStart:j]
		}
	}
	return lbl
}

// tokenBefore returns the start of the label token ending at end, or ok=false when
// the run is longer than maxLabelTokenBytes (a run that long is not a label).
func tokenBefore(line string, end int) (int, bool) {
	i := end
	for i > 0 && end-i < maxLabelTokenBytes && isLabelTokenByte(line[i-1]) {
		i--
	}
	if i > 0 && end-i == maxLabelTokenBytes && isLabelTokenByte(line[i-1]) {
		return end, false
	}
	return i, true
}

// labelSegments splits a label token into lowercase words on '_', '-', '.' and
// camelCase boundaries: "createdAt" -> created, at; "NPINumber" -> npi, number.
func labelSegments(tok string) []string {
	var segs []string
	from := 0
	flush := func(to int) {
		if to > from {
			segs = append(segs, strings.ToLower(tok[from:to]))
		}
	}
	for j := 0; j < len(tok); j++ {
		c := tok[j]
		if c == '_' || c == '-' || c == '.' {
			flush(j)
			from = j + 1
			continue
		}
		if j > from && isUpperASCII(c) {
			p := tok[j-1]
			nextLower := j+1 < len(tok) && isLowerASCII(tok[j+1])
			if isLowerASCII(p) || (p >= '0' && p <= '9') || (isUpperASCII(p) && nextLower) {
				flush(j)
				from = j
			}
		}
	}
	flush(len(tok))
	return segs
}

// labelHead is the last segment that is not filler: what the label says the value
// is. "" when every segment is filler or there are none.
func labelHead(segs []string) string {
	for k := len(segs) - 1; k >= 0; k-- {
		if !labelFillerWords[segs[k]] {
			return segs[k]
		}
	}
	return ""
}

// unitAfter returns the lowercase word written right after the value, skipping up to
// maxLabelSeparatorBytes of spaces, tabs and opening brackets, or "" when the next
// thing is not a whole word of letters.
func unitAfter(line string, end int) string {
	i, n := end, 0
	for i < len(line) && n < maxLabelSeparatorBytes &&
		(line[i] == ' ' || line[i] == '\t' || line[i] == '(' || line[i] == '[') {
		i++
		n++
	}
	j := i
	for j < len(line) && j-i < maxUnitLetters && isLetterASCII(line[j]) {
		j++
	}
	if j == i || (j < len(line) && isLabelWordByte(line[j])) {
		return ""
	}
	return strings.ToLower(line[i:j])
}

func isLabelSeparator(c byte) bool {
	switch c {
	case ' ', '\t', '"', '\'', '`', ':', '=', '#', '(', ')', '[', ']', '{', '<', '>', '.', '-':
		return true
	}
	return false
}

func isLabelTokenByte(c byte) bool {
	return isLabelWordByte(c) || c == '.' || c == '-'
}

func isLabelWordByte(c byte) bool {
	return isLetterASCII(c) || (c >= '0' && c <= '9') || c == '_'
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

func isLetterASCII(c byte) bool { return isLowerASCII(c) || isUpperASCII(c) }

func isLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }

func isUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }
