// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	stdctx "context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// UK health service numbers (#859): the NHS number of England, Wales and the Isle of Man (Northern
// Ireland's Health and Care number shares the format) and Scotland's Community Health Index (CHI)
// number. Both are 10 digits whose last digit is a mod-11 check digit over the first nine; a CHI
// number additionally starts with a DDMMYY date, normally the date of birth.
//
// Before this, no type owned them. A labelled NHS number was reported only as a US/CA PHONE, so
// format-preserving redaction kept its last four digits; a spaced CHI (`150100 0004`) and several
// JSON spellings got no finding at all and passed --enable-redaction in cleartext.
//
// THE CHECK DIGIT IS NOT ENOUGH ON ITS OWN, so every finding here needs a label BOUND to the value
// (ukHealthBinding). Measured on 200,000 random 10-digit strings the check passes 9.09%, and it
// passes every numeric ISBN-10 (20,000 of 20,000), whose check digit is the same mod-11 sum. A bare
// "nhs" or "chi" never admits: "NHS 111" heads a helpline line, and in Go's own sources "chi" is the
// ClientHelloInfo variable of crypto/tls.
//
// These findings are additive. PHONE, MRN and NPI findings on the same bytes are left exactly as
// they were: no NHS or CHI label lowers or removes them (#684, #672).

// The two type names, returned by one helper so the source-harvesting type guard
// (core.TestEverySourceEmittableTypeIsKnown) sees both.
const (
	ukHealthNHS ukHealthKind = iota + 1
	ukHealthCHI
)

// ukHealthKind is which scheme a label names.
type ukHealthKind int

func (k ukHealthKind) typeName() string {
	if k == ukHealthCHI {
		return "CHI_NUMBER"
	}
	return "NHS_NUMBER"
}

// reUKHealthCandidate is every printed form: 10 unbroken digits, the NHS 3-3-4 grouping, or the
// CHI 6-4 grouping (date, then serial and check digit), with a space or a hyphen. Which grouping a
// kind may take, and that a 3-3-4 value uses ONE separator, is checked after the match: RE2 has no
// backreference.
var reUKHealthCandidate = regexp.MustCompile(`\b(?:\d{10}|\d{3}[ -]\d{3}[ -]\d{4}|\d{6}[ -]\d{4})\b`)

// nhsLabels and chiLabels are the labels that BIND a value: matched as words, the way
// kwmatch.ContainsLabel matches, so "nhs_number", "nhs-number" and the camelCase "nhsNumber" are the
// same label as "NHS number". "H&C" is Northern Ireland's Health and Care number.
var (
	nhsLabels = []string{"nhs number", "nhs no", "h&c number", "health and care number"}
	chiLabels = []string{"chi number", "chi no", "community health index", "community health index number"}
)

// nhsFHIRSystem is the FHIR identifier system for an NHS number. A value under it is an NHS number
// whatever its key is called, and the key is "value".
const nhsFHIRSystem = "https://fhir.nhs.uk/Id/nhs-number"

// hl7NHSAuthority follows an NHS number in an HL7 v2 PID-3 component: ID^check^scheme^authority^type.
const hl7NHSAuthority = "^^^NHS^NH"

// ukHealthLookBehind bounds how far before a value the inline label is looked for, so the per-value
// cost does not grow with the line (the single-long-line shape dos_test.go guards).
const ukHealthLookBehind = 64

// ukHealthCeiling is the CONFIDENCE_CONTRACT §7c T2 ceiling, published in confidence_ceiling.
const ukHealthCeiling = 15.0

// ukHealthFailedBase is the score of a bound value whose check digit or CHI date fails: LOW, and
// never dropped, because the label still says what the number is.
const ukHealthFailedBase = 40.0

// ukHealthValidBase is the score of a bound value whose check digit (and CHI date) holds: HIGH.
const ukHealthValidBase = 90.0

// ukHealthLine is what a line's candidates share, computed once per line so the per-candidate cost
// stays independent of the line's length.
type ukHealthLine struct {
	prevKind    ukHealthKind     // a bare field label on the line above
	fhirNear    bool             // the NHS FHIR identifier system on this line or the line above
	headerAbove *delimitedHeader // the line above is a delimited header naming a scheme in some cell
}

// delimitedHeader maps a candidate on this line to the cell of the line above it.
//
// It covers what internal/tabular deliberately does not: a two-column export. tabular needs three
// fields, because two is often prose ("Smith, John"), so `surname,nhs_number` above
// `Alpha,9991112227` is not a table to it and the value had no binding. Only the line directly
// above is read, so this binds the first data row of such a file; a three-column table is bound on
// every row by the column-header arm instead.
type delimitedHeader struct {
	seps  []int          // offsets of the delimiter in this line
	kinds []ukHealthKind // the scheme each cell of the line above names, or 0
}

func (h *delimitedHeader) kindAt(off int) ukHealthKind {
	if h == nil {
		return 0
	}
	if idx := sort.SearchInts(h.seps, off); idx < len(h.kinds) {
		return h.kinds[idx]
	}
	return 0
}

// newDelimitedHeader returns the header map for line when prevLine has the same number of one
// delimiter and at least one of its cells names a scheme, else nil.
func newDelimitedHeader(prevLine, line string) *delimitedHeader {
	for _, d := range []byte{',', '\t', ';', '|'} {
		n := strings.Count(line, string(d))
		if n == 0 || strings.Count(prevLine, string(d)) != n {
			continue
		}
		cells := strings.Split(prevLine, string(d))
		kinds := make([]ukHealthKind, len(cells))
		named := false
		for i, c := range cells {
			if c = strings.TrimSpace(c); c != "" && !strings.ContainsAny(c, "0123456789") {
				kinds[i] = labelKindIn(c)
				named = named || kinds[i] != 0
			}
		}
		if !named {
			continue
		}
		seps := make([]int, 0, n)
		for i := 0; i < len(line); i++ {
			if line[i] == d {
				seps = append(seps, i)
			}
		}
		return &delimitedHeader{seps: seps, kinds: kinds}
	}
	return nil
}

// scanUKHealthNumbers reports NHS and CHI numbers on one line. It is the whole of #859's hook into
// scanLine and reads only what scanLine already has.
func (v *Validator) scanUKHealthNumbers(ctx stdctx.Context, line, prevLine string, lc medicalLineContext, lineNum int, originalPath string) []detector.Match {
	var ul ukHealthLine
	if prevLine != "" && mayCarryUKHealthLabel(prevLine) {
		ul.prevKind = ukHealthLabelLine(prevLine)
		ul.headerAbove = newDelimitedHeader(prevLine, line)
	}
	ul.fhirNear = strings.Contains(line, nhsFHIRSystem) || strings.Contains(prevLine, nhsFHIRSystem)

	// Cheap admission, so ordinary lines never run the regex: a value can be bound only by a label
	// on this line, a label line or header line above, the FHIR system, or a column header.
	if ul.prevKind == 0 && ul.headerAbove == nil && !ul.fhirNear && lc.bounds == nil && !mayCarryUKHealthLabel(line) {
		return nil
	}

	var out []detector.Match
	for i, loc := range reUKHealthCandidate.FindAllStringIndex(line, -1) {
		if execguard.LineLoopCancelled(ctx, i) {
			return out
		}
		if kwmatch.IsDecimalFractionTail(line, loc[0]) {
			continue
		}
		if m, ok := v.evaluateUKHealthNumber(line, lc, &ul, loc[0], loc[1], lineNum, originalPath); ok {
			out = append(out, m)
		}
	}
	return out
}

// evaluateUKHealthNumber decides one candidate at line[start:end].
func (v *Validator) evaluateUKHealthNumber(line string, lc medicalLineContext, ul *ukHealthLine, start, end, lineNum int, originalPath string) (detector.Match, bool) {
	match := line[start:end]
	kind, binding := v.ukHealthBinding(line, lc, ul, start, end)
	if kind == 0 {
		return detector.Match{}, false
	}
	digits, ok := ukHealthShape(line, match, start, end, kind)
	if !ok {
		return detector.Match{}, false
	}

	checksum := ukHealthCheckDigitValid(digits)
	dateOK := kind != ukHealthCHI || chiDateValid(digits)
	repdigit := strings.Count(digits, digits[:1]) == len(digits)
	testRange := kind == ukHealthNHS && strings.HasPrefix(digits, "999")

	contextImpact := lc.lineImpact
	var confidence float64
	if checksum && dateOK {
		confidence = clamp(ukHealthValidBase + contextImpact)
		// The check digit is a value-intrinsic proof, so context may demote but not erase (TM-11,
		// as evaluateNPI and evaluateDEA do).
		if confidence <= 0 {
			confidence = intrinsicValueFloor
		}
	} else {
		// A failed check digit or date leaves the bound label as the only evidence, so positive
		// words do not raise it; negative ones may take it to the floor, not below.
		confidence = ukHealthFailedBase
		if contextImpact < 0 {
			confidence += contextImpact
		}
		if confidence < intrinsicValueFloor {
			confidence = intrinsicValueFloor
		}
	}

	metadata := map[string]any{
		"subtype":        kind.typeName(),
		"checksum_valid": checksum,
		"context_impact": contextImpact,
		"label_binding":  binding,
	}
	if digits != match {
		metadata["normalized"] = digits
	}
	// NHS England never issues 999 000 0000 to 999 999 9999, and every repdigit passes the check
	// digit. Both are fixtures, which still need redacting, so they are capped, not dropped: §7c T2.
	if (testRange || repdigit) && confidence > ukHealthCeiling {
		confidence = ukHealthCeiling
	}
	if testRange || repdigit {
		metadata["confidence_ceiling"] = ukHealthCeiling
	}

	// Only the checks this function actually made (#537).
	checks := map[string]bool{"not_repdigit": !repdigit, "not_test_data": !lc.testData}
	if kind == ukHealthCHI {
		checks["chi_checksum"] = checksum
		checks["chi_date"] = dateOK
		checks["chi_label"] = true
	} else {
		checks["nhs_checksum"] = checksum
		checks["nhs_label"] = true
		checks["not_reserved_test_range"] = !testRange
	}
	metadata["validation_checks"] = checks

	return detector.Match{
		Text:       match,
		LineNumber: lineNum + 1,
		Type:       kind.typeName(),
		Confidence: confidence,
		Filename:   originalPath,
		Validator:  "medicalid",
		Context:    v.buildContext(match, line, start, lc.posKW, lc.negKW),
		Metadata:   metadata,
	}, true
}

// ukHealthBinding reports which scheme's label is bound to the value at line[start:end], and how.
// Every binding is positive-only and names the value it binds; none is a line-wide keyword.
func (v *Validator) ukHealthBinding(line string, lc medicalLineContext, ul *ukHealthLine, start, end int) (ukHealthKind, string) {
	lo := start - ukHealthLookBehind
	if lo < 0 {
		lo = 0
	}
	tail := trimLabelTail(asciiLower(line[lo:start]))

	// 1. A label or key immediately before the value: "NHS number: ", `"nhsNumber": "`,
	//    `<chiNumber>`, "nhs_number=".
	if k := labelKindAtEnd(tail); k != 0 {
		return k, "label"
	}
	// 2. HL7 v2: the NHS assigning authority right after the value.
	if strings.HasPrefix(line[end:], hl7NHSAuthority) {
		return ukHealthNHS, "hl7_assigning_authority"
	}
	// 3. FHIR: the "value" of an identifier whose system is the NHS number, on this line or the
	//    line above (a pretty-printed identifier object).
	if ul.fhirNear && endsWithWords(tail, "value") {
		return ukHealthNHS, "fhir_system"
	}
	// 4. The header of this value's own column, in a table internal/tabular recognises, or the
	//    header line directly above in a two-column export it does not.
	if h := lc.columnHeaderAt(start); h != "" {
		if k := labelKindIn(h); k != 0 {
			return k, "column_header"
		}
	}
	if k := ul.headerAbove.kindAt(start); k != 0 {
		return k, "column_header"
	}
	// 5. A bare field label on the line above.
	if ul.prevKind != 0 {
		return ul.prevKind, "label_above"
	}
	return 0, ""
}

// ukHealthShape validates the candidate's printed form for its kind and returns its 10 digits.
func ukHealthShape(line, match string, start, end int, kind ukHealthKind) (string, bool) {
	switch len(match) {
	case 10:
	case 12: // 3-3-4, the NHS grouping, with one separator throughout
		if kind != ukHealthNHS || match[3] != match[7] {
			return "", false
		}
	case 11: // 6-4, the CHI grouping
		if kind != ukHealthCHI {
			return "", false
		}
	default:
		return "", false
	}
	// A grouped value must not be one group of a longer grouped number.
	if len(match) != 10 {
		if start >= 2 && isGroupSep(line[start-1]) && isASCIIDigit(line[start-2]) {
			return "", false
		}
		if end+1 < len(line) && isGroupSep(line[end]) && isASCIIDigit(line[end+1]) {
			return "", false
		}
	}
	// A value after an international prefix is a phone number: 9.1% of UK numbers after +44 pass
	// the check digit.
	if afterCountryCode(line[:start]) {
		return "", false
	}
	digits := strings.NewReplacer(" ", "", "-", "").Replace(match)
	return digits, len(digits) == 10
}

// ukHealthCheckDigitValid applies the NHS / CHI mod-11 check: weights 10 down to 2 over the first
// nine digits; the check digit is 11 minus the sum mod 11, where 11 means 0 and 10 means the number
// is never issued.
func ukHealthCheckDigitValid(d string) bool {
	if len(d) != 10 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (10 - i)
	}
	c := 11 - sum%11
	if c == 11 {
		c = 0
	}
	return c != 10 && int(d[9]-'0') == c
}

// chiDateValid reports whether a CHI number starts with a real DDMMYY date in 19YY or 20YY. The
// first six digits are normally, not always, the date of birth, which is why a failure scores LOW
// rather than dropping the value.
func chiDateValid(d string) bool {
	dd := int(d[0]-'0')*10 + int(d[1]-'0')
	mm := int(d[2]-'0')*10 + int(d[3]-'0')
	yy := int(d[4]-'0')*10 + int(d[5]-'0')
	if dd < 1 || mm < 1 || mm > 12 {
		return false
	}
	for _, century := range []int{1900, 2000} {
		t := time.Date(century+yy, time.Month(mm), dd, 0, 0, 0, 0, time.UTC)
		if t.Day() == dd && int(t.Month()) == mm {
			return true
		}
	}
	return false
}

// ukHealthLabelLine reports which scheme a bare field-label line names ("NHS number",
// "Patient CHI number:"), or 0. Prose that mentions a label does not qualify: the line must be all
// label vocabulary, kwmatch.LooksLikeFieldLabel's test.
func ukHealthLabelLine(prevLine string) ukHealthKind {
	if prevLine == "" || !mayCarryUKHealthLabel(prevLine) {
		return 0
	}
	if !kwmatch.LooksLikeFieldLabel(prevLine, ukHealthLabelVocabulary) {
		return 0
	}
	return labelKindIn(prevLine)
}

// ukHealthLabelVocabulary is the label-line vocabulary: the labels, plus "patient", which commonly
// heads one ("Patient NHS number"). "patient" alone binds nothing: labelKindIn still has to find a
// label.
var ukHealthLabelVocabulary = append(append([]string{"patient"}, nhsLabels...), chiLabels...)

// labelKindAtEnd reports which scheme's label tail ENDS with, so the label is the last thing before
// the value. NHS is tried first; the two label sets share no spelling.
func labelKindAtEnd(tail string) ukHealthKind {
	for _, l := range nhsLabels {
		if endsWithWords(tail, l) {
			return ukHealthNHS
		}
	}
	for _, l := range chiLabels {
		if endsWithWords(tail, l) {
			return ukHealthCHI
		}
	}
	return 0
}

// labelKindIn reports which scheme's label appears anywhere in s (a column header or a label line).
func labelKindIn(s string) ukHealthKind {
	s = asciiLower(s)
	if kwmatch.ContainsAnyLabel(s, nhsLabels) {
		return ukHealthNHS
	}
	if kwmatch.ContainsAnyLabel(s, chiLabels) {
		return ukHealthCHI
	}
	return 0
}

// endsWithWords reports whether s ends with label's words, matched as kwmatch.ContainsLabel matches
// them: consecutive words may be joined by a run of separator bytes (space, tab, '_', '-') or by
// nothing, and the first word starts at a word boundary. s and label are lowercase.
func endsWithWords(s, label string) bool {
	words := strings.Fields(label)
	i := len(s)
	for w := len(words) - 1; w >= 0; w-- {
		if w < len(words)-1 {
			for i > 0 && isLabelSep(s[i-1]) {
				i--
			}
		}
		word := words[w]
		if i < len(word) || s[i-len(word):i] != word {
			return false
		}
		i -= len(word)
	}
	return i == 0 || !isLowerAlnum(s[i-1])
}

// trimLabelTail drops the punctuation that sits between a label or key and its value: whitespace,
// ':', '=', '#', quotes, '>', '(', '[', ',' and '.'.
func trimLabelTail(s string) string {
	return strings.TrimRight(s, " \t:=#\"'>([,.")
}

// mayCarryUKHealthLabel is a cheap, allocation-free prefilter for the label words: one pass looking
// for "nhs", "chi", "h&c" or "hea" (health), in any case. It may say yes too often ("machine" holds
// "chi"); it must never say no to a line that holds a label.
func mayCarryUKHealthLabel(line string) bool {
	for i := 0; i+3 <= len(line); i++ {
		a, b, c := lowerASCIIByte(line[i]), lowerASCIIByte(line[i+1]), lowerASCIIByte(line[i+2])
		switch {
		case a == 'n' && b == 'h' && c == 's',
			a == 'c' && b == 'h' && c == 'i',
			a == 'h' && b == '&' && c == 'c',
			a == 'h' && b == 'e' && c == 'a':
			return true
		}
	}
	return false
}

func lowerASCIIByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// afterCountryCode reports whether before ends with an international prefix, "+44" or "0044",
// optionally followed by one space, hyphen or closing parenthesis.
func afterCountryCode(before string) bool {
	b := strings.TrimRight(before, " -)")
	n := 0
	for n < len(b) && n < 4 && isASCIIDigit(b[len(b)-1-n]) {
		n++
	}
	if n == 0 {
		return false
	}
	rest := b[:len(b)-n]
	if strings.HasSuffix(rest, "+") || strings.HasSuffix(rest, "(+") {
		return n <= 3
	}
	// "00" + a 1-3 digit country code, written as one run: 0044, 00353.
	run := b[len(b)-n:]
	if (rest == "" || !isASCIIDigit(rest[len(rest)-1])) && n >= 3 && strings.HasPrefix(run, "00") {
		return true
	}
	return false
}

// asciiLower lowercases ASCII letters only, so byte offsets are preserved. strings.ToLower does not
// preserve them for every rune (U+212A KELVIN SIGN becomes the 1-byte 'k'), and the offsets here
// come from the original line.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

func isLabelSep(b byte) bool { return b == ' ' || b == '\t' || b == '_' || b == '-' }

func isGroupSep(b byte) bool { return b == ' ' || b == '-' }

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func isLowerAlnum(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') }
