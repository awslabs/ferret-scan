// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import "strings"

// Non-US licence shapes (#861, enhancement half).
//
// Candidates came only from the US state shapes, and emit dropped what classifyMatch could not name
// after a state, so two common non-US forms gave no finding of any type under any label. Measured on
// main @ b0a9163 with "Driving licence number:" as the label:
//
//	WOMBA901010ZZ9AA (Great Britain, 12 display variants)   no finding in 12 of 12
//	W1234-12345-12345 (Ontario, as printed)                  no finding
//	W1234-123456-12  (Quebec, as printed)                    no finding
//
// while the same Ontario and Quebec numbers written without hyphens scored 95 under a US format name
// (NJ_1L14D, FL_MI_1L12D), because their contiguous shapes ARE those states' shapes. Each shape below
// is one more alternative of the composite reAnyDL, so a line is still scanned once.
//
// Scope is deliberate. These are the shapes with a fixed, distinctive layout; the jurisdictions
// whose numbers are bare 7-, 10- or 12-digit runs, or short letter/digit mixes, are left out because
// on 43,367 public text files an "every jurisdiction" set added 216 findings, all inspected ones
// false positives (#861). docs/validators-new.md lists what is out and why.
const (
	// formatGBDVLA is a Great Britain (DVLA) driver number.
	formatGBDVLA = "GB_DVLA"
	// formatOntario is an Ontario licence printed with hyphens; contiguous it is NJ_1L14D's shape.
	formatOntario = "CA_ON"
	// formatQuebec is a Quebec licence printed with hyphens; contiguous it is FL_MI_1L12D's shape.
	formatQuebec = "CA_QC"
)

// The reAnyDL alternatives for these shapes. Kept here so the layout and its gate read together.
const (
	// GB driver number, 16 characters, or 18 with the two-digit issue number written straight after
	// it. Written with a space before the issue number ("... ZZ9AA 01") the 16 characters match and
	// the issue number stays outside the span.
	reGBDVLAAlt = `[A-Za-z9]{5}\d{6}[A-Za-z9]{2}\d[A-Za-z0-9]{2}(?:\d{2})?`
	// The same 16 characters printed in the card's 5/6/5 groups.
	reGBDVLASpacedAlt = `[A-Za-z9]{5} \d{6} [A-Za-z9]{2}\d[A-Za-z0-9]{2}`
	// Ontario as printed: letter, 4, 5 and 5 digits.
	reOntarioAlt = `[A-Za-z]\d{4}-\d{5}-\d{5}`
	// Quebec as printed: letter, 4, 6 and 2 digits.
	reQuebecAlt = `[A-Za-z]\d{4}-\d{6}-\d{2}`
)

// classifyContiguous names a reAnyDL match: one of the non-US shapes if the match has that layout and
// passes its gate, else the US state format. normalized is the separator-free form used for scoring
// and reported as metadata["normalized"] when it differs from the span. format "" drops the match.
//
// The non-US shapes are told apart from the US ones by layout alone: every US shape is 8 to 15
// contiguous characters, so a 16- or 18-character run or a span with an inner space or hyphen can
// only have come from one of the alternatives above.
func (v *Validator) classifyContiguous(line string, start, end int) (format, normalized string) {
	text := line[start:end]
	switch {
	case len(text) == 16 || (len(text) == 18 && !strings.ContainsRune(text, ' ')):
		if validGBDriverNumber(text[:16]) {
			return formatGBDVLA, text
		}
		return "", ""
	case len(text) == 18 && text[5] == ' ' && text[12] == ' ':
		number := text[:5] + text[6:12] + text[13:]
		if validGBDriverNumber(number) {
			return formatGBDVLA, number
		}
		return "", ""
	case len(text) == 17 && text[5] == '-' && text[11] == '-':
		if joinedByHyphen(line, start, end) {
			return "", ""
		}
		return formatOntario, stripHyphens(text)
	case len(text) == 15 && text[5] == '-' && text[12] == '-':
		if joinedByHyphen(line, start, end) {
			return "", ""
		}
		return formatQuebec, stripHyphens(text)
	}
	return v.classifyMatch(text), text
}

// validGBDriverNumber is the structural gate for the 16-character GB driver number. The layout
// (DVLA; see "Driving licence in the United Kingdom", Driver number):
//
//	1-5    first five letters of the surname, padded with 9s
//	6      decade digit of the birth year
//	7-8    birth month, plus 50 for women: 01-12 or 51-62
//	9-10   birth day, 01-31
//	11     year digit of the birth year
//	12-13  initials, a 9 standing for a missing one ("99" when the name is not split)
//	14     arbitrary digit, usually 9
//	15-16  check characters, digits or letters
//
// No check-character algorithm is published, so the gate is the layout itself, and it is what keeps
// the shape from matching random alphanumerics: the number encodes surname, birth date and sex, and
// it is only reported on a line that already carries licence vocabulary (lineHasPositiveKeyword). The
// regex has already pinned digits and letters to their positions; this checks what it cannot.
func validGBDriverNumber(s string) bool {
	if len(s) != 16 {
		return false
	}
	// Surname: one to five letters, then only padding.
	i := 0
	for i < 5 && isASCIILetter(s[i]) {
		i++
	}
	if i == 0 {
		return false
	}
	for ; i < 5; i++ {
		if s[i] != '9' {
			return false
		}
	}
	month := int(s[6]-'0')*10 + int(s[7]-'0')
	if !(month >= 1 && month <= 12 || month >= 51 && month <= 62) {
		return false
	}
	if day := int(s[8]-'0')*10 + int(s[9]-'0'); day < 1 || day > 31 {
		return false
	}
	// Initials: a letter then a letter or the 9 for a missing middle name, or 99.
	a, b := s[11], s[12]
	return isASCIILetter(a) && (isASCIILetter(b) || b == '9') || a == '9' && b == '9'
}

// joinedByHyphen reports whether the span [start,end) is one segment of a longer hyphenated token:
// "W1234-12345-12345-0001" is not an Ontario licence followed by "-0001", it is some other
// identifier that happens to begin with the same groups.
func joinedByHyphen(line string, start, end int) bool {
	if start >= 2 && line[start-1] == '-' && isASCIIAlnum(line[start-2]) {
		return true
	}
	return end+1 < len(line) && line[end] == '-' && isASCIIAlnum(line[end+1])
}

func stripHyphens(s string) string { return strings.ReplaceAll(s, "-", "") }

func isASCIILetter(b byte) bool { return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' }

func isASCIIAlnum(b byte) bool { return isASCIILetter(b) || b >= '0' && b <= '9' }
