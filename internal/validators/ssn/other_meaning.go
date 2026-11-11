// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// A nine-digit value whose own context says what else it is (#939). Measured on main @ 2fb4719,
// each repository file scanned whole (--config /dev/null --confidence all --checks SSN,PASSPORT),
// with <9 digits> standing for the value:
//
//	quotas-and-limits.md    a pipe-table row ending "(max: <9 digits> bytes)"           SSN 95 HIGH
//	COVERAGE_DISCLOSURE.md  "would exceed the <9 digits>-byte total embedded ..."       SSN 70
//	passport/help.go        "UK passport: 9 digits (e.g., <9 digits>)",                 SSN 95 HIGH
//	passport/validator.go   a comment holding "Field: Passport Number" above
//	                        "Value: <9 digits>"                                         SSN 95 HIGH
//
// Every one is the bare form with a valid area number (base 70) on a line isTabularData accepts (a
// pipe table, two commas, a tab), and a tabular line is boosted and never capped. Neither a unit nor
// another type's label was read.

// otherMeaningCeiling holds a value whose surroundings say it is something else: a byte count, or
// a passport number. It is contradictingHeaderCap, the number this validator already gives a value
// whose column header names another identifier ("passport_number" among them, through
// headerNamesAnotherIdentifier), so a passport label is judged the same whether it sits above the
// column or beside the value. Inside LOW, it leaves `--confidence high,medium` and stops failing a
// HIGH-gated hook, while the value is still REPORTED and therefore still redacted.
const otherMeaningCeiling = contradictingHeaderCap

// byteWordUnits are matched case-insensitively ("bytes", "Bytes"); byteSymbolUnits exactly, because
// a lower-case "b" is a bit in the unit conventions that use it ("Mb").
var (
	byteWordUnits   = []string{"bytes", "byte"}
	byteSymbolUnits = []string{"KiB", "MiB", "GiB", "TiB", "kB", "KB", "MB", "GB", "TB", "B"}
)

// isByteQuantityAt reports whether the candidate ending at line[end] is directly followed by a unit
// of bytes, with at most one space or hyphen between: "<9 digits> bytes", "<9 digits>-byte",
// "<9 digits> B", "<9 digits> KiB". The unit must end at a word boundary, so a following "Baker" or
// "bytecode" is not a unit.
//
// The unit is the bytes right after the value, which an author cannot move without rewriting the
// value's own sentence, so the caller publishes the ceiling whenever this holds: the bridge's
// document-level adjustment must not lift a byte count back, whatever it scored here.
//
// It reads a fixed number of bytes after the candidate, so the per-candidate cost is constant on a
// line of any length.
func isByteQuantityAt(line string, end int) bool {
	rest := line[end:]
	if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '-') {
		rest = rest[1:]
	}
	unitEnds := func(n int) bool {
		return len(rest) == n || !isASCIIAlnum(rest[n])
	}
	for _, u := range byteWordUnits {
		if len(rest) >= len(u) && strings.EqualFold(rest[:len(u)], u) && unitEnds(len(u)) {
			return true
		}
	}
	for _, u := range byteSymbolUnits {
		if strings.HasPrefix(rest, u) && unitEnds(len(u)) {
			return true
		}
	}
	return false
}

// isBareNineDigits reports whether match is the separator-less form. The hyphenated and spaced forms
// are how an SSN is written down, so the quantity rule leaves them alone.
func isBareNineDigits(match string) bool {
	if len(match) != 9 {
		return false
	}
	for i := 0; i < len(match); i++ {
		if match[i] < '0' || match[i] > '9' {
			return false
		}
	}
	return true
}

// passportLabels name a value as a passport number.
var passportLabels = []string{"passport", "passport number", "passport no", "travel document"}

// namesAPassport reports whether line i's values are labelled as passport numbers: a passport label
// on the line, or a bare field label naming a passport on the line above. A two-line form writes
// the label there:
//
//	Field: Passport Number
//	Value: <9 digits>
//
// and the passport validator already reads that layout (its lineContext.labelAbove) with
// kwmatch.LooksLikeFieldLabel, the shape test that keeps prose mentioning a passport out. Before
// this the value was reported as PASSPORT 100 and, through the tab, as SSN 95 at the same time.
//
// The caller caps only when no SSN keyword is on the value's line: "SSN <9 digits>, passport ..."
// keeps its score, the inline form of headerSupports outranking a contradicting header.
//
// Unlike the byte unit, a label can sit anywhere on its line, so the ceiling is published only
// when it lowered the value. Publishing it on eligibility as well would mark values already below
// it; measured, that adds confidence_ceiling to the SSN finding on line 3 of the golden case
// overlap_groups_render_once ("Passport number: <9 digits>", SSN 50 LOW) and takes the SSN row of
// the metadata-key census from 11 keys to 12. A passport-labelled value below the ceiling is
// therefore left where main leaves it, including what the bridge adds to it.
func namesAPassport(line string, i int, lines []string) bool {
	for _, kw := range passportLabels {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return i > 0 && kwmatch.LooksLikeFieldLabel(lines[i-1], passportLabels)
}
