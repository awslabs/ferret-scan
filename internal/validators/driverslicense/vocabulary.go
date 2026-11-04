// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// The licence-label vocabulary, generated from its parts (#861).
//
// Three lists decide how strongly a line labels a driver's licence, and each used to be written out
// by hand:
//
//   - positiveKeywords ADMIT a line (lineHasPositiveKeyword), are counted for the keyword arm of
//     AnalyzeContext, and locate the label for the positional test/placeholder rule.
//   - prefixLabels earn the label boost when they occupy the label position (labelledFieldPrefix).
//   - labelLiterals earn the same boost wherever they appear on the line (AnalyzeContext).
//
// The three had drifted apart. positiveKeywords carried 9 of the 24 {driver, drivers, driver's,
// driving} x {license, licence} x {"", number, no} spellings, the literal list lacked "licence no."
// and prefixLabels lacked "driving licence"/"driving license". Because kwmatch matches a keyword's
// concatenation only as a WHOLE word, a camelCase key is found only when one keyword concatenates to
// exactly that key (#438). Measured on main @ b0a9163, one line per file, `<label>: D1234567`:
//
//	drivingLicence, DrivingLicenceNo, driversLicence, driverLicence, ...   no finding (10 of 10)
//	drivingLicenseNumber, driversLicense, driverLicense (their US twins)    95
//	Driving licence:, Driving license:, driving_licence:                    75
//	Licence No. D1234567                                                     65, against 95 for License No.
//
// A licence that is not reported is never handed to the redactor, so each of the first row stayed in
// cleartext under --enable-redaction. Generating every list from the same parts makes that drift
// impossible: a spelling is either in all three or in none.
var (
	// licenceHolders is who or what the licence is for. The apostrophe spelling stays: kwmatch treats
	// an apostrophe as a word boundary, so "driver's license" also finds "driver'slicense".
	licenceHolders = []string{"driver's", "drivers", "driver", "driving"}

	// licenceNouns are the US and British spellings. Both are always generated together: a British
	// spelling missing from one list is exactly the defect this file exists to prevent.
	licenceNouns = []string{"license", "licence"}
)

// holderForms returns every "<holder> <noun><suffix>" spelling, holder-major.
func holderForms(suffix string) []string {
	out := make([]string, 0, len(licenceHolders)*len(licenceNouns))
	for _, h := range licenceHolders {
		for _, n := range licenceNouns {
			out = append(out, h+" "+n+suffix)
		}
	}
	return out
}

// nounForms returns the holder-less field labels "<noun><suffix>": "license number", "licence no".
func nounForms(suffix string) []string {
	out := make([]string, 0, len(licenceNouns))
	for _, n := range licenceNouns {
		out = append(out, n+suffix)
	}
	return out
}

// licenceLabelForms are the 24 {holder} {noun}{suffix} spellings every list below is built from.
func licenceLabelForms() []string {
	forms := holderForms("")
	forms = append(forms, holderForms(" number")...)
	return append(forms, holderForms(" no")...)
}

// contextKeywords are the positive keywords that are NOT spellings of a licence label: single words
// and other phrases that make a line about driving or ID. They admit a line and count toward the
// keyword arm; they never earn the label boost on their own (bare "license" could be software,
// fishing or gun licence, so it is deliberately absent from prefixLabels and labelLiterals).
var contextKeywords = []string{
	"driver", "license", "licence", "dl", "dmv",
	"motor vehicle", "driving", "permit", "state id",
	"identification card", "operator",
}

// buildPositiveKeywords returns contextKeywords plus every generated label spelling.
//
// The ORDER is chosen, not incidental. Context.PositiveKeywords lists the matched keywords in this
// order and SARIF reports it, so every keyword that existed before #861 keeps its relative position:
// the two-word spellings, then "dl number" and the holder-less field labels, then the suffixed
// spellings. A line that matched only pre-#861 keywords therefore reports the same list as before.
//
// Why the three-word forms are needed at all, rather than being redundant with the two-word ones:
// "drivers license" finds `driversLicense`, but appending "Number" makes the word
// `driverslicensenumber`, which no two-word keyword reaches (#438). The " no" forms exist for the
// same reason: `DrivingLicenceNo` is one word.
func buildPositiveKeywords() []string {
	kw := append([]string{}, contextKeywords...)
	kw = append(kw, holderForms("")...)
	kw = append(kw, "dl number")
	kw = append(kw, nounForms(" number")...)
	kw = append(kw, holderForms(" number")...)
	return append(kw, holderForms(" no")...)
}

// buildPrefixLabels returns the labels that, standing in the LABEL POSITION of a field, identify the
// value beside them as a driver's licence number: every generated spelling, the holder-less field
// labels and the abbreviation. Order does not matter here; labelledFieldPrefix asks only whether any
// of them is present.
func buildPrefixLabels() []string {
	labels := licenceLabelForms()
	labels = append(labels, nounForms(" number")...)
	labels = append(labels, nounForms(" no")...)
	return append(labels, "dl number", "dl")
}

// buildLabelLiterals returns the substrings that earn the label boost wherever they appear on a
// lowercased line, which is what labelledFieldPrefix cannot do: a label after another field
// ("Name: A. Wombat, driving licence: D1234567") and the separator-less "Licence No. D1234567",
// where the abbreviation's own full stop ends the label.
//
// Only the two-word spellings and the holder-less field labels are listed. Every suffixed spelling
// ends in a holder-less one ("driving licence no:" ends in "licence no:"), so listing them would only
// repeat a substring search that has already matched.
func buildLabelLiterals() []string {
	lits := []string{"dl:", "dl #", "dl#", "d.l."}
	for _, f := range holderForms("") {
		lits = append(lits, f+":")
	}
	for _, f := range nounForms(" number") {
		lits = append(lits, f+":")
	}
	for _, f := range nounForms(" no") {
		lits = append(lits, f+":", f+".")
	}
	return lits
}

var (
	prefixLabels  = buildPrefixLabels()
	labelLiterals = buildLabelLiterals()
)

// drivPrefix is the prefix shared by every holder spelling and by the "driver"/"driving" keywords.
// A keyword that starts with it can only match a line that contains it, so a line without it skips
// those keywords — 26 of the 38 — without changing any result. That is what keeps the per-line gate,
// which runs on every line of every file, no slower than before the vocabulary grew.
const drivPrefix = "driv"

// containsLabelKeywordLower is containsLabel for a lowercased line and a lowercased keyword, with the
// drivPrefix skip. hasDriv is strings.Contains(lower, drivPrefix), computed once per line by the
// caller.
func containsLabelKeywordLower(lower, kw string, hasDriv bool) bool {
	if !hasDriv && strings.HasPrefix(kw, drivPrefix) {
		return false
	}
	return kwmatch.ContainsLabelLower(lower, kw)
}

// hasLabelLiteral reports whether a lowercased line contains any labelLiteral.
func hasLabelLiteral(lower string) bool {
	for _, lit := range labelLiterals {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}
