// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

// ITIN: the IRS Individual Taxpayer Identification Number (#884).
//
// An ITIN is written exactly like an SSN, 9XX-XX-XXXX, and the IRS issues it from the area numbers
// the SSA never uses for an SSN. IRS Publication 4757 (https://www.irs.gov/pub/irs-pdf/p4757.pdf)
// states the format: nine digits, beginning with a 9, with the 4th and 5th digits in 50-65, 70-88,
// 90-92 or 94-99. Group 93 is the Adoption Taxpayer Identification Number (ATIN), which is out of
// scope here.
//
// Before this, isValidSSN rejected every area of 900 or above without reading the group, and
// couldBeSSN carried a copy of the same rule, so every ITIN was discarded as an invalid SSN. Measured
// on main @ 769be4e, --config /dev/null --confidence all: "ITIN: 912-70-3456", "ITIN: 912703456",
// "SSN: 912-70-3456" and "Taxpayer ID: 912-70-3456" each reported nothing, and 60 seeded ITINs gave
// 0/60 in each of the three display forms. A finding that is never reported is never redacted, so
// every one of them stayed in cleartext under --enable-redaction.
//
// isValidSSN still rejects all of 900-999: an ITIN is not an SSN, and it is reported under its own
// type, ITIN, from this validator, enabled by --checks SSN, as the credit-card validator reports
// VISA. It is scored on the SSN curve with the 9xx area treated as valid for an ITIN, so it inherits
// the SSN's keywords, negatives, header caps and test-value drops.

// isITINGroup reports whether the 4th and 5th digits fall in a range the IRS issues ITINs from.
func isITINGroup(group int) bool {
	return (group >= 50 && group <= 65) ||
		(group >= 70 && group <= 88) ||
		(group >= 90 && group <= 92) ||
		(group >= 94 && group <= 99)
}

// isITIN reports whether a nine-digit string is an ITIN.
//
// This is the ONE predicate both candidate paths call: the regex path in ValidateContentCtx and the
// glued-run path in couldBeSSN. Before #884 each path carried its own copy of the area veto, which is
// how a single rule came to be enforced in two places.
//
// It is a value predicate only. Whether a candidate is in a FORM that may be reported as an ITIN is
// decided separately by itinFormAdmits, because the bare nine-digit form needs a label and that is a
// property of the line, not of the digits.
//
// Two values are withheld outright, each a value that identifies nobody (CONFIDENCE_CONTRACT §7c,
// T1):
//
//   - 987-65-4320 through 987-65-4329, the block the SSA reserves for advertising. Its group, 65, is an
//     ITIN group, so before this the advertising block was "safe" only because the area veto rejected
//     it: lifting the veto for ITINs reported "SSN: 987-65-4325" at 90. It is now an explicit drop
//     rather than a side effect of a rule about something else.
//   - the repdigit 999-99-9999, the 9xx placeholder; isTestSSN already lists it for the SSN path.
//
// A serial of 0000 is rejected as it is for an SSN. The SSN's pattern checks (sequential digits,
// repeated digits, the common patterns) are NOT vetoes here: on the SSN path they cost confidence and
// leave the value reported, and a real ITIN such as 912-70-1000 must not be dropped where the same
// shape under an SSN area is reported. See calculateConfidence.
func isITIN(digits string) bool {
	if len(digits) != 9 || digits[0] != '9' {
		return false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return false
		}
	}
	if !isITINGroup(int(digits[3]-'0')*10 + int(digits[4]-'0')) {
		return false
	}
	if digits[5:] == "0000" {
		return false
	}
	if isSSAAdvertisingNumber(digits) || isRepdigit(digits) {
		return false
	}
	return true
}

// isSSAAdvertisingNumber reports whether a nine-digit string is in 987-65-4320..4329, the block the
// SSA reserves for use in advertisements.
func isSSAAdvertisingNumber(digits string) bool {
	return len(digits) == 9 && digits[:8] == "98765432"
}

// isRepdigit reports whether every digit of a non-empty string is the same.
func isRepdigit(digits string) bool {
	if digits == "" {
		return false
	}
	for i := 1; i < len(digits); i++ {
		if digits[i] != digits[0] {
			return false
		}
	}
	return true
}

// itinLabels are the words that name an ITIN. They are the label the form gate reads: a bare
// nine-digit 9xx value, or one half of a glued 18-digit run, is reported as an ITIN only on a line
// (or under a column header) carrying one of them. Matched with containsKeyword, so whole words,
// case-insensitive, with '_' as a boundary ("customer_itin").
var itinLabels = []string{"itin", "individual taxpayer identification number"}

// itinKeywords are the positive keywords an ITIN candidate reads IN ADDITION to the SSN's own list,
// which already carries tax id, taxpayer id, irs, w2 and 1099. Form W-7 is the ITIN application.
//
// Kept apart from positiveKeywords on purpose: adding them there would also raise SSN findings on
// any line that mentions an ITIN or a W-7, and every finding main reports must keep its confidence.
var itinKeywords = []string{"itin", "individual taxpayer identification number", "w-7"}

// isSeparatedITINForm reports whether a candidate is written 9XX-XX-XXXX or 9XX XX XXXX, the same
// separator twice. Those are the forms an ITIN is printed in, so they need no label.
func isSeparatedITINForm(match string) bool {
	if len(match) != 11 {
		return false
	}
	sep := match[3]
	if (sep != '-' && sep != ' ') || match[6] != sep {
		return false
	}
	for i := 0; i < len(match); i++ {
		if i == 3 || i == 6 {
			continue
		}
		if match[i] < '0' || match[i] > '9' {
			return false
		}
	}
	return true
}

// hasITINLabel reports whether a line names an ITIN. The glued-run path asks this before a
// lineContext exists; itinLabelled answers the same question from the cache afterwards.
func hasITINLabel(line string) bool {
	for _, kw := range itinLabels {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return false
}

// itinLabelled reports whether this match's line, or the header of its column, names an ITIN.
func (v *Validator) itinLabelled(lc *lineContext) bool {
	for _, kw := range itinLabels {
		if lc.keywordOnLine[kw] {
			return true
		}
		if lc.columnHeader != "" && containsKeyword(lc.columnHeader, kw) {
			return true
		}
	}
	return false
}

// itinFormAdmits is the form gate: whether a candidate that isITIN accepts may be REPORTED as one.
//
// The separated forms always are; the bare nine-digit form only with an ITIN label on the line or in
// its column header. A glued half has no column, so it needs the label on the line.
//
// The gate is what keeps ITIN's precision at the SSN's. A nine-digit run beginning with 9 is ordinary
// in code and data, and a Chilean mobile is +56 9XXXXXXXX. Measured against main @ 769be4e with
// --checks SSN --confidence all, accepting every 9xx value with an ITIN group in any form (V1) against
// this gate (V3), every finding hand-checked:
//
//	                                              V1 added           V3 added
//	Go 1.27.3 tree (14,941 files)                 67 (55 ssa/opGen)  0
//	Go module cache (11,917 files)                3                  0
//	"Contacto: +56 9XXXXXXXX", 2 x 200 mobiles    85, 83             0
//
// Every V1 addition was a false positive. The issue measured the same shape on its corpora: 57 and 0
// on 306 MB of Go source, and 75-92 per 200 mobiles against 0.
func (v *Validator) itinFormAdmits(match string, lc *lineContext) bool {
	return isSeparatedITINForm(match) || v.itinLabelled(lc)
}
