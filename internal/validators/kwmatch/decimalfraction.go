// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

// IsDecimalFractionTail reports whether the match starting at matchIndex is the fractional tail of a
// decimal number rather than a standalone value.
//
// A digit, then '.', immediately before the match means the digits that follow the decimal point have
// been taken as an identifier. Measured at main @ 0610b7e, before the guard existed:
//
//	35.008 31.354                                ->  PHONE HIGH 100  (matched "008 31.354")
//	M0.5,1 C0.304262935,18 0.125262935,18.115    ->  2 x SSN HIGH 100
//	0.1234567893                                  ->  MEDICAL_ID NPI LOW 40
//
// In the first two, a real labelled value of the same type scored LOWER than the fraction — PHONE 15
// and SSN 50 respectively — so the false positive outranked the true positive.
//
// LIVES HERE, NOT IN EACH VALIDATOR, and that is the point.
//
// PHONE and SSN were fixed separately, by hand, weeks apart, with two implementations of the same
// eight lines; MEDICAL_ID was only found afterwards by testing the class rather than waiting to trip
// over it. Three instances of one predicate is where a shared home stops being premature.
//
// It is deliberately a narrow SYNTACTIC predicate, not a policy: it answers "are these digits the
// tail of a decimal number" and nothing else. A broader "is this a standalone value" contract applied
// across all validators was measured and rejected — the punctuation around a match contributes
// nothing to the current scores, and a general predicate would have turned real findings into
// cleartext. Callers still decide what to DO with the answer.
//
// LOOKS BEHIND THE MATCH. An earlier proposal looked ahead, treating a trailing period as a decimal
// point, and deleted a labelled SSN at the end of a sentence ("Employee SSN: 130-07-5728." reported
// nothing). It was refuted for that. A sentence-terminal period is AFTER the value; a decimal point is
// BEFORE it, so the two are not variants of one idea — one of them cannot reach a real finding.
//
// matchIndex is a byte offset into line. An index under 2 cannot have "digit dot" before it.
func IsDecimalFractionTail(line string, matchIndex int) bool {
	if matchIndex < 2 || matchIndex > len(line) {
		return false
	}
	if line[matchIndex-1] != '.' {
		return false
	}
	d := line[matchIndex-2]
	return d >= '0' && d <= '9'
}
