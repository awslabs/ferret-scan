// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "strings"

// arcepFictionRoots are the first five digits of the French national significant number (the nine
// digits after the trunk "0" or the "+33") of the six blocks of 10,000 numbers that ARCEP reserves for
// audiovisual works, #1026. The source is the "Numéros pour œuvres audiovisuelles" section of ARCEP's
// "Plan national de numérotation" (the annex to decision n° 2018-0881 of 24 July 2018, in the version
// of 1 January 2026, page 54 of 67: https://www.arcep.fr/uploads/tx_gsavis/18-0881.pdf, read
// 2026-11-19). It gives the roots in national format (0ZABPQ), a block each of ten thousand numbers
// (0ZABPQ 0000 .. 9999):
//
//	01 99 00 00 00 .. 01 99 00 99 99   geographic, Île-de-France
//	02 61 91 00 00 .. 02 61 91 99 99   geographic, North-west
//	03 53 01 00 00 .. 03 53 01 99 99   geographic, North-east
//	04 65 71 00 00 .. 04 65 71 99 99   geographic, South-east
//	05 36 49 00 00 .. 05 36 49 99 99   geographic, South-west
//	06 39 98 00 00 .. 06 39 98 99 99   mobile
//
// The plan states that ARCEP never allocates them, that they cannot call or be called, and that they
// "may be used as telephone numbers in fictions that need them". The regions are Wikipedia's reading
// of each root, not the plan's, so they are not repeated in code.
var arcepFictionRoots = []string{"19900", "26191", "35301", "46571", "53649", "63998"}

// isArcepFictionNumber reports whether a cleaned number (cleanPhoneNumber, its extension removed) is in
// one of arcepFictionRoots' blocks, written nationally ("0199004718") or internationally
// ("+33 1 99 00 47 18", "0033 1 99 00 47 18", "+33 (0)1 99 00 47 18", whose "(0)" cleans to a trunk
// 0 after the code).
func isArcepFictionNumber(clean string) bool {
	var nsn string
	intl := false
	switch {
	case strings.HasPrefix(clean, "+33"):
		nsn, intl = clean[3:], true
	case strings.HasPrefix(clean, "0033"):
		nsn, intl = clean[4:], true
	case strings.HasPrefix(clean, "0") && !strings.HasPrefix(clean, "00"):
		nsn = clean[1:]
	default:
		return false
	}
	if intl && len(nsn) == 10 && nsn[0] == '0' {
		nsn = nsn[1:] // the "(0)" of "+33 (0)1 99 00 47 18"
	}
	if len(nsn) != 9 {
		return false
	}
	for _, r := range arcepFictionRoots {
		if strings.HasPrefix(nsn, r) {
			return true
		}
	}
	return false
}
