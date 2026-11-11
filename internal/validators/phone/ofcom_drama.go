// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "strings"

// ofcomDramaPrefixes are the first seven digits of the UK national significant number (the number
// after the trunk "0" or the "+44") of the three Ofcom ranges reserved for TV and radio drama that
// #930 measured at HIGH 100, each a block of 1,000 numbers that Ofcom does not allocate
// (https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama):
//
//	020 7946 0000 .. 020 7946 0999   London
//	01632 960000  .. 01632 960999    no area: Ofcom's choice for any area code it does not list
//	07700 900000  .. 07700 900999    mobile
//
// Ofcom publishes a block for several other area codes too (0113, 0114, 0115, 0116, 0117, 0118,
// 0121, 0131, 0141, 0151, 0161, 0191, 028, 029 and the non-geographic ranges). They are the same
// class and are not listed here: the score corpus holds "0161 496 0000" (Manchester's block) as a
// real UK number that must stay HIGH (tp__real_uk_numbers_survive_the_length_bound), so widening
// the list needs that corpus case changed first.
var ofcomDramaPrefixes = []string{"2079460", "1632960", "7700900"}

// mayBeReservedFictional is the cheap pre-filter in front of isReservedFictionalNumber: true when
// cleanNew (cleanPhoneNumber of the match) can hold a reserved number at all. The digits that
// function tests are a substring of cleanNew (it strips only a trailing extension and a prefix), so
// a number it accepts always has "55501" or one of ofcomDramaPrefixes in cleanNew.
func mayBeReservedFictional(cleanNew string) bool {
	if strings.Contains(cleanNew, "55501") {
		return true
	}
	for _, p := range ofcomDramaPrefixes {
		if strings.Contains(cleanNew, p) {
			return true
		}
	}
	return false
}

// isReservedFictionalDigits reports whether a cleaned number (cleanPhoneNumber, its extension
// removed) is in a reserved fictional range: NANP's 555-0100..0199 (reFictional555), or one of
// Ofcom's drama ranges.
func isReservedFictionalDigits(clean string) bool {
	return reFictional555.MatchString(strings.TrimPrefix(clean, "00")) || isOfcomDramaNumber(clean)
}

// isOfcomDramaNumber reports whether a cleaned number is in one of ofcomDramaPrefixes' ranges,
// written nationally ("020 7946 0958", "07700900123") or internationally ("+44 20 7946 0958",
// "0044 20 7946 0958", "+44 (0)20 7946 0958", whose "(0)" cleans to a trunk 0 after the code).
func isOfcomDramaNumber(clean string) bool {
	var nsn string
	intl := false
	switch {
	case strings.HasPrefix(clean, "+44"):
		nsn, intl = clean[3:], true
	case strings.HasPrefix(clean, "0044"):
		nsn, intl = clean[4:], true
	case strings.HasPrefix(clean, "0") && !strings.HasPrefix(clean, "00"):
		nsn = clean[1:]
	default:
		return false
	}
	if intl && len(nsn) == 11 && nsn[0] == '0' {
		nsn = nsn[1:] // the "(0)" of "+44 (0)20 7946 0958"
	}
	if len(nsn) != 10 {
		return false
	}
	for _, p := range ofcomDramaPrefixes {
		if strings.HasPrefix(nsn, p) {
			return true
		}
	}
	return false
}
