// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import "strings"

// ofcomDramaPrefixes are the first seven digits of the UK national significant number (the number
// after the trunk "0" or the "+44") of the ranges Ofcom reserves for TV and radio drama, each a block
// of 1,000 numbers that Ofcom does not allocate. The source is Ofcom's "Telephone numbers for use in
// TV and radio drama programmes" (https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama,
// published 1 March 2019, last updated 11 May 2023). The page answers 403 to a script, so it was read
// through the Internet Archive's copy of 2024-12-23
// (https://web.archive.org/web/20241223042545/https://www.ofcom.org.uk/phones-and-broadband/phone-numbers/numbers-for-drama);
// https://en.wikipedia.org/wiki/Fictitious_telephone_number reproduces the same table. The first four
// blocks are #930's, the other sixteen are #1019's:
//
//	020 7946 0000 .. 020 7946 0999   London
//	01632 960000  .. 01632 960999    no area: Ofcom's choice for any area code it does not list
//	07700 900000  .. 07700 900999    mobile
//	0161 496 0000 .. 0161 496 0999   Manchester (#930: "Phone: 0161 496 0815" read PHONE 100)
//	0113, 0114, 0115, 0116, 0117, 0118, 0121, 0131, 0141, 0151 496 0000 .. 496 0999
//	                                 Leeds, Sheffield, Nottingham, Leicester, Bristol, Reading,
//	                                 Birmingham, Edinburgh, Glasgow, Liverpool
//	0191 498 0000 .. 0191 498 0999   Tyneside/Durham/Sunderland
//	028 9649 6000 .. 028 9649 6999   Northern Ireland (Ofcom's page; #1019's table said 9018 0xxx, which
//	                                 Wikipedia lists but Ofcom's page no longer does, so it is not held)
//	029 2018 0000 .. 029 2018 0999   Cardiff
//	0808 157 0000 .. 0808 157 0999   freephone (Ofcom writes 08081 570000 .. 570999)
//	0909 879 0000 .. 0909 879 0999   premium rate (Ofcom writes 0909 8790000 .. 8790999)
//	0306 999 0000 .. 0306 999 0999   UK-wide (Ofcom writes 03069 990000 .. 990999)
//
// Every block is a seven-digit prefix of a ten-digit number, so the 1,000 numbers of a block are the
// three digits after it. The goldencorpus holds none of them; the scorecorpus holds none either
// (checked for #1019).
var ofcomDramaPrefixes = []string{
	"2079460", "1632960", "7700900", "1614960",
	"1134960", "1144960", "1154960", "1164960", "1174960", "1184960",
	"1214960", "1314960", "1414960", "1514960",
	"1914980", "2896496", "2920180", "8081570", "9098790", "3069990",
}

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
