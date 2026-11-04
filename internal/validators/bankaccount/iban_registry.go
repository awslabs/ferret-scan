// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

// ibanRegistry is the SWIFT IBAN Registry: the IBAN length and BBAN structure of every country
// with a registered national IBAN format. isValidIBAN and the display-form scan read only this
// table, so a country missing here is an IBAN never reported, and never redacted.
//
// GENERATED DATA, not hand-maintained. Regenerate it, and check it for drift, from the registry's
// TXT download (swift.com/standards/data-standards/iban-international-bank-account-number):
//
//	IBAN_REGISTRY_TXT=/path/to/iban-registry.txt UPDATE_IBAN_REGISTRY=1 \
//	    go test ./internal/validators/bankaccount/ -run TestIBANRegistryMatchesDownload
//
// Without UPDATE_IBAN_REGISTRY the same command fails on any added, removed or changed entry, and
// without IBAN_REGISTRY_TXT it skips. The download carries no release number, so what was read is
// recorded instead:
//
//	read 2026-11-04 from https://www.swift.com/swift-resource/11971/download
//	89 entries; newest "Last update date" in the download: Sep-26
//
// Only code, length and structure are copied. The registry's examples are kept for the tests in
// iban_registry_examples_test.go; its contact details are not copied at all.
//
// # Why generated
//
// The map this replaced was hand-written, labelled a "subset", and had no source or refresh path.
// It held 74 of the registry's 89 entries, so an IBAN from Egypt, Russia, Oman, Somalia or any of
// eleven other registered countries was never reported in any form (#862). Its 74 lengths were
// right; it was the missing rows nobody could see, because nothing compared it with the registry.
var ibanRegistry = map[string]ibanFormat{
	"AD": {length: 24, structure: "4!n4!n12!c"},
	"AE": {length: 23, structure: "3!n16!n"},
	"AL": {length: 28, structure: "8!n16!c"},
	"AT": {length: 20, structure: "5!n11!n"},
	"AZ": {length: 28, structure: "4!a20!c"},
	"BA": {length: 20, structure: "3!n3!n8!n2!n"},
	"BE": {length: 16, structure: "3!n7!n2!n"},
	"BG": {length: 22, structure: "4!a4!n2!n8!c"},
	"BH": {length: 22, structure: "4!a14!c"},
	"BI": {length: 27, structure: "5!n5!n11!n2!n"},
	"BR": {length: 29, structure: "8!c5!n10!n1!c1!c"},
	"BY": {length: 28, structure: "4!c4!n16!c"},
	"CH": {length: 21, structure: "5!n12!c"},
	"CR": {length: 22, structure: "4!n14!n"},
	"CY": {length: 28, structure: "3!n5!n16!c"},
	"CZ": {length: 24, structure: "4!n16!n"},
	"DE": {length: 22, structure: "8!n10!n"},
	"DJ": {length: 27, structure: "5!n5!n11!n2!n"},
	"DK": {length: 18, structure: "4!n9!n1!n"},
	"DO": {length: 28, structure: "4!c20!n"},
	"EE": {length: 20, structure: "2!n14!n"},
	"EG": {length: 29, structure: "4!n4!n17!n"},
	"ES": {length: 24, structure: "4!n4!n1!n1!n10!n"},
	"FI": {length: 18, structure: "3!n11!n"},
	"FK": {length: 18, structure: "2!a12!n"},
	"FO": {length: 18, structure: "4!n9!n1!n"},
	"FR": {length: 27, structure: "5!n5!n11!c2!n"},
	"GB": {length: 22, structure: "4!a6!n8!n"},
	"GE": {length: 22, structure: "2!a16!n"},
	"GI": {length: 23, structure: "4!a15!c"},
	"GL": {length: 18, structure: "4!n9!n1!n"},
	"GR": {length: 27, structure: "3!n4!n16!c"},
	"GT": {length: 28, structure: "4!c20!c"},
	"HN": {length: 28, structure: "4!a20!n"},
	"HR": {length: 21, structure: "7!n10!n"},
	"HU": {length: 28, structure: "3!n4!n1!n15!n1!n"},
	"IE": {length: 22, structure: "4!a6!n8!n"},
	"IL": {length: 23, structure: "3!n3!n13!n"},
	"IQ": {length: 23, structure: "4!a3!n12!n"},
	"IS": {length: 26, structure: "4!n2!n6!n10!n"},
	"IT": {length: 27, structure: "1!a5!n5!n12!c"},
	"JO": {length: 30, structure: "4!a4!n18!c"},
	"KW": {length: 30, structure: "4!a22!c"},
	"KZ": {length: 20, structure: "3!n13!c"},
	"LB": {length: 28, structure: "4!n20!c"},
	"LC": {length: 32, structure: "4!a24!c"},
	"LI": {length: 21, structure: "5!n12!c"},
	"LT": {length: 20, structure: "5!n11!n"},
	"LU": {length: 20, structure: "3!n13!c"},
	"LV": {length: 21, structure: "4!a13!c"},
	"LY": {length: 25, structure: "3!n3!n15!n"},
	"MC": {length: 27, structure: "5!n5!n11!c2!n"},
	"MD": {length: 24, structure: "2!c18!c"},
	"ME": {length: 22, structure: "3!n13!n2!n"},
	"MK": {length: 19, structure: "3!n10!c2!n"},
	"MN": {length: 20, structure: "4!n12!n"},
	"MR": {length: 27, structure: "5!n5!n11!n2!n"},
	"MT": {length: 31, structure: "4!a5!n18!c"},
	"MU": {length: 30, structure: "4!a2!n2!n12!n3!n3!a"},
	"NI": {length: 28, structure: "4!a20!n"},
	"NL": {length: 18, structure: "4!a10!n"},
	"NO": {length: 15, structure: "4!n6!n1!n"},
	"OM": {length: 23, structure: "3!n16!c"},
	"PK": {length: 24, structure: "4!a16!c"},
	"PL": {length: 28, structure: "8!n16!n"},
	"PS": {length: 29, structure: "4!a21!c"},
	"PT": {length: 25, structure: "4!n4!n11!n2!n"},
	"QA": {length: 29, structure: "4!a21!c"},
	"RO": {length: 24, structure: "4!a16!c"},
	"RS": {length: 22, structure: "3!n13!n2!n"},
	"RU": {length: 33, structure: "9!n5!n15!c"},
	"SA": {length: 24, structure: "2!n18!c"},
	"SC": {length: 31, structure: "4!a2!n2!n16!n3!a"},
	"SD": {length: 18, structure: "2!n12!n"},
	"SE": {length: 24, structure: "3!n16!n1!n"},
	"SI": {length: 19, structure: "5!n8!n2!n"},
	"SK": {length: 24, structure: "4!n6!n10!n"},
	"SM": {length: 27, structure: "1!a5!n5!n12!c"},
	"SO": {length: 23, structure: "4!n3!n12!n"},
	"ST": {length: 25, structure: "4!n4!n11!n2!n"},
	"SV": {length: 28, structure: "4!a20!n"},
	"TL": {length: 23, structure: "3!n14!n2!n"},
	"TN": {length: 24, structure: "2!n3!n13!n2!n"},
	"TR": {length: 26, structure: "5!n1!n16!c"},
	"UA": {length: 29, structure: "6!n19!c"},
	"VA": {length: 22, structure: "3!n15!n"},
	"VG": {length: 24, structure: "4!a16!n"},
	"XK": {length: 20, structure: "4!n10!n2!n"},
	"YE": {length: 30, structure: "4!a4!n18!c"},
}

// ibanRegistryEntries is the number of entries the generator wrote. TestIBANRegistryCompiles
// requires ibanRegistry to hold exactly this many, so a hand edit that adds or drops a country,
// instead of regenerating, fails.
const ibanRegistryEntries = 89
