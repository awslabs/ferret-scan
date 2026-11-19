// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

import "strings"

// Check-digit and validity rules for the six Americas national identifiers (#884 Part B).
//
// Each rule is the published algorithm for the number; the issue's appendix carries the same
// arithmetic as Python and pins one value per rule, which TestCheckDigitsMatchTheIssueAppendix
// reproduces. Every function takes the identifier's CANONICAL form: its digits (and, for a CURP or a
// RUT verifier, its letters) upper-cased with every separator removed. canonical builds that form.

// Type names, one per identifier. They are the Match.Type each finding carries.
const (
	TypeBRCPF  = "BR_CPF"  // Brazil, Cadastro de Pessoas Físicas
	TypeCLRUT  = "CL_RUT"  // Chile, Rol Único Tributario / Nacional (RUT and RUN share one space)
	TypeARCUIL = "AR_CUIL" // Argentina, CUIL and the personal CUIT prefixes 20/23/24/27
	TypeCASIN  = "CA_SIN"  // Canada, Social Insurance Number
	TypeMXCURP = "MX_CURP" // Mexico, Clave Única de Registro de Población
	TypeMXRFC  = "MX_RFC"  // Mexico, Registro Federal de Contribuyentes (a person's or a company's tax ID)
)

// Types lists every type this validator emits, in a fixed order.
var Types = []string{TypeBRCPF, TypeCLRUT, TypeARCUIL, TypeCASIN, TypeMXCURP, TypeMXRFC}

// canonical returns s with every byte that is not an ASCII letter or digit removed, letters
// upper-cased.
func canonical(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'Z':
			b = append(b, c)
		case c >= 'a' && c <= 'z':
			b = append(b, c-'a'+'A')
		}
	}
	return string(b)
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// repdigit reports whether every byte of s is the same.
func repdigit(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return len(s) > 0
}

// Valid reports whether value (in any of the spellings this validator matches) is a valid
// identifier of the given type: right length, check digit(s) correct, and the type's structural
// rules met. An unknown type is never valid.
//
// Exported for the redaction arms (internal/redactors/replacement), whose synthetic replacements
// must FAIL this test so a redacted copy never re-detects (#669, as #974 did for card numbers).
func Valid(dataType, value string) bool {
	shapeOK, checkOK := assess(dataType, value)
	return shapeOK && checkOK
}

// assess splits Valid in two. shapeOK is the structural rule: the right length and alphabet, and the
// type's own constraints that no check digit is part of (an existing birth date, an issued prefix).
// checkOK is the check digit alone, and is meaningful only when shapeOK is true. A value whose shape
// is right and whose check digit fails is a mistyped number as often as a random one: the scan
// reports it at LOW when its label is there (checkFailedConfidence).
func assess(dataType, value string) (shapeOK, checkOK bool) {
	if dataType == TypeMXRFC {
		return assessRFC(strings.ToUpper(strings.TrimSpace(value)))
	}
	c := canonical(value)
	switch dataType {
	case TypeBRCPF:
		return assessCPF(c)
	case TypeCLRUT:
		return assessRUT(c)
	case TypeARCUIL:
		return assessCUIL(c)
	case TypeCASIN:
		return assessSIN(c)
	case TypeMXCURP:
		return assessCURP(c)
	}
	return false, false
}

// assessCPF: 11 digits, two mod-11 check digits over weights 10..2 and 11..2. The repdigits pass the
// arithmetic and are never issued, so they fail here.
func assessCPF(c string) (shapeOK, checkOK bool) {
	if len(c) != 11 || !allDigits(c) || repdigit(c) {
		return false, false
	}
	return true, cpfCheck(c[:9]) == c[9:]
}

// cpfCheck returns the two CPF check digits for a 9-digit base.
func cpfCheck(base string) string {
	d := make([]int, 0, 11)
	for i := 0; i < len(base); i++ {
		d = append(d, int(base[i]-'0'))
	}
	for _, n := range []int{10, 11} {
		sum := 0
		for i, w := 0, n; w >= 2; i, w = i+1, w-1 {
			sum += d[i] * w
		}
		r := sum % 11
		if r < 2 {
			d = append(d, 0)
		} else {
			d = append(d, 11-r)
		}
	}
	return string([]byte{byte('0' + d[9]), byte('0' + d[10])}) // #nosec G115 -- decimal digits
}

// assessRUT: a 7- or 8-digit body and a mod-11 verifier (0-9 or K) over the repeating weights 2..7.
func assessRUT(c string) (shapeOK, checkOK bool) {
	if len(c) < 8 || len(c) > 9 || !allDigits(c[:len(c)-1]) || c[0] == '0' {
		return false, false
	}
	return true, rutCheck(c[:len(c)-1]) == c[len(c)-1]
}

// rutCheck returns the RUT verifier for a body of digits.
func rutCheck(body string) byte {
	t, m := 0, 2
	for i := len(body) - 1; i >= 0; i-- {
		t += int(body[i]-'0') * m
		if m == 7 {
			m = 2
		} else {
			m++
		}
	}
	switch r := 11 - t%11; r {
	case 11:
		return '0'
	case 10:
		return 'K'
	default:
		return byte('0' + r) // #nosec G115 -- r is 1..9
	}
}

// assessCUIL: 11 digits, a personal prefix (20, 23, 24 or 27) and a mod-11 check digit over weights
// 5,4,3,2,7,6,5,4,3,2. A remainder that would give 10 is never issued: the issuer re-prefixes the
// number to 23 or 24 instead, so no check digit makes it valid.
func assessCUIL(c string) (shapeOK, checkOK bool) {
	if len(c) != 11 || !allDigits(c) {
		return false, false
	}
	switch c[:2] {
	case "20", "23", "24", "27":
	default:
		return false, false
	}
	dv, ok := cuilCheck(c[:10])
	return true, ok && dv == c[10]
}

// cuilCheck returns the CUIL/CUIT check digit for a 10-digit base, and false when none exists.
func cuilCheck(base string) (byte, bool) {
	weights := [10]int{5, 4, 3, 2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 10; i++ {
		sum += int(base[i]-'0') * weights[i]
	}
	switch r := 11 - sum%11; r {
	case 11:
		return '0', true
	case 10:
		return 0, false
	default:
		return byte('0' + r), true // #nosec G115 -- r is 1..9
	}
}

// assessSIN: 9 digits passing Luhn. The first digit is the province or series: 0 is never assigned,
// 8 is the business-number series, and every other leading digit (including 9, temporary residents)
// is a personal SIN. There is no area veto beyond that.
func assessSIN(c string) (shapeOK, checkOK bool) {
	if len(c) != 9 || !allDigits(c) || c[0] == '0' || c[0] == '8' {
		return false, false
	}
	return true, luhn(c)
}

func luhn(digits string) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// curpStates are the RENAPO entity codes a CURP's positions 12-13 carry: the 32 federal entities and
// NE (born abroad).
var curpStates = map[string]bool{
	"AS": true, "BC": true, "BS": true, "CC": true, "CL": true, "CM": true, "CS": true, "CH": true,
	"DF": true, "DG": true, "GT": true, "GR": true, "HG": true, "JC": true, "MC": true, "MN": true,
	"MS": true, "NT": true, "NL": true, "OC": true, "PL": true, "QT": true, "QR": true, "SP": true,
	"SL": true, "SR": true, "TC": true, "TS": true, "TL": true, "VZ": true, "YN": true, "ZS": true,
	"NE": true,
}

// curpAlphabet is the CURP check-digit alphabet: each symbol's value is its index. Ñ sits after N
// (index 24); a CURP never prints it (RENAPO writes X), so '&' holds its slot here and the letters
// after N keep their published values.
const curpAlphabet = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ"

func curpValue(c byte) int {
	for i := 0; i < len(curpAlphabet); i++ {
		if curpAlphabet[i] == c {
			return i
		}
	}
	return -1
}

func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isCURPConsonant(c byte) bool {
	return isUpper(c) && c != 'A' && c != 'E' && c != 'I' && c != 'O' && c != 'U'
}

// assessCURP: 18 symbols. Four letters (the second a vowel or X), a YYMMDD birth date that exists,
// sex H, M or X, a state code, three internal consonants, a disambiguator (a digit for a birth before
// 2000, a letter after) and a check digit over the 37-symbol alphabet (the check digit is checkOK, the rest shapeOK).
func assessCURP(c string) (shapeOK, checkOK bool) {
	if len(c) != 18 {
		return false, false
	}
	for i := 0; i < 4; i++ {
		if !isUpper(c[i]) {
			return false, false
		}
	}
	switch c[1] {
	case 'A', 'E', 'I', 'O', 'U', 'X':
	default:
		return false, false
	}
	for i := 4; i < 10; i++ {
		if !isDigit(c[i]) {
			return false, false
		}
	}
	if !validDate(c[4:10]) {
		return false, false
	}
	switch c[10] {
	case 'H', 'M', 'X':
	default:
		return false, false
	}
	if !curpStates[c[11:13]] {
		return false, false
	}
	for i := 13; i < 16; i++ {
		if !isCURPConsonant(c[i]) {
			return false, false
		}
	}
	if !isDigit(c[16]) && !isUpper(c[16]) {
		return false, false
	}
	if !isDigit(c[17]) {
		return false, false
	}
	return true, curpCheck(c[:17]) == c[17]
}

// curpCheck returns the CURP check digit for its first 17 symbols.
func curpCheck(c17 string) byte {
	sum := 0
	for i := 0; i < 17; i++ {
		v := curpValue(c17[i])
		if v < 0 {
			return 0
		}
		sum += v * (18 - i)
	}
	return byte('0' + (10-sum%10)%10) // #nosec G115 -- a decimal digit
}

// validDate reports whether YYMMDD names a day that exists in some century (29 February only in a
// year divisible by 4, which 00 is in 2000).
func validDate(s string) bool {
	yy := int(s[0]-'0')*10 + int(s[1]-'0')
	mm := int(s[2]-'0')*10 + int(s[3]-'0')
	dd := int(s[4]-'0')*10 + int(s[5]-'0')
	if mm < 1 || mm > 12 || dd < 1 {
		return false
	}
	days := [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mm]
	if mm == 2 && yy%4 != 0 {
		days = 28
	}
	return dd <= days
}

// rfcAlphabet is the SAT's RFC check-digit table: each symbol's value is its index. The digits, the
// letters with '&' between N and O, a space at 37 (the padding of a company's 12-character RFC) and
// Ñ at 38. This validator reads ASCII only (see the MX_RFC shape), so Ñ is never looked up.
const rfcAlphabet = "0123456789ABCDEFGHIJKLMN&OPQRSTUVWXYZ "

// rfcCheck returns the RFC verifier for the first 12 symbols of a 13-symbol RFC (a company's
// 12-character RFC is padded on the left with a space first): the sum of each symbol's table value
// times a weight from 13 down to 2, the verifier 11 minus that sum modulo 11, where 11 is written 0
// and 10 is written A. The homoclave's first two symbols are assigned by the SAT; only this last one
// is computed.
//
// Source: the algorithm is the SAT's, printed in its RFC structure document ("Estructura de la
// clave en el Registro Federal de Contribuyentes",
// https://wwwmat.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461176322651&ssbinary=true).
// The author could not open that PDF from the build host (it is not served as text); the table and the
// weights are the widely published ones, and TestRFCVerifierMatchesSampleRFCs checks them against
// seven sample RFCs of SAT CFDI test taxpayers (EKU9003173C9, URE180429TM6, KAHO641101B39,
// CACX7605101P8, IIA040805DZ4, XIQB891116QE4, GODE561231GR8), 7 of 7. The author recalled those
// samples; none was read from an SAT page, so they show the arithmetic is the one in use, not that
// the SAT prints it that way.
func rfcCheck(first12 string) byte {
	sum := 0
	for i := 0; i < 12; i++ {
		v := strings.IndexByte(rfcAlphabet, first12[i])
		if v < 0 {
			return 0
		}
		sum += v * (13 - i)
	}
	switch r := (11 - sum%11) % 11; r {
	case 10:
		return 'A'
	default:
		return byte('0' + r) // #nosec G115 -- r is 0..9
	}
}

// genericRFCs are the two RFCs the SAT prints for an invoice whose customer has none: XAXX010101000
// for a national customer without an RFC, XEXX010101000 for a resident abroad. They name nobody.
// Source: SAT, Resolución Miscelánea Fiscal, the rule on the generic RFC in an invoice (its page is
// https://wwwmat.sat.gob.mx/articulo/16302, whose slug names the rule's number; the number is left
// out here because a dotted quad reads as an IP address to the self-scan). Read 2026-11-19 through a
// search result's snippet only; the page is not fetchable from the build host. XAXX010101000 does not pass the verifier
// above (it computes to 4) and XEXX010101000 does: the generic RFCs are assigned, not computed.
var genericRFCs = map[string]bool{"XAXX010101000": true, "XEXX010101000": true}

// isGenericRFC reports whether c, an upper-case RFC, is one of the SAT's two generic RFCs.
func isGenericRFC(c string) bool { return genericRFCs[c] }

// assessRFC: 12 characters for a company (three letters or '&') or 13 for a person (four), then a
// YYMMDD date that exists, then a three-symbol homoclave whose last symbol is the verifier (a digit
// or A). c is upper-case.
func assessRFC(c string) (shapeOK, checkOK bool) {
	var letters int
	switch len(c) {
	case 12:
		letters = 3
	case 13:
		letters = 4
	default:
		return false, false
	}
	for i := 0; i < letters; i++ {
		if !isUpper(c[i]) && c[i] != '&' {
			return false, false
		}
	}
	for i := letters; i < letters+6; i++ {
		if !isDigit(c[i]) {
			return false, false
		}
	}
	if !validDate(c[letters : letters+6]) {
		return false, false
	}
	for i := letters + 6; i < len(c)-1; i++ {
		if !isDigit(c[i]) && !isUpper(c[i]) {
			return false, false
		}
	}
	last := c[len(c)-1]
	if !isDigit(last) && last != 'A' {
		return false, false
	}
	padded := c
	if len(c) == 12 {
		padded = " " + c
	}
	return true, rfcCheck(padded[:12]) == last
}
