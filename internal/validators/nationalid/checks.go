// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

// Check-digit and validity rules for the five Americas national identifiers (#884 Part B).
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
)

// Types lists every type this validator emits, in a fixed order.
var Types = []string{TypeBRCPF, TypeCLRUT, TypeARCUIL, TypeCASIN, TypeMXCURP}

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
	c := canonical(value)
	switch dataType {
	case TypeBRCPF:
		return validCPF(c)
	case TypeCLRUT:
		return validRUT(c)
	case TypeARCUIL:
		return validCUIL(c)
	case TypeCASIN:
		return validSIN(c)
	case TypeMXCURP:
		return validCURP(c)
	}
	return false
}

// validCPF: 11 digits, two mod-11 check digits over weights 10..2 and 11..2. The repdigits pass the
// arithmetic and are never issued, so they fail here.
func validCPF(c string) bool {
	if len(c) != 11 || !allDigits(c) || repdigit(c) {
		return false
	}
	return cpfCheck(c[:9]) == c[9:]
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

// validRUT: a 7- or 8-digit body and a mod-11 verifier (0-9 or K) over the repeating weights 2..7.
func validRUT(c string) bool {
	if len(c) < 8 || len(c) > 9 || !allDigits(c[:len(c)-1]) || c[0] == '0' {
		return false
	}
	return rutCheck(c[:len(c)-1]) == c[len(c)-1]
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

// validCUIL: 11 digits, a personal prefix (20, 23, 24 or 27) and a mod-11 check digit over weights
// 5,4,3,2,7,6,5,4,3,2. A remainder that would give 10 is never issued: the issuer re-prefixes the
// number to 23 or 24 instead, so no check digit makes it valid.
func validCUIL(c string) bool {
	if len(c) != 11 || !allDigits(c) {
		return false
	}
	switch c[:2] {
	case "20", "23", "24", "27":
	default:
		return false
	}
	dv, ok := cuilCheck(c[:10])
	return ok && dv == c[10]
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

// validSIN: 9 digits passing Luhn. The first digit is the province or series: 0 is never assigned,
// 8 is the business-number series, and every other leading digit (including 9, temporary residents)
// is a personal SIN. There is no area veto beyond that.
func validSIN(c string) bool {
	if len(c) != 9 || !allDigits(c) || c[0] == '0' || c[0] == '8' {
		return false
	}
	return luhn(c)
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

// validCURP: 18 symbols. Four letters (the second a vowel or X), a YYMMDD birth date that exists,
// sex H, M or X, a state code, three internal consonants, a disambiguator (a digit for a birth before
// 2000, a letter after) and a check digit over the 37-symbol alphabet.
func validCURP(c string) bool {
	if len(c) != 18 {
		return false
	}
	for i := 0; i < 4; i++ {
		if !isUpper(c[i]) {
			return false
		}
	}
	switch c[1] {
	case 'A', 'E', 'I', 'O', 'U', 'X':
	default:
		return false
	}
	for i := 4; i < 10; i++ {
		if !isDigit(c[i]) {
			return false
		}
	}
	if !validDate(c[4:10]) {
		return false
	}
	switch c[10] {
	case 'H', 'M', 'X':
	default:
		return false
	}
	if !curpStates[c[11:13]] {
		return false
	}
	for i := 13; i < 16; i++ {
		if !isCURPConsonant(c[i]) {
			return false
		}
	}
	if !isDigit(c[16]) && !isUpper(c[16]) {
		return false
	}
	if !isDigit(c[17]) {
		return false
	}
	return curpCheck(c[:17]) == c[17]
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
