// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

// Redaction helpers for internal/redactors/replacement's NATIONAL_ID arms. They live here, beside
// Valid, so the rule "a synthetic replacement fails the check" is written once against the same
// validity test the scan uses.

// IsType reports whether dataType is one of this validator's types.
func IsType(dataType string) bool {
	for _, t := range Types {
		if t == dataType {
			return true
		}
	}
	return false
}

func isASCIIAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Mask is the format-preserving rendering: every letter and digit becomes '*', every separator stays,
// so a dotted CPF becomes "***.***.***-**". Nothing of the value is kept: unlike an SSN's last
// four, no part of these numbers is conventionally printed as a reference.
func Mask(value string) string {
	b := []byte(value)
	for i, c := range b {
		if isASCIIAlnum(c) || c >= 0x80 {
			b[i] = '*'
		}
	}
	return string(b)
}

// Key is the synthetic scope's canonical key: the value's letters and digits, upper-cased, so one
// number written with and without separators takes one replacement.
func Key(value string) string { return canonical(value) }

// DrawSynthetic returns a canonical replacement for a canonical key: each digit a random digit, each
// letter a random letter, and a RUT's K verifier a digit. The result FAILS Valid for dataType, so a
// redacted copy never re-detects (#669): when the draw passes the check, its last symbol is moved
// until it does not. intn(n) returns a uniform integer in [0, n).
//
// A replacement of the all-digit types also starts with "000". A national ID often sits on the same
// span as an SSN finding, or an SSN finding covers its first nine digits ("CPF: 234567890-92"), and
// the overlap group then writes this replacement for both; random leading digits re-detected as an
// SSN in 4 of 5 synthetic runs of a four-line file. Area 000 is never an SSN or an ITIN, a SIN never
// starts with 0, a RUT body never does and no CUIL prefix is 00, so the replacement is none of them.
// shortcut: that leaves a SIN six random digits, one million replacements a run; widen the draw if a
// run ever holds more distinct SINs than that.
func DrawSynthetic(dataType, key string, intn func(int) int) string {
	b := []byte(key)
	for i, c := range b {
		switch {
		case c >= '0' && c <= '9':
			b[i] = byte('0' + intn(10)) // #nosec G115 -- a decimal digit
		case c >= 'A' && c <= 'Z':
			if dataType == TypeCLRUT {
				b[i] = byte('0' + intn(10)) // #nosec G115 -- the verifier K becomes a digit
			} else {
				b[i] = byte('A' + intn(26)) // #nosec G115 -- an upper-case letter
			}
		}
	}
	if dataType != TypeMXCURP {
		for i := 0; i < 3 && i < len(b); i++ {
			b[i] = '0'
		}
	}
	for tries := 0; tries < 10 && len(b) > 0 && Valid(dataType, string(b)); tries++ {
		last := len(b) - 1
		if b[last] >= '0' && b[last] <= '9' {
			b[last] = '0' + (b[last]-'0'+1)%10
		} else {
			b[last] = 'A' + (b[last]-'A'+1)%26
		}
	}
	return string(b)
}

// RenderSynthetic writes a canonical replacement into value's shape: its separators kept, each letter
// or digit replaced in order by the next symbol of stored, a letter keeping its case.
func RenderSynthetic(value, stored string) string {
	b := []byte(value)
	j := 0
	for i, c := range b {
		if !isASCIIAlnum(c) || j >= len(stored) {
			continue
		}
		r := stored[j]
		j++
		if c >= 'a' && c <= 'z' && r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b[i] = r
	}
	return string(b)
}
