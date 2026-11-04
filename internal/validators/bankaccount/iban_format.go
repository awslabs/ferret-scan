// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"fmt"
	"strconv"
)

// ibanFormat is one entry of the SWIFT IBAN Registry, as iban_registry.go records it: the total
// IBAN length (country code and check digits included) and the BBAN structure in the registry's
// own notation, where "8!n10!n" means exactly 8 digits then exactly 10 digits. The notation is
// kept rather than a pre-expanded layout so a reviewer can compare an entry with the registry
// directly.
type ibanFormat struct {
	length    int
	structure string
}

// ibanCountry is an ibanFormat compiled for matching: layout holds one character class per BBAN
// position, 'n' a digit, 'a' an uppercase letter and 'c' an uppercase letter or a digit.
type ibanCountry struct {
	length int
	layout string
}

// ibanCountries is ibanRegistry compiled once, indexed by country code (see ibanCountryIndex), so
// the display scan can look up a candidate's country without a map access or an allocation. An
// entry with length 0 is a code with no registered IBAN format.
var ibanCountries, ibanRegistryErrors = compileIBANRegistry(ibanRegistry)

// ibanCountryIndex maps a two-letter code to its slot in ibanCountries, or -1 when either byte is
// not an uppercase ASCII letter.
func ibanCountryIndex(a, b byte) int {
	if a < 'A' || a > 'Z' || b < 'A' || b > 'Z' {
		return -1
	}
	return int(a-'A')*26 + int(b-'A')
}

// lookupIBANCountry returns the compiled format registered for the code a+b.
func lookupIBANCountry(a, b byte) (ibanCountry, bool) {
	i := ibanCountryIndex(a, b)
	if i < 0 || ibanCountries[i].length == 0 {
		return ibanCountry{}, false
	}
	return ibanCountries[i], true
}

// compileIBANRegistry expands every entry's structure into its per-position layout and checks it
// against the recorded length. An entry that does not compile is left out, so its country's IBANs
// are rejected rather than half-checked, and is reported in the returned errors, which
// TestIBANRegistryCompiles requires to be empty. Leaving it out instead of panicking keeps a
// malformed regeneration from taking the whole scanner down at start-up.
func compileIBANRegistry(reg map[string]ibanFormat) ([26 * 26]ibanCountry, []error) {
	var out [26 * 26]ibanCountry
	var errs []error
	for code, f := range reg {
		idx := -1
		if len(code) == 2 {
			idx = ibanCountryIndex(code[0], code[1])
		}
		if idx < 0 {
			errs = append(errs, fmt.Errorf("IBAN registry: %q is not a two-letter uppercase country code", code))
			continue
		}
		layout, err := expandBBANStructure(f.structure)
		if err != nil {
			errs = append(errs, fmt.Errorf("IBAN registry %s: %w", code, err))
			continue
		}
		if 4+len(layout) != f.length {
			errs = append(errs, fmt.Errorf("IBAN registry %s: structure %q is %d characters, so the IBAN is %d, but the entry records %d",
				code, f.structure, len(layout), 4+len(layout), f.length))
			continue
		}
		if f.length < minIBANLength || f.length > maxIBANLength {
			errs = append(errs, fmt.Errorf("IBAN registry %s: length %d is outside %d..%d", code, f.length, minIBANLength, maxIBANLength))
			continue
		}
		out[idx] = ibanCountry{length: f.length, layout: layout}
	}
	return out, errs
}

// minIBANLength and maxIBANLength bound every registered IBAN (Norway is 15; ISO 13616 caps the
// format at 34).
const (
	minIBANLength = 15
	maxIBANLength = 34
)

// expandBBANStructure turns registry notation such as "4!a6!n8!n" into one class byte per
// position ("aaaannnnnnnnnnnnnn"). Only fixed-length components ("!") and the three classes an
// IBAN uses (n, a, c) are accepted: a registry entry with anything else is not one this matcher
// can check, and is refused rather than approximated.
func expandBBANStructure(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty BBAN structure")
	}
	var layout []byte
	for i := 0; i < len(s); {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i || j+1 >= len(s) || s[j] != '!' {
			return "", fmt.Errorf("BBAN structure %q: expected <count>!<class> at offset %d", s, i)
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil || n <= 0 || n > maxIBANLength {
			return "", fmt.Errorf("BBAN structure %q: bad component length %q", s, s[i:j])
		}
		class := s[j+1]
		if class != 'n' && class != 'a' && class != 'c' {
			return "", fmt.Errorf("BBAN structure %q: unknown character class %q", s, class)
		}
		for k := 0; k < n; k++ {
			layout = append(layout, class)
		}
		i = j + 2
	}
	return string(layout), nil
}

// bbanConforms reports whether bban, an uppercased candidate's characters after the country code
// and check digits, has the registered character class at every position. The caller has already
// checked the length.
func bbanConforms(bban, layout string) bool {
	if len(bban) != len(layout) {
		return false
	}
	for i := 0; i < len(bban); i++ {
		c := bban[i]
		switch layout[i] {
		case 'n':
			if c < '0' || c > '9' {
				return false
			}
		case 'a':
			if c < 'A' || c > 'Z' {
				return false
			}
		default: // 'c'
			if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
				return false
			}
		}
	}
	return true
}
