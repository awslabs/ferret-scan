// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"strings"
	"testing"
)

// TestIBANRegistryCompiles pins the generated table: every entry compiles, its structure sums to
// its recorded length, and the map holds exactly the number of entries the generator wrote.
func TestIBANRegistryCompiles(t *testing.T) {
	for _, err := range ibanRegistryErrors {
		t.Errorf("%v", err)
	}
	if len(ibanRegistry) != ibanRegistryEntries {
		t.Errorf("ibanRegistry holds %d entries, the generator wrote %d: regenerate instead of editing by hand",
			len(ibanRegistry), ibanRegistryEntries)
	}
	compiled := 0
	for _, c := range ibanCountries {
		if c.length > 0 {
			compiled++
		}
	}
	if compiled != len(ibanRegistry) {
		t.Errorf("%d of %d entries compiled", compiled, len(ibanRegistry))
	}
	for code, f := range ibanRegistry {
		layout, err := expandBBANStructure(f.structure)
		if err != nil {
			t.Errorf("%s: %v", code, err)
			continue
		}
		if 4+len(layout) != f.length {
			t.Errorf("%s: 4 + structure %q (%d) != length %d", code, f.structure, len(layout), f.length)
		}
	}
	// The registry entries #862 found missing from the hand-written map, and Norway, the shortest.
	for _, code := range []string{"BI", "DJ", "EG", "FK", "HN", "LY", "MN", "NI", "OM", "RU", "SD", "SO", "ST", "SV", "YE", "NO"} {
		if _, ok := ibanRegistry[code]; !ok {
			t.Errorf("%s missing from ibanRegistry", code)
		}
	}
	if len(ibanRegistryExamples) != len(ibanRegistry) {
		t.Errorf("%d examples for %d registry entries", len(ibanRegistryExamples), len(ibanRegistry))
	}
}

// TestCompileIBANRegistryReportsAMalformedEntry: a bad entry is left out and reported, never
// half-checked and never a start-up panic.
func TestCompileIBANRegistryReportsAMalformedEntry(t *testing.T) {
	table, errs := compileIBANRegistry(map[string]ibanFormat{
		"DE": {length: 22, structure: "8!n10!n"},
		"NO": {length: 16, structure: "4!n6!n1!n"}, // length disagrees with the structure
		"XX": {length: 20, structure: "4!n12!q"},   // unknown class
		"x1": {length: 20, structure: "16!n"},      // not a country code
	})
	if len(errs) != 3 {
		t.Fatalf("got %d errors, want 3: %v", len(errs), errs)
	}
	if table[ibanCountryIndex('D', 'E')].length != 22 {
		t.Error("the well-formed DE entry was dropped")
	}
	if table[ibanCountryIndex('N', 'O')].length != 0 || table[ibanCountryIndex('X', 'X')].length != 0 {
		t.Error("a malformed entry was compiled")
	}
}

// TestEveryRegistryExampleIsAccepted is the table's positive control: each registry entry's own
// published example passes isValidIBAN, and is reported compact, grouped in fours by spaces, by
// hyphens and by double spaces, with the whole value in the reported span.
func TestEveryRegistryExampleIsAccepted(t *testing.T) {
	v := NewValidator()
	if len(ibanRegistryExamples) < 89 {
		t.Fatalf("only %d registry examples", len(ibanRegistryExamples))
	}
	for code, ex := range ibanRegistryExamples {
		if !v.isValidIBAN(ex) {
			t.Errorf("%s: registry example %s rejected by isValidIBAN", code, ex)
			continue
		}
		forms := map[string]string{
			"compact":      ex,
			"spaced":       groupIBAN(ex, " "),
			"hyphen":       groupIBAN(ex, "-"),
			"double space": groupIBAN(ex, "  "),
		}
		for form, text := range forms {
			got := ibanTexts(t, v, "IBAN: "+text+" BIC: EXMP"+code+"XX")
			if len(got) != 1 || got[0] != text {
				t.Errorf("%s %s: reported %q, want exactly [%q]", code, form, got, text)
			}
		}
	}
}

// TestBBANStructureGate: one wrong character class per component type is rejected, with the check
// digits recomputed so mod-97 still holds and only the structure can be what rejects it. The
// conforming value is accepted.
func TestBBANStructureGate(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		name, cc, bban string
		valid          bool
	}{
		{"DE conforming (8!n10!n)", "DE", "370400440532013000", true},
		{"DE letter where a digit belongs (n)", "DE", "37040044053201300X", false},
		{"DE letter in the bank code (n)", "DE", "3704004A0532013000", false},
		{"GB conforming (4!a6!n8!n)", "GB", "NWBK60161331926819", true},
		{"GB digit where a letter belongs (a)", "GB", "NWB160161331926819", false},
		{"GB letter in the sort code (n)", "GB", "NWBK6016133192681A", false},
		{"GT conforming, all alphanumeric (4!c20!c)", "GT", "TRAJ01020000001210029690", true},
		{"GT letters anywhere (c)", "GT", "EXAMPLEKEY0000000000ABCD", true},
		{"BE conforming (3!n7!n2!n)", "BE", "539007547034", true},
		{"BE letters (n)", "BE", "KEYEXAMPLE00", false},
		{"MU conforming, letters at the end (3!a)", "MU", "BOMM0101101030300200000MUR", true},
		{"MU digit in the trailing currency (a)", "MU", "BOMM0101101030300200000MU1", false},
		{"IT conforming (1!a5!n5!n12!c)", "IT", "X0542811101000000123456", true},
		{"IT digit in the CIN letter (a)", "IT", "10542811101000000123456", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iban := withCheckDigits(tc.cc, tc.bban)
			if !ibanChecksumValid(iban) {
				t.Fatalf("%s: test value must pass mod-97 so only the structure decides", iban)
			}
			if got := v.isValidIBAN(iban); got != tc.valid {
				t.Errorf("isValidIBAN(%s) = %v, want %v", iban, got, tc.valid)
			}
			// The scan applies the same gate: reported exactly when valid, compact and grouped.
			for _, text := range []string{iban, groupIBAN(iban, " ")} {
				got := ibanTexts(t, v, "IBAN "+text)
				if tc.valid != (len(got) == 1) {
					t.Errorf("%q reported as %q, valid=%v", text, got, tc.valid)
				}
			}
		})
	}
}

// TestIBANChecksumValidMatchesTheReference: the incremental mod-97 agrees with the textbook
// rearrange-and-convert computation on every registry example and on their off-by-one neighbours.
func TestIBANChecksumValidMatchesTheReference(t *testing.T) {
	ref := func(s string) bool {
		rearranged := s[4:] + s[:4]
		rem := 0
		for _, c := range rearranged {
			var digits string
			switch {
			case c >= '0' && c <= '9':
				digits = string(c)
			case c >= 'A' && c <= 'Z':
				digits = itoa2(int(c-'A') + 10)
			default:
				return false
			}
			for _, d := range digits {
				rem = (rem*10 + int(d-'0')) % 97
			}
		}
		return rem == 1
	}
	for _, ex := range ibanRegistryExamples {
		for _, s := range []string{ex, bumpLastDigit(ex), strings.ToLower(ex)} {
			if ibanChecksumValid(s) != ref(s) {
				t.Errorf("ibanChecksumValid(%q) = %v, reference %v", s, ibanChecksumValid(s), ref(s))
			}
		}
	}
}

func itoa2(n int) string { return string([]byte{byte('0' + n/10), byte('0' + n%10)}) }

// bumpLastDigit changes the last digit of s, which breaks mod-97 while keeping the shape.
func bumpLastDigit(s string) string {
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] >= '0' && b[i] <= '9' {
			b[i] = '0' + (b[i]-'0'+1)%10
			break
		}
	}
	return string(b)
}
