// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"strings"
	"testing"
)

func TestIsByteQuantityAt(t *testing.T) {
	const v = "104857600"
	cases := []struct {
		after string
		want  bool
	}{
		{" bytes", true}, {" byte", true}, {"-byte", true}, {"-bytes", true}, {" Bytes", true},
		{" BYTES", true}, {" B", true}, {" KiB", true}, {" kB", true}, {" KB", true},
		{" MiB", true}, {" MB", true}, {" GiB", true}, {" GB", true}, {" TiB", true}, {" TB", true},
		{" bytes)", true}, {" B,", true}, {"-byte total", true},
		{"", false}, {" ", false}, {" b", false}, {" Mb", false}, {" Baker", false},
		{" bytecode", false}, {" Bx", false}, {" B2", false}, {"  bytes", false},
		{" kib", false}, {":bytes", false}, {" by", false},
		// No separator: the candidate pattern's \b cannot end a match before a letter, so this
		// is unreachable from ValidateContent; the helper still reads it as a unit.
		{"bytes", true},
	}
	for _, tc := range cases {
		line := "max " + v + tc.after
		end := strings.Index(line, v) + len(v)
		if got := isByteQuantityAt(line, end); got != tc.want {
			t.Errorf("isByteQuantityAt(%q) = %v, want %v", line, got, tc.want)
		}
	}
}

func TestIsBareNineDigits(t *testing.T) {
	for s, want := range map[string]bool{
		"104857600": true, "452-11-9384": false, "452 11 9384": false, "10485760": false, "1048576000": false,
	} {
		if got := isBareNineDigits(s); got != want {
			t.Errorf("isBareNineDigits(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestNamesAPassport(t *testing.T) {
	cases := []struct {
		lines []string
		want  bool
	}{
		{[]string{"UK passport: 512345678"}, true},
		{[]string{"Travel document 512345678"}, true},
		{[]string{"Field: Passport Number", "Value: 512345678"}, true},
		{[]string{"\t//\tField: Passport Number", "\t//\tValue: 512345678"}, true},
		{[]string{"Please renew your passport soon.", "Value: 512345678"}, false},
		{[]string{"Field: Passport or SSN", "Value: 512345678"}, false},
		{[]string{"Field: SSN", "Value: 512345678"}, false},
		{[]string{"passports 512345678"}, false}, // whole word only
		{[]string{"Value: 512345678"}, false},
	}
	for _, tc := range cases {
		i := len(tc.lines) - 1
		if got := namesAPassport(tc.lines[i], i, tc.lines); got != tc.want {
			t.Errorf("namesAPassport(%q) = %v, want %v", tc.lines, got, tc.want)
		}
	}
}

// TestOtherMeaningCeilingIsTheHeaderCap: issue939_test.go asserts against contradictingHeaderCap
// so it compiles against the parent commit; this keeps the two from drifting apart.
func TestOtherMeaningCeilingIsTheHeaderCap(t *testing.T) {
	if otherMeaningCeiling != wantOtherMeaningCeiling {
		t.Errorf("otherMeaningCeiling = %v, issue939_test.go asserts %v", otherMeaningCeiling, wantOtherMeaningCeiling)
	}
	if otherMeaningCeiling >= 60 {
		t.Errorf("otherMeaningCeiling = %v is MEDIUM or above (the bands are 90 and 60)", otherMeaningCeiling)
	}
}
