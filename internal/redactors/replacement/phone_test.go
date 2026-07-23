// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"
)

// These tests lock in the fix for security finding HIGH-1: format-preserving
// phone redaction previously left the whole number in clear for 7-digit inputs
// (middle = Repeat("*", 0)) and PANICKED for 6-digit inputs (Repeat("*", -1)).
// The policy is now "mask all but the last 4 digits", identical to SSN/CC.

// TestPhone_FormatPreserving_NoLeak asserts that for a range of digit counts the
// masked output never contains the leading digits and always ends in the real
// last 4 — i.e. redaction actually redacts.
func TestPhone_FormatPreserving_NoLeak(t *testing.T) {
	cases := []struct {
		name  string
		input string
		last4 string
		lead  string // leading digits that MUST NOT survive
	}{
		{"six_digits", "012345", "2345", "01"},
		{"seven_digits_local", "0123456", "3456", "012"}, // the old full-leak case
		{"seven_dashed", "012-3456", "3456", "012"},      // the old full-leak case
		{"ten_digits", "2065550173", "0173", "206555"},
		{"us_formatted", "(206) 555-0173", "0173", "206555"},
		{"e164", "+12065550173", "0173", "120655"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatPreserving(tc.input, "PHONE")
			digitsOnly := stripNonDigits(got)
			if !strings.HasSuffix(digitsOnly, tc.last4) {
				t.Errorf("FormatPreserving(%q) = %q; digits %q must end in last4 %q",
					tc.input, got, digitsOnly, tc.last4)
			}
			// Everything before the last 4 must be masked — no leading real digit survives.
			maskedPart := digitsOnly[:len(digitsOnly)-len(tc.last4)]
			if maskedPart != "" {
				t.Errorf("FormatPreserving(%q) = %q; leading digits not fully masked (got %q before last4)",
					tc.input, got, maskedPart)
			}
			if strings.HasPrefix(digitsOnly, tc.lead) {
				t.Errorf("FormatPreserving(%q) = %q leaks leading digits %q", tc.input, got, tc.lead)
			}
		})
	}
}

// TestPhone_FormatPreserving_NoPanic asserts the 6-and-under digit inputs that
// previously computed Repeat("*", negative) no longer panic.
func TestPhone_FormatPreserving_NoPanic(t *testing.T) {
	for _, in := range []string{"1", "12", "123", "1234", "12345", "012345", "12-34", "1.2.3"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("FormatPreserving(%q) panicked: %v", in, r)
				}
			}()
			_ = FormatPreserving(in, "PHONE")
		}()
	}
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
