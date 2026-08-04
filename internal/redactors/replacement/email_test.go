// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"
)

// These tests lock in the fix for a cleartext leak in format-preserving EMAIL
// redaction, which is the same defect class as the phone leak next door: a
// masking scheme whose masked span is empty at the smallest input size, so the
// value survives redaction untouched.
//
// preserveEmail kept the first character of the local part for readability
// ("j***@example.com"). When the local part was exactly ONE character that rule
// degenerated to returning the input verbatim, so "a@b.co" redacted to "a@b.co".
//
// Reproduced end to end on the shipped binary before the fix — a .txt containing
// "contact a@b.co for details" scanned with --redaction-strategy
// format_preserving produced a "redacted" copy containing the address in full.
// It is reachable from the library too: format-preserving is the DEFAULT strategy
// in pkg/scan, so an embedder gets this path unless it opts out.

// TestEmail_FormatPreserving_NoLeak asserts the local part is never returned
// intact, at every length — most importantly length 1, which was the leak.
func TestEmail_FormatPreserving_NoLeak(t *testing.T) {
	cases := []struct {
		name  string
		input string
		user  string // the local part that MUST NOT survive verbatim
	}{
		{"one_char_local", "a@b.co", "a"},       // the leak
		{"one_char_short_tld", "a@b.c", "a"},    // the leak
		{"one_char_real_domain", "x@y.io", "x"}, // the leak
		{"two_char_local", "ab@cd.ef", "ab"},
		{"typical", "jane@example.com", "jane"},
		{"long_local", "jane.analyst.qa@example.com", "jane.analyst.qa"},
		{"digit_local", "1@example.com", "1"},
		{"plus_addressing", "a+tag@example.com", "a+tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatPreserving(tc.input, "EMAIL")

			if got == tc.input {
				t.Fatalf("FormatPreserving(%q) returned the input unchanged — "+
					"a redaction that redacts nothing is a cleartext leak", tc.input)
			}

			// The masked output must not begin with the whole local part followed
			// by "@": that is the exact shape of the leak.
			if strings.HasPrefix(got, tc.user+"@") && len(tc.user) > 1 {
				// For a local part longer than one character, keeping only the FIRST
				// character is the intended behaviour, so this checks the whole
				// local part did not survive.
				t.Errorf("FormatPreserving(%q) = %q: the entire local part %q survived",
					tc.input, got, tc.user)
			}
			if len(tc.user) == 1 && strings.HasPrefix(got, tc.user+"@") {
				t.Errorf("FormatPreserving(%q) = %q: the single-character local part %q "+
					"survived; it must be masked", tc.input, got, tc.user)
			}
		})
	}
}

// Length preservation is the contract of this strategy, and it is load-bearing
// beyond cosmetics: the legacy OLE redactor patches bytes in place and can only
// do so when the replacement is exactly as long as the original. A length change
// there would corrupt the container.
func TestEmail_FormatPreserving_PreservesLength(t *testing.T) {
	for _, in := range []string{
		"a@b.co",
		"a@b.c",
		"ab@cd.ef",
		"jane@example.com",
		"jane.analyst.qa@example.com",
		"1@example.com",
		"a+tag@example.com",
	} {
		got := FormatPreserving(in, "EMAIL")
		if len(got) != len(in) {
			t.Errorf("FormatPreserving(%q) = %q: %d bytes, want %d — format-preserving "+
				"must not change length; the OLE redactor's in-place patching depends on it",
				in, got, len(got), len(in))
		}
	}
}

// The domain is deliberately retained: it carries triage value (which provider,
// internal vs external) and is not itself the identifier. This pins that choice
// so a future "mask everything" change is a deliberate decision rather than an
// accident, and confirms the masked local part is what changed.
func TestEmail_FormatPreserving_KeepsDomain(t *testing.T) {
	cases := map[string]string{
		"a@b.co":           "b.co",
		"jane@example.com": "example.com",
		"a+tag@corp.local": "corp.local",
	}
	for in, domain := range cases {
		got := FormatPreserving(in, "EMAIL")
		if !strings.HasSuffix(got, "@"+domain) {
			t.Errorf("FormatPreserving(%q) = %q, want it to end in @%s", in, got, domain)
		}
	}
}

// Degenerate inputs must not panic and must not pass the value through. A crash
// here takes down an embedding process; a pass-through is a leak.
func TestEmail_FormatPreserving_DegenerateInputs(t *testing.T) {
	for _, in := range []string{
		"@example.com", // empty local part
		"noatsign",     // not an email at all
		"@",            // just the separator
		"a@",           // empty domain
		"",             // empty string
	} {
		got := FormatPreserving(in, "EMAIL")
		if in != "" && got == in {
			t.Errorf("FormatPreserving(%q) returned the input unchanged", in)
		}
	}
}

// The alias types route to the same helper, so the fix must cover them. A leak
// that only closes for "EMAIL" while "GMAIL"/"BUSINESS" still pass the value
// through would be worse than no fix, because the type that leaks is the one a
// reader is least likely to check.
func TestEmail_FormatPreserving_CoversAliasTypes(t *testing.T) {
	for _, dataType := range []string{"EMAIL", "GMAIL", "BUSINESS"} {
		got := FormatPreserving("a@b.co", dataType)
		if got == "a@b.co" {
			t.Errorf("FormatPreserving(%q, %s) returned the input unchanged", "a@b.co", dataType)
		}
		if len(got) != len("a@b.co") {
			t.Errorf("FormatPreserving(%q, %s) = %q: length changed", "a@b.co", dataType, got)
		}
	}
}
