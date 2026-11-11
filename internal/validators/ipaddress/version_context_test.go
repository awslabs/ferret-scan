// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"net"
	"strings"
	"testing"
)

// TestTheIPv4CompatibleBlockIsNonSensitive pins the range change behind the "::EC2" fix: ::/96
// replaces ::1/128, which it contains, and holds no IPv4 address and no IPv4-mapped one.
func TestTheIPv4CompatibleBlockIsNonSensitive(t *testing.T) {
	v := NewValidator()
	for _, ip := range []string{"::ec2", "::1", "::ce", "::ffff:52", "::ab:cd"} {
		if v.isSensitiveIP(ip) {
			t.Errorf("isSensitiveIP(%q) = true; it is inside ::/96", ip)
		}
	}
	for _, ip := range []string{"52.94.236.248", "::ffff:52.94.236.248", "2606:4700:4700::1111", "1:2::3"} {
		if !v.isSensitiveIP(ip) {
			t.Errorf("isSensitiveIP(%q) = false; it is outside ::/96 and must stay reportable", ip)
		}
	}
	// Non-vacuity for the IPv4-mapped row: Go parses it to the same 16 bytes as the IPv4 address,
	// so a ::/96 membership test that compared 16-byte forms would wrongly swallow every IPv4.
	if ip := net.ParseIP("::ffff:52.94.236.248"); ip.To4() == nil {
		t.Fatal("expected an IPv4-mapped address to have a 4-byte form")
	}
}

func TestIsScopedIdentifierAt(t *testing.T) {
	cases := []struct {
		line, match string
		want        bool
	}{
		{"Face::Add::Bead", "Face::Add", true},
		{"1::2::3", "1::2", true},
		{"Face::Add", "Face::Add", false},
		{"2606:4700:4700::1111]:443", "2606:4700:4700::1111", false},
		{"2606:4700:4700::1111:", "2606:4700:4700::1111", false},
		{"52.94.236.248::", "52.94.236.248", false}, // no ':' in the match: not an IPv6 shape
		{"::EC2", "::EC2", false},
	}
	for _, tc := range cases {
		end := strings.Index(tc.line, tc.match) + len(tc.match)
		if got := isScopedIdentifierAt(tc.match, tc.line, end); got != tc.want {
			t.Errorf("isScopedIdentifierAt(%q in %q) = %v, want %v", tc.match, tc.line, got, tc.want)
		}
	}
}

func TestProductVersionValues(t *testing.T) {
	v := NewValidator()
	std := v.patterns[0]
	if std.name != "IPv4_Standard" {
		t.Fatalf("patterns[0] is %q; productVersionValues is fed the IPv4_Standard matches", std.name)
	}
	cases := []struct {
		line string
		want []string
	}{
		{"matching `4.3.3.2` out of `LibreOffice/4.3.3.2$Linux`", []string{"4.3.3.2"}},
		{"Chrome/138.0.0.0 and Firefox/115.0.2.1", []string{"138.0.0.0", "115.0.2.1"}},
		{"http://52.94.236.248/x and 4.3.3.2", nil},
		{"Gateway/52.94.236.248:8443 and Route/52.94.236.249/24", nil},
		{"no quads here", nil},
	}
	for _, tc := range cases {
		got := productVersionValues(tc.line, std.regex.FindAllStringIndex(tc.line, -1))
		if len(got) != len(tc.want) {
			t.Errorf("productVersionValues(%q) = %v, want %v", tc.line, got, tc.want)
			continue
		}
		for _, w := range tc.want {
			if !hasProductValue(got, w) {
				t.Errorf("productVersionValues(%q) lacks %q", tc.line, w)
			}
		}
	}
	if hasProductValue(nil, "4.3.3.2") {
		t.Error("hasProductValue(nil, ...) = true")
	}
}

func TestIsNamedByNonAddressWordAt(t *testing.T) {
	v := NewValidator()
	const q = "26.8.0.3"
	cases := []struct {
		prefix string
		want   bool
		why    string
	}{
		{"Manager ", true, "a capitalised non-keyword word"},
		{"Acme Server Manager ", true, "the last word of a multi-word name"},
		{"LibreOffice ", true, "CamelCase is a name"},
		{"Server ", false, "an IP keyword names the value"},
		{"Host ", false, "an IP keyword names the value"},
		{"From ", false, "a preposition introduces the value"},
		{"Per ", false, "a preposition"},
		{"manager ", false, "lower case is prose, not a name"},
		{"ACCEPT ", false, "all capitals is a log field"},
		{"Manager  ", false, "two spaces are a column gap"},
		{"Manager\t", false, "only a single space binds a name"},
		{"x9Manager ", false, "the tail of a longer token"},
		{"a_Manager ", false, "the tail of a longer token"},
		{"M ", false, "one letter is not a word"},
		{"", false, "nothing before the value"},
		{" ", false, "a space and nothing else"},
		{strings.Repeat("A", 40) + "manager ", false, "longer than any name word"},
	}
	for _, tc := range cases {
		line := tc.prefix + q
		if got := v.isNamedByNonAddressWordAt(line, len(tc.prefix)); got != tc.want {
			t.Errorf("isNamedByNonAddressWordAt(%q) = %v, want %v (%s)", line, got, tc.want, tc.why)
		}
	}
}

// TestTheNameScanIsBoundedNearOffsetZero guards the backward scan against a slice panic.
func TestTheNameScanIsBoundedNearOffsetZero(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{"", " ", "A ", "Ab ", "Ab", " 1.2.3.4", "Ab 1.2.3.4"} {
		for off := 0; off <= len(line); off++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("isNamedByNonAddressWordAt(%q, %d) panicked: %v", line, off, r)
					}
				}()
				v.isNamedByNonAddressWordAt(line, off)
			}()
		}
	}
}
