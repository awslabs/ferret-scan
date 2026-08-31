// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tabular

import "testing"

// #548: the same genuine public address scored 100 HIGH or 75 MEDIUM depending on how its column
// header was spelled.
//
//	header               HeaderAt returned      keyword "ip address" found
//	"Source IP address"  "source ip address"    yes
//	"source_ip_address"  "source_ip_address"    yes  ('_' is a word boundary)
//	"sourceIPAddress"    "sourceipaddress"      NO
//	"SourceIpAddress"    "sourceipaddress"      NO
//
// Measured end to end on a 3-row CSV of genuine public addresses: `--confidence high` returned 3
// findings for the spaced spelling and 0 for the camel one. Real CloudTrail writes the spaced
// form; anything derived from the JSON field name writes the camel form.
//
// The cause was ORDER: headers are stored lower-cased, and lower-casing first destroys the case
// transitions a camelCase header is made of. Six validators consult headers with whole-word
// lookups, so all six were blind to the camel spelling.

func TestNormalizeHeaderSplitsCamelAndPascal(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The reported cases.
		{"sourceIPAddress", "source IP Address"},
		{"SourceIpAddress", "Source Ip Address"},
		// Acronym at the end of a run followed by a word: the LAST upper-case rune starts the
		// next word, which is what makes "IPAddress" work rather than becoming "I P Address".
		{"IPAddress", "IP Address"},
		{"destIPAddr", "dest IP Addr"},
		// Digit-to-upper.
		{"ipv4Address", "ipv4 Address"},
		{"field2Name", "field2 Name"},
		// Single words and leading capitals are untouched.
		{"source", "source"},
		{"Source", "Source"},
		{"IP", "IP"},
		{"", ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := NormalizeHeader(tc.in); got != tc.want {
				t.Errorf("NormalizeHeader(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestNormalizeHeaderIsIdentityOnSeparatedHeaders is the safety half, and it is what bounds the
// blast radius of a change to shared infrastructure.
//
// A header that already carries separators has no case transition to act on, so it comes back
// byte-identical. That is why this cannot alter the behaviour of any header spelled the
// conventional way — asserted rather than argued, because six validators read these strings.
func TestNormalizeHeaderIsIdentityOnSeparatedHeaders(t *testing.T) {
	for _, h := range []string{
		"source ip address", "Source IP address", "source_ip_address", "source-ip-address",
		"ssn", "tracking_number", "employee id", "parcel_id", "eventtime", "username",
		"medical record number", "SOURCE IP ADDRESS", "IP", "ip", "id",
	} {
		if got := NormalizeHeader(h); got != h {
			t.Errorf("NormalizeHeader(%q) = %q, want it unchanged: a header that is already "+
				"separated must be inert, or this change alters headers it has no business "+
				"touching", h, got)
		}
	}
}

// TestHeaderAtNormalizesCamelInThePipeline drives Analyze/HeaderAt rather than NormalizeHeader
// alone, because the defect was the ORDER of two operations inside Analyze: a unit test of the
// splitter passed while the pipeline still failed, which is exactly how a first attempt at this
// fix measured as completely inert.
//
// Underscored headers are deliberately NOT asserted to equal the spaced form. They keep their
// underscores and always worked, because the keyword matcher treats '_' as a word boundary — the
// cross-spelling equivalence that matters is about the KEYWORD being findable, and that is
// asserted where the real matcher lives, in the ipaddress validator's tests.
func TestHeaderAtNormalizesCamelInThePipeline(t *testing.T) {
	const value = "52.94.236.248"
	for _, tc := range []struct{ header, want string }{
		{"Source IP address", "source ip address"},
		{"sourceIPAddress", "source ip address"},
		{"SourceIpAddress", "source ip address"},
		{"source_ip_address", "source_ip_address"},
	} {
		t.Run(tc.header, func(t *testing.T) {
			content := "eventTime," + tc.header + ",userName\n2026-08-01," + value + ",alice\n"
			tbl := Analyze(content)
			if !tbl.IsTable() {
				t.Fatalf("not recognised as a table")
			}
			row := "2026-08-01," + value + ",alice"
			b := tbl.Bounds(row)
			if b == nil {
				t.Fatal("no bounds for the data row")
			}
			got := tbl.HeaderAt(b, len("2026-08-01,"))
			if got != tc.want {
				t.Errorf("HeaderAt for header %q = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
