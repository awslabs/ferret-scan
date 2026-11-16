// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/validators/address"
)

// TestStreetNamesAreNotPersons: the street lines of #935, as they stand in this repository, report no
// PERSON_NAME, and the address validator still reports the street, so the bytes stay redacted in a
// scan that runs both checks.
func TestStreetNamesAreNotPersons(t *testing.T) {
	cases := []struct {
		where    string
		line     string
		wantGone []string
		street   string // what the address validator must still report, "" when the line has no number
	}{
		{"overlap.go:134 (92, 67)", "//	Residence: 77 August Lane, Boise ID 83702",
			[]string{"August Lane", "Lane, Boise"}, "77 August Lane"},
		{"overlap.go:135 (81, 91): the two values quoted apart; the address validator's month-name veto " +
			"rejects a bare \"77 August Lane\" with no address context, so on this line neither check reports it",
			`//	US_STREET_ADDRESS "77 August Lane"   PERSON_NAME "Lane, Boise"`,
			[]string{"August Lane", "Lane, Boise"}, ""},
		{"plaintext/redactor.go:239 (91): the comma form alone",
			`	// "Lane, Boise" came out as "77 August [PERSON-NAME-REDACTED]", the head of the address in`,
			[]string{"Lane, Boise"}, ""},
		{"legacyole/redactor.go:197 (100)",
			`	// overwrites had already masked. For "Located at 100 Martin Luther King Blvd" the PERSON_NAME`,
			[]string{"Martin Luther King"}, "100 Martin Luther King Blvd"},
	}
	addr := address.NewValidator()
	for _, c := range cases {
		t.Run(c.where, func(t *testing.T) {
			for _, m := range scanText(t, c.line+"\n") {
				for _, gone := range c.wantGone {
					if m.Text == gone {
						t.Errorf("%q reported as PERSON_NAME at %.0f; it is part of a street address", m.Text, m.Conf)
					}
				}
			}
			if c.street == "" {
				return
			}
			ms, err := addr.ValidateContent(c.line+"\n", "t.txt")
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range ms {
				if strings.Contains(m.Text, c.street) {
					return
				}
			}
			t.Errorf("the address validator no longer reports %q; dropping the PERSON_NAME finding would leave it unredacted", c.street)
		})
	}
}

// TestStreetFilterKeepsRealNames: a person whose surname is a street type, with no house number in
// front, or written surname first before a known given name, keeps the confidence main gives it; so
// does a name beside an address.
func TestStreetFilterKeepsRealNames(t *testing.T) {
	cases := []struct {
		line, name string
		conf       float64
	}{
		{"Diane Lane starred in it.", "Diane Lane", 92},
		{"Mailing: 1247 Oakmont Street, Marcus Whitfield", "Marcus Whitfield", 57},
		{"Marcus Whitfield, 1247 Oakmont Street", "Marcus Whitfield", 92},
		{"Martin Luther King Jr. spoke.", "Martin Luther King", 93},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, m := range scanText(t, c.line+"\n") {
				got = append(got, m.Text)
				if m.Text == c.name {
					if m.Conf != c.conf {
						t.Errorf("%q confidence %.0f, want %.0f (unchanged from main)", c.name, m.Conf, c.conf)
					}
					return
				}
			}
			t.Errorf("%q not reported (got %q)", c.name, strings.Join(got, " | "))
		})
	}
}
