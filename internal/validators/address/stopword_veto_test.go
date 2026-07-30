// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import "testing"

// realAddressesWithCollidingStreetNames are real US street names that collide
// with the monthNames or unlikelyStreetWords sets, written as complete addresses.
// Every one of these reported NOTHING before the heuristics were gated on
// independent address evidence.
//
// The consequence is a leak, not a scoring nit: only reported findings are handed
// to the redactor, and a file that yields no findings has no redacted output
// written at all, so the whole address survived in cleartext.
var realAddressesWithCollidingStreetNames = []string{
	// monthNames collisions -- May, March, August, June are all real US streets.
	"Mailing address: 1420 May Street, Springfield IL 62704",
	"Residence: 77 August Lane, Boise ID 83702",
	"Employee home address 15 June Court, Tulsa OK 74103",
	"Billing address: 12 January Road, Peoria IL 61602",
	"1420 May Street, Springfield IL 62704",

	// unlikelyStreetWords collisions -- articles are ordinary in planned
	// developments and coastal towns.
	"Mailing address: 88 The Meadows Drive, Springfield IL 62704",
	"Ship to 300 The Oaks Boulevard, Cary NC 27511",

	// The abbreviation-plus-unit form, where the space after "Dr."/"St." is
	// omitted. Previously read as a file extension.
	"Home address 4821 Maple Dr.Suite 200, Springfield IL 62704",
	"Mailing address: 1 Oak St.Apt 4, Reno NV 89501",
}

// nonAddressesThatMustStaySuppressed is what the heuristics exist for. Widening
// recall must not start reporting these.
var nonAddressesThatMustStaySuppressed = []string{
	// The shape the unlikelyStreetWords set was written to catch: a count, a
	// preposition, then something that looks like a street.
	"100 connections on Main Loop",
	"3 processes on Server Way",
	"12 entries in the Event Circle",
	"8 sessions on Test Drive",
	"6 connections on the Main Way",
	"Retry 3 requests in the Batch Circle",

	// Month/day words in ordinary prose.
	"Meeting on Monday Street",
	"Due 15 January Road",
	"Scheduled 4 events on Friday Street",

	// Code references: the file-extension check must still fire.
	"Home address 4821 Maple Dr.go handler",
	"Home address 100 North Dr.py script",
	"Mailing address: 5 Elm St.java build",

	// Adversarial: log lines that happen to contain a bare STATE ZIP token. The
	// city/state/ZIP evidence pattern requires the ", City ST ZIP" tail precisely
	// so these do not get rescued.
	"Error IL 62704 returned by 3 processes on Server Way",
	"Job CA 90210 failed after 5 items in the Queue Lane",
}

// TestRealStreetNamesAreReported is the leak this file exists for.
func TestRealStreetNamesAreReported(t *testing.T) {
	v := NewValidator()

	for _, line := range realAddressesWithCollidingStreetNames {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "hr-export.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("a real address was deleted because its street name collides "+
					"with a stopword or month name: %s", line)
			}
		})
	}
}

// TestNonAddressesStaySuppressed is the precision half, and the reason the fix
// gates the heuristics rather than deleting them.
func TestNonAddressesStaySuppressed(t *testing.T) {
	v := NewValidator()

	for _, line := range nonAddressesThatMustStaySuppressed {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "app.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a non-address was reported: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestControlPairs is what makes the two tests above non-circular: for each
// leaking street name, the identical line with a neutral name must ALREADY
// report. If the control did not report either, the fixture shape would be wrong
// and the "leak" would be an artifact of the sentence rather than the word.
func TestControlPairs(t *testing.T) {
	v := NewValidator()

	pairs := []struct{ colliding, control string }{
		{
			"Mailing address: 1420 May Street, Springfield IL 62704",
			"Mailing address: 1420 Oak Street, Springfield IL 62704",
		},
		{
			"Mailing address: 88 The Meadows Drive, Springfield IL 62704",
			"Mailing address: 88 Meadows Drive, Springfield IL 62704",
		},
		{
			"Home address 4821 Maple Dr.Suite 200, Springfield IL 62704",
			"Home address 4821 Maple Dr Suite 200, Springfield IL 62704",
		},
	}

	for _, p := range pairs {
		t.Run(p.control, func(t *testing.T) {
			control, err := v.ValidateContent(p.control, "hr-export.csv")
			if err != nil {
				t.Fatalf("ValidateContent(control): %v", err)
			}
			if len(control) == 0 {
				t.Fatalf("the CONTROL line reports nothing, so the paired case proves "+
					"nothing about the colliding word: %s", p.control)
			}

			colliding, err := v.ValidateContent(p.colliding, "hr-export.csv")
			if err != nil {
				t.Fatalf("ValidateContent(colliding): %v", err)
			}
			if len(colliding) == 0 {
				t.Errorf("colliding form dropped while the control reports: %s", p.colliding)
			}
		})
	}
}

// TestHasAddressEvidence pins the arbitration signal directly. It has to be
// independent of the street name's own words, which is exactly what lets it
// overrule name-based heuristics.
func TestHasAddressEvidence(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		// Explicit labels.
		{"Mailing address: 1420 May Street", true},
		{"Home address 4821 Maple Dr", true},
		{"Billing address: 12 January Road", true},
		{"Residence: 77 August Lane, Boise ID 83702", true},
		{"address: 1 Oak St", true},

		// City/state/ZIP tail.
		{"1420 May Street, Springfield IL 62704", true},
		{"300 The Oaks Boulevard, Cary NC 27511", true},
		{"9 Isle of Wight Road, Norfolk VA 23510-1234", true},
		{"1 Main St, New York NY 10020", true},

		// Neither: ordinary prose and log lines.
		{"100 connections on Main Loop", false},
		{"Meeting on Monday Street", false},
		{"Due 15 January Road", false},
		{"5 items in the Records Court", false},

		// A bare STATE ZIP with no ", City" prefix must NOT count, or log text
		// gets the rescue.
		{"Error IL 62704 returned by 3 processes on Server Way", false},
		{"Job CA 90210 failed after 5 items in the Queue Lane", false},

		// Degenerate.
		{"", false},
	}

	for _, c := range cases {
		ctx := &streetFPContext{line: c.line}
		if got := ctx.hasAddressEvidence(); got != c.want {
			t.Errorf("hasAddressEvidence(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestHasAddressEvidenceIsMemoized guards the per-line hoist. isFalsePositive
// runs once per match and these are whole-line regexes, so evaluating them per
// match would put O(matches x line length) work back into the hot path -- the
// single-long-line shape streetFPContext exists to remove.
func TestHasAddressEvidenceIsMemoized(t *testing.T) {
	ctx := &streetFPContext{line: "Mailing address: 1420 May Street"}

	if ctx.addrEvidenceDone {
		t.Fatal("evidence must be computed lazily, not at construction")
	}
	first := ctx.hasAddressEvidence()
	if !ctx.addrEvidenceDone {
		t.Error("the memo flag was not set after the first call")
	}

	// Poison the cached value: a second call must return the CACHED result, not
	// recompute from the line.
	ctx.addrEvidence = !first
	if got := ctx.hasAddressEvidence(); got == first {
		t.Error("hasAddressEvidence recomputed instead of returning the memoized value")
	}
}

// TestIsSourceFileExtension pins the extension check. Requiring a real extension
// (rather than "any letter") is what distinguishes a code reference from an
// address whose space was omitted.
func TestIsSourceFileExtension(t *testing.T) {
	cases := []struct {
		rest string
		want bool
	}{
		// Real code references.
		{"go handler", true},
		{"py script", true},
		{"java build", true},
		{"ts", true},
		{"cpp:42", true},

		// Address continuations, not extensions.
		{"Suite 200", false},
		{"Apt 4", false},
		{"Unit 12", false},
		{"Ste 900", false},
		{"Floor 3", false},

		// The token must END at a non-word byte: "gopher" is not ".go".
		{"gopher Lane", false},
		{"pythonic Way", false},

		// Degenerate.
		{"", false},
		{" go", false},
		{".go", false},
	}

	for _, c := range cases {
		if got := isSourceFileExtension(c.rest); got != c.want {
			t.Errorf("isSourceFileExtension(%q) = %v, want %v", c.rest, got, c.want)
		}
	}
}
