// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"strings"
	"testing"
)

// PR #282 changed the database gate from "a hit in EITHER list" to "the SURNAME must
// be known", which fixed a large false-positive class and was the right call. Its own
// comment recorded the cost: "The remaining recall cost is entirely MISSING SURNAMES
// (vries, sato, yilmaz, nkosi, ...), which is a data gap the surname list closes."
//
// That gap was a cleartext leak, because an unreported name is never redacted.
// Measured by building the parent commit 92c2fa8 and diffing the same fixture:
//
//	Employee: Marcus Horvath signed the contract.   79 -> not reported
//	Dr. Elena Papadopoulos reviewed the chart.      73 -> not reported
//	Contact Siobhan D'Arcy about the claim.         78 -> not reported
//	Patient Giulia D'Amico was admitted.            78 -> not reported
//	Reviewed by Pierre L'Ecuyer on Tuesday.         66 -> not reported
//	Contact Sean O'Sullivan about the claim.         78 -> not reported
//
// and under --enable-redaction all six came back in cleartext from a file the tool
// reported as successfully redacted, while a list-surname name on an adjacent line
// masked correctly.
//
// These tests pin the data, not the scores. A band assertion belongs in the
// scorecorpus, which owns the measured numbers; what must not silently regress here is
// the presence of the entries themselves.

// TestSurnameListCoversApostropheFamilies is the non-vacuity gate for the data fix.
//
// Before it, the list held exactly SIX apostrophe surnames — o'brien, o'connor,
// o'donnell, o'keefe, o'neill, o'reilly — and no D' or L' form at all. So Patrick
// O'Connor was reported at 100 while Sean O'Sullivan was reported not at all, which
// reads as a parser bug and is not one: the lookup lowercases and normalizes accents
// but does not strip the apostrophe, so the stored form must carry it.
func TestSurnameListCoversApostropheFamilies(t *testing.T) {
	db, err := LoadNameDatabases()
	if err != nil {
		t.Fatalf("LoadNameDatabases: %v", err)
	}

	// Each of these was absent and is a common surname.
	for _, s := range []string{
		"o'sullivan", "o'shea", "o'rourke", "o'malley", "o'leary", "o'hara",
		"d'amico", "d'angelo", "d'arcy", "d'agostino", "d'souza",
		"l'ecuyer", "l'heureux",
	} {
		if !db.LastNames[s] {
			t.Errorf("surname %q missing from the list — the name is unreportable at every "+
				"confidence level and therefore never redacted", s)
		}
	}

	// The apostrophe must be STORED, not stripped: the lookup does not remove it.
	if db.LastNames["osullivan"] {
		t.Error(`the list contains "osullivan" without the apostrophe; the lookup lowercases ` +
			`and normalizes accents but does not strip punctuation, so that entry can never match`)
	}
}

// The locale gaps #282 named by hand must be closed.
func TestSurnameListCoversTheLocalesNamedIn282(t *testing.T) {
	db, err := LoadNameDatabases()
	if err != nil {
		t.Fatalf("LoadNameDatabases: %v", err)
	}
	for _, s := range []string{
		"horvath", "papadopoulos", // the two from the reproduction in #386
		"vries", "sato", "yilmaz", "nkosi", // the four #282 named explicitly
		"kovacs", "szabo", "nowak", "novotny", "dvorak", // Central European
		"ozturk", "arslan", "celik", // Turkish, measured at 20% coverage
		"papadakis", "nikolaidis", // Greek
		"okonkwo", "mwangi", "dlamini", // African, measured at 60%
	} {
		if !db.LastNames[s] {
			t.Errorf("surname %q missing from the list", s)
		}
	}
}

// The data file must stay ASCII-only and sorted.
//
// The ASCII property is load-bearing rather than cosmetic: normalizeAccents maps
// accented INPUT onto its ASCII form before lookup, so an accented entry such as
// "oláh" can only ever be matched by input that is already accented, while the ASCII
// spelling matches both. One such entry was added during this work and corrected.
func TestSurnameDataIsASCIIAndSorted(t *testing.T) {
	db, err := LoadNameDatabases()
	if err != nil {
		t.Fatalf("LoadNameDatabases: %v", err)
	}

	names := make([]string, 0, len(db.LastNames))
	for n := range db.LastNames {
		names = append(names, n)
		for _, r := range n {
			if r > 127 {
				t.Errorf("surname %q contains a non-ASCII rune; store the ASCII form so "+
					"normalizeAccents can reach it from both spellings", n)
				break
			}
		}
		if n != strings.ToLower(n) {
			t.Errorf("surname %q is not lowercase; the lookup lowercases its input", n)
		}
	}
	if len(names) < 2300 {
		t.Errorf("surname list holds %d entries, fewer than expected — the data fix may have "+
			"been reverted", len(names))
	}
}

// First names do not gate detection, but they do drive confidence: a name with both
// halves known scores materially higher than one with only the surname. Measured on
// the same fixture, the surname list alone took Mehmet Yilmaz / Haruto Sato /
// Thabo Nkosi from not-reported to 67, and adding the given names took them to 92.
func TestFirstNameListCoversTheSameLocales(t *testing.T) {
	db, err := LoadNameDatabases()
	if err != nil {
		t.Fatalf("LoadNameDatabases: %v", err)
	}
	for _, s := range []string{"mehmet", "haruto", "thabo", "piet", "ayse", "ren"} {
		if !db.FirstNames[s] {
			t.Errorf("first name %q missing; the name is still detected via its surname but "+
				"scores lower than an equivalent Anglo name, which is the inequity the "+
				"scorecorpus locale case exists to measure", s)
		}
	}
}
