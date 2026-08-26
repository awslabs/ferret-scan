// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import "testing"

// #460: the concatenated-SSN path was gated on `strings.Contains(originalPath, ".docx")`.
//
// That is a substring of the PATH, not the file's type, so it was wrong in both directions. The
// interesting part is which direction turned out to matter, because the issue proposed two fixes and
// MEASUREMENT rejected both of them.
//
// # What the path is for, measured rather than assumed
//
// Two adjacent fields each holding a bare 9-digit number, read back with --preprocess-only:
//
//	.docx  two <w:r> runs      -> "449874100130075728"    GLUED
//	.pptx  two <a:r> runs      -> "449874100 130075728"   space
//	.xlsx  two adjacent cells  -> "449874100\t130075728"  tab
//
// So Word run concatenation is the only extractor here that produces an 18-digit run from field
// adjacency. The issue's premise -- that "`.xlsx` extraction concatenates cells by construction" -- does
// not hold for this codebase, so widening to spreadsheets would add reach the rule cannot use.
//
// # Why the path was NOT removed, and why it was NOT ungated
//
// The issue's title proposed removing it ("0 findings on 7MB of real documents, 200 false ones on 38KB
// of logs") while its body argued the handling is right and only the gate is wrong. Both were tested:
//
//	forcing the gate ON, 3,000 real text/code/doc files (22MB)   145 -> 147 findings (+2, both false)
//	forcing the gate ON, one 125KB log with 2,000 18-digit runs     0 -> 3,114 findings
//
// So ungating is out: an 18-digit run is ordinary in a log (an id pair, an epoch pair) and couldBeSSN on
// both halves is far too weak to carry that load. But the path is not dead either -- Word run gluing is
// real and measured -- so removing it would lose a genuine shape.
//
// What is left is exactly the looseness: gate on the TYPE. After the change, the log and the 3,000-file
// corpus report identically to before (0 and 145), and the only behaviour that moves is a path that
// merely CONTAINS the substring.

// TestASubstringInThePathIsNotAType is the defect.
//
// Each of these is a file whose type has nothing to do with Word. The first four DID take the Word-only
// path on the parent, verified there: `strings.Contains(p, ".docx")` is true for each.
//
// The `docx-exports/` case is DEFENSIVE, not a reproduction, and the distinction is worth keeping
// straight: a directory named `docx-exports` has no dot before `docx`, so the old gate did not match it
// either. The issue listed it as an example of the looseness and it is not one. It is kept because a
// future gate written with `strings.Contains(p, "docx")` -- one character less -- would match it, and
// this test would then say so.
func TestASubstringInThePathIsNotAType(t *testing.T) {
	for _, p := range []string{
		"sheet.docx.csv",              // a CSV that was taking the docx path
		"report.docx.bak",             // a backup copy
		"/tmp/.docx/notes.txt",        // a directory literally named .docx
		"archive.docx.zip",            // a zip of one
		"/exports/docx-exports/a.csv", // defensive: never matched the old gate either
	} {
		t.Run(p, func(t *testing.T) {
			if gluesAdjacentFields(p) {
				t.Errorf("%q was treated as a Word document. Its extraction does not glue adjacent "+
					"fields, so the concatenated path has nothing real to find in it -- and on "+
					"log-shaped content that path produced 3,114 findings where the correct answer is 0.", p)
			}
		})
	}
}

// TestTheWordFormsAreStillAdmitted is the direction that must not break.
//
// Word run concatenation is the measured reason this path exists: two adjacent <w:r> runs each holding a
// 9-digit number extract as one 18-digit run, and that is a real document shape.
func TestTheWordFormsAreStillAdmitted(t *testing.T) {
	for _, p := range []string{
		"report.docx",
		"/a/b/report.docx",
		"REPORT.DOCX", // extension comparison is case-insensitive
		"macro.docm",  // the same format and the same extractor
		"MACRO.DOCM",
	} {
		t.Run(p, func(t *testing.T) {
			if !gluesAdjacentFields(p) {
				t.Errorf("%q was excluded. Word run concatenation is what the concatenated path reads, "+
					"and excluding it loses a real document shape.", p)
			}
		})
	}
}

// TestSpreadsheetsAndPresentationsAreNotWidenedInto records a deliberate, measured exclusion.
//
// Not an oversight: their extractors insert a tab and a space respectively, so an 18-digit run cannot
// arise there from field adjacency. Admitting them would extend the rule's reach to files where it can
// only be wrong. The legacy .doc is excluded for a different reason -- whether its OLE extraction glues
// has not been measured, and a gate is the wrong place to guess.
func TestSpreadsheetsAndPresentationsAreNotWidenedInto(t *testing.T) {
	for _, p := range []string{
		"book.xlsx", "book.xlsm", "deck.pptx", "deck.pptm",
		"legacy.doc", "legacy.xls", "legacy.ppt",
		"notes.txt", "data.csv", "app.log", "page.html", "doc.pdf",
	} {
		t.Run(p, func(t *testing.T) {
			if gluesAdjacentFields(p) {
				t.Errorf("%q was admitted to the concatenated path", p)
			}
		})
	}
}

// TestTheNarrowRuleItselfIsUnchanged pins findSSNsInConcatenatedNumbers, so a future change to the gate
// cannot be mistaken for a change to what the gate admits.
//
// Exactly 18 digits, split in half, both halves passing couldBeSSN. That restrictiveness is the only
// thing holding the rule back, which is precisely why it cannot be ungated.
func TestTheNarrowRuleItselfIsUnchanged(t *testing.T) {
	v := &Validator{}

	got := v.findSSNsInConcatenatedNumbers("employee ids 449874100130075728 end")
	if len(got) != 2 || got[0] != "449874100" || got[1] != "130075728" {
		t.Errorf("findSSNsInConcatenatedNumbers = %v, want both halves of the 18-digit run", got)
	}

	for _, line := range []string{
		"only 17 digits 44987410013007572 end",    // one short
		"nineteen digits 4498741001300757281 end", // one long
		"a nine digit 449874100 alone",            // the normal path's job
		"000000000000000000",                      // both halves rejected by couldBeSSN
	} {
		if m := v.findSSNsInConcatenatedNumbers(line); len(m) != 0 {
			t.Errorf("findSSNsInConcatenatedNumbers(%q) = %v, want none", line, m)
		}
	}
}
