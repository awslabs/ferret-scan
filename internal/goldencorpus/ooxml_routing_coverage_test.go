// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"io"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// These tests protect the new OOXML corpus cases from the failure mode that made
// them necessary in the first place: a snapshot that is green because the code under
// test never ran.
//
// The corpus locks output, so it cannot tell "this scan examined the document body
// and found nothing" apart from "this scan never saw the document body". Both render
// as a small golden file. The assertions below check the PRECONDITION instead — that
// an Office fixture really does engage two extractors — so that when a later PR
// changes routing, the snapshot diff means something.

// TestOOXMLCasesReachTheCombinedArm is the guard. Every .docx/.xlsx case must be
// dual-extractor: that is the only arm where the FileRouter concatenates output with
// "--- name ---" separators and the ContentRouter re-splits it. A case that quietly
// drops to one extractor would still produce a stable snapshot while testing nothing.
//
// The specific way that happens is a path guard: the Office metadata extractor
// refuses paths under /var/, /tmp/, /home/ and C:\Users\, which is where t.TempDir()
// lives on all three CI platforms. caseTempDir exists to avoid it, and this test
// fails if that ever regresses.
func TestOOXMLCasesReachTheCombinedArm(t *testing.T) {
	var seen int
	for _, fc := range FileCases {
		if !needsGuardFreePath(fc.Filename) {
			continue
		}
		seen++
		fc := fc
		t.Run(fc.Name, func(t *testing.T) {
			dir := caseTempDir(t, fc)
			path := writeFixture(t, dir, fc)

			res, err := core.ScanFile(core.ScanConfig{
				FilePath:            path,
				Checks:              fc.Checks,
				EnablePreprocessors: fc.EnablePreprocessors,
				LogWriter:           io.Discard,
			})
			if err != nil {
				t.Fatalf("ScanFile: %v", err)
			}

			// A metadata finding proves the office_metadata extractor ran, which is
			// the extractor the path guard silently removes. Every OOXML case here
			// carries dc:creator, so its absence means the fixture never reached the
			// dual-extractor arm and the case is vacuous.
			var metaTypes []string
			for _, m := range res.Matches {
				switch m.Type {
				case "AUTHOR_INFO", "LAST_MODIFIED_BY", "COMPANY_INFO", "DOCUMENT_DESCRIPTION":
					metaTypes = append(metaTypes, m.Type)
				}
			}
			if len(metaTypes) == 0 {
				var got []string
				for _, m := range res.Matches {
					got = append(got, m.Type)
				}
				t.Fatalf("case %q produced no metadata finding, so the office_metadata "+
					"extractor did not run and this case never exercised the "+
					"combined_preprocessors arm it exists to lock.\n"+
					"  scanned path: %s\n"+
					"  finding types: %v\n"+
					"Most likely the fixture landed under a directory the Office extractor's "+
					"validateFilePath rejects (/var/, /tmp/, /home/, C:\\Users\\) — see caseTempDir.",
					fc.Name, path, got)
			}
		})
	}

	if seen == 0 {
		t.Fatal("no OOXML cases found in FileCases — this guard is vacuous; either a case " +
			"was removed or needsGuardFreePath no longer recognizes the extensions")
	}
}

// TestCaseTempDirAvoidsTheOfficePathGuard pins the helper's contract directly, so the
// reason for the repo-relative directory survives future refactoring. Without it, a
// well-meaning simplification back to t.TempDir() would make six corpus cases vacuous
// and nothing would fail.
func TestCaseTempDirAvoidsTheOfficePathGuard(t *testing.T) {
	ooxml := FileCase{Filename: "book.xlsx"}
	dir := caseTempDir(t, ooxml)

	lower := strings.ToLower(strings.ReplaceAll(dir, "\\", "/"))
	for _, bad := range []string{"/var/", "/tmp/", "/home/", "c:/users/"} {
		if strings.HasPrefix(lower, bad) {
			t.Errorf("caseTempDir returned %q for an OOXML case, which starts with the "+
				"rejected prefix %q; the Office metadata extractor will refuse it and the "+
				"case will silently lose a preprocessor", dir, bad)
		}
	}

	// And the plain-text path must NOT pay the cost of a repo-relative dir.
	plain := caseTempDir(t, FileCase{Filename: "notes.txt"})
	if plain == dir {
		t.Error("caseTempDir returned the same directory for a .txt and an .xlsx case")
	}
}
