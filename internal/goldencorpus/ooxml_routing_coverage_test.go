// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"io"
	"path/filepath"
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
// The specific way that happened was a path guard: the Office metadata extractor
// refused paths under /var/, /tmp/, /home/ and C:\Users\, which is where t.TempDir()
// lives on all three CI platforms. That guard is gone, so this test now runs
// everywhere instead of skipping — and it is what fails if the guard, or anything
// else that costs a fixture its second extractor, comes back.
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

// TestOfficeMetadataWorksUnderATempPath pins the fix that let the tests above stop
// skipping: an Office fixture written to an ordinary temp directory must still get
// Office metadata extraction.
//
// It asserts the user-facing property directly rather than the shape of a path
// list. The old guard refused /var/, /tmp/, /home/ and C:\Users\, which is both
// where t.TempDir() resolves on every platform and — more importantly — where all
// of a Linux user's own files live: `ferret-scan --file ~/report.docx` lost
// metadata extraction with no error shown. Measured on this fixture with the
// pre-fix binary: 2 findings at a temp path versus 4 at an allowed one, the two
// missing ones being the metadata fields.
//
// This is deliberately a separate assertion from the corpus snapshots. A future
// change that re-introduced any location-dependent refusal would make six cases
// quietly cover less; this fails outright and names the reason.
func TestOfficeMetadataWorksUnderATempPath(t *testing.T) {
	dir := t.TempDir()
	lower := strings.ToLower(filepath.ToSlash(dir))
	if !strings.HasPrefix(lower, "/var/") && !strings.HasPrefix(lower, "/tmp/") &&
		!strings.HasPrefix(lower, "/home/") && !strings.Contains(lower, ":/users/") {
		t.Skipf("t.TempDir() returned %q, which is not under any of the roots the old "+
			"guard refused, so this platform cannot exercise the regression", dir)
	}

	fc := FileCase{
		Filename: "guard_probe.docx",
		Checks:   []string{"SSN", "METADATA"},
		Content: BuildDOCX("Jane Analyst", "Ops Reviewer", []string{
			"Employee SSN 449-87-4100 on file.",
		}),
		EnablePreprocessors: true,
	}
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

	var sawMeta, sawBody bool
	var got []string
	for _, m := range res.Matches {
		got = append(got, m.Type)
		switch m.Type {
		case "AUTHOR_INFO", "LAST_MODIFIED_BY":
			sawMeta = true
		case "SSN":
			sawBody = true
		}
	}
	if !sawBody {
		t.Errorf("no SSN finding from a fixture at %s; the document body was not scanned. types=%v", dir, got)
	}
	if !sawMeta {
		t.Errorf("no metadata finding from a fixture at %s, so the Office metadata extractor "+
			"refused this path. That is the guard this PR removed: every file a Linux user owns "+
			"is under /home/, so it silently dropped author/company/custom properties from every "+
			"scan. types=%v", dir, got)
	}
}
