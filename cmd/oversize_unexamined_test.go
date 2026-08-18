// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// A file refused for being over the size limit must be COUNTED, and its treatment
// must follow from whether the tool could have processed its type.
//
// Before this, a size refusal reached no counter anywhere. Measured on a directory
// holding one 105MB file plus a small file with an SSN:
//
//	Files: 1 scanned | Findings: 1
//	total_files 1, files_skipped 0, files_not_examined absent
//	--fail-on-incomplete -> exit 0
//
// So the artifact described a complete, clean scan of a directory containing a file
// that was never opened. The only trace was a stderr line, which is exactly what CI
// discards when it redirects stdout to a report. See #324.
//
// The warning decision was also a hardcoded 11-extension list, duplicated at three
// call sites, so the tool was quiet about a few known-big binary types and noisy about
// everything else — including files it could never have scanned at any size, and
// including browser partial downloads whose random suffixes no list can cover.

// bigTextFile writes a sparse file over the limit whose FIRST 512 bytes are real text.
//
// The leading text has to fill more than the sniff window: Truncate extends with NULs,
// so a file with only a line or two of text sniffs as binary and the fixture silently
// tests the wrong branch.
func bigTextFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := f.WriteString("Quarterly report text content.\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

// bigOpaqueFile writes a sparse over-limit file of binary bytes with a random-suffix
// name, the browser-partial-download shape no extension list can match.
func bigOpaqueFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 600)); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

func pathsOf(entries []SkippedFile) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Base(e.Path))
	}
	return out
}

// All three discovery routes must agree: single file, glob, and recursive walk.
func TestOversizeProcessableFileIsUnexamined(t *testing.T) {
	routes := []struct {
		name  string
		input func(dir string) string
		rec   bool
	}{
		{"directory walk", func(dir string) string { return dir }, true},
		{"glob", func(dir string) string { return filepath.Join(dir, "*") }, false},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			dir := t.TempDir()
			bigTextFile(t, filepath.Join(dir, "big_report.txt"))
			bigOpaqueFile(t, filepath.Join(dir, ".com.brave.Browser.ABCdef"))
			small := filepath.Join(dir, "normal.txt")
			if err := os.WriteFile(small, []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			res, err := getFilesToProcess(route.input(dir), route.rec, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}

			// The small file is scanned.
			if len(res.FilesToProcess) != 1 || filepath.Base(res.FilesToProcess[0]) != "normal.txt" {
				t.Errorf("FilesToProcess = %v, want just normal.txt", res.FilesToProcess)
			}

			// The oversize TEXT file is a coverage loss: unexamined, with its own cause.
			var found *SkippedFile
			for i := range res.UnexaminedFiles {
				if filepath.Base(res.UnexaminedFiles[i].Path) == "big_report.txt" {
					found = &res.UnexaminedFiles[i]
				}
			}
			if found == nil {
				t.Fatalf("big_report.txt is not in UnexaminedFiles %v — a processable file "+
					"refused for size was expected to produce a result and did not, so it must "+
					"reach files_not_examined and --fail-on-incomplete",
					pathsOf(res.UnexaminedFiles))
			}
			if found.Cause != causeTooLarge {
				t.Errorf("cause = %v (%q), want causeTooLarge. The zero value is causeUnreadable, "+
					"which would claim the file could not be opened — a failure that did not happen",
					found.Cause, found.Cause.String())
			}
			if !strings.Contains(found.Reason, "too large") {
				t.Errorf("reason = %q, want it to say the file was too large", found.Reason)
			}
			// Payload-free: the reason reaches stderr and every machine format.
			if strings.Contains(found.Reason, "452-11-9384") {
				t.Errorf("reason %q leaked file content", found.Reason)
			}

			// The opaque binary is a genuine SKIP, and silent: nothing would have read
			// it at any size, so a warning would be noise about a non-event.
			var opaque *SkippedFile
			for i := range res.SkippedFiles {
				if strings.Contains(res.SkippedFiles[i].Path, "Browser") {
					opaque = &res.SkippedFiles[i]
				}
			}
			if opaque == nil {
				t.Fatalf("the opaque binary is not in SkippedFiles %v — it must still be "+
					"recorded so it stays in the denominator", pathsOf(res.SkippedFiles))
			}
			if !opaque.Silent {
				t.Error("the opaque binary produced a visible warning; no extension list can " +
					"ever cover random-suffix partial downloads, which is why the predicate " +
					"must be capability-derived")
			}
			for _, u := range res.UnexaminedFiles {
				if strings.Contains(u.Path, "Browser") {
					t.Error("the opaque binary was reported as unexamined; nothing would have " +
						"read it, so no coverage was lost")
				}
			}
		})
	}
}

// With preprocessors DISABLED, an oversize binary document is not a coverage loss:
// nothing would have read it either way.
func TestOversizeBinaryDocumentWithoutPreprocessorsIsASkip(t *testing.T) {
	dir := t.TempDir()
	// A .docx is a binary document: processable only with preprocessors.
	f, err := os.Create(filepath.Join(dir, "big.docx")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("PK\x03\x04")); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	withPre, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(withPre.UnexaminedFiles) != 1 {
		t.Errorf("with preprocessors: UnexaminedFiles = %v, want the .docx — its content "+
			"would have been extracted and scanned", pathsOf(withPre.UnexaminedFiles))
	}

	without, err := getFilesToProcess(dir, true, nil, nil, false)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(without.UnexaminedFiles) != 0 {
		t.Errorf("without preprocessors: UnexaminedFiles = %v, want none — nothing would "+
			"have read a .docx, so refusing it for size loses nothing",
			pathsOf(without.UnexaminedFiles))
	}
}

// Every cmd-side cause must map to a distinct formatter cause.
//
// causeNotFollowed had no case in the mapping switch and fell through to the
// conservative default, so machine formats said "cannot read" for every refused
// symlink while the text report said "symlink not followed" — a file the tool
// deliberately declined, reported as an I/O failure that never happened.
func TestEveryCauseMapsToItsOwnFormatterCause(t *testing.T) {
	cases := []struct {
		cause unscannedCause
		want  formatters.NotExaminedCause
	}{
		{causeUnreadable, formatters.NotExaminedUnreadable},
		{causeUnparseable, formatters.NotExaminedUnparseable},
		{causeNoText, formatters.NotExaminedNoText},
		{causeCutShort, formatters.NotExaminedCutShort},
		{causeNotFollowed, formatters.NotExaminedNotFollowed},
		{causeTooLarge, formatters.NotExaminedTooLarge},
	}

	seen := make(map[formatters.NotExaminedCause]unscannedCause, len(cases))
	for _, c := range cases {
		got := toFormatterNotExamined([]unscannedEntry{{Path: "f", Cause: c.cause, Detail: "d"}})
		if len(got) != 1 {
			t.Fatalf("cause %v produced %d entries", c.cause, len(got))
		}
		if got[0].Cause != c.want {
			t.Errorf("cause %v (%q) mapped to %q, want %q — an unmapped cause silently "+
				"becomes 'cannot read', asserting a failure that did not happen",
				c.cause, c.cause.String(), got[0].Cause.String(), c.want.String())
		}
		if prev, dup := seen[c.want]; dup {
			t.Errorf("formatter cause %q is used by both %v and %v; the two are "+
				"indistinguishable in every machine format", c.want.String(), prev, c.cause)
		}
		seen[c.want] = c.cause
		// The two sides must also agree on the wording, since an operator compares a
		// human report against a machine artifact from the same run.
		if c.cause.String() != c.want.String() {
			t.Errorf("wording differs: cmd says %q, formatter says %q",
				c.cause.String(), c.want.String())
		}
	}
}

// A refused symlink must keep its own cause through discovery. The cause now travels
// on SkippedFile, and the zero value is causeUnreadable, so a producer that forgets to
// set it silently mislabels the entry.
func TestSymlinkDisclosureCarriesItsCause(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "dangling.txt")
	if err := os.Symlink(filepath.Join(root, "nope.txt"), link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	d, resolved, reason := classifySymlink(link, root, 100*1024*1024)
	if d != symlinkDisclose {
		t.Fatalf("fixture: disposition = %v, want symlinkDisclose", d)
	}
	_, disclose := resolveSymlinkCandidates(
		[]symlinkCandidate{{linkPath: link, resolved: resolved, reason: reason, disp: d}}, nil)
	if len(disclose) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclose))
	}
	if disclose[0].Cause != causeNotFollowed {
		t.Errorf("cause = %v (%q), want causeNotFollowed. The zero value claims the link "+
			"could not be read, which is not what happened — the tool declined to follow it",
			disclose[0].Cause, disclose[0].Cause.String())
	}
}
