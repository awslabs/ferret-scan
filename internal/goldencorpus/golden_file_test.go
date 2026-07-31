// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestGoldenFileScanFormats locks the scan->format output for FILE-based cases,
// scanned through the real core.ScanFile path (worker pool + FileRouter +
// dual-path routing) — the machinery core.ScanContent skips. This is the
// coverage Phase 2 (bridge-stack collapse) most needs, since the metadata /
// dual-path branch has no other golden coverage.
func TestGoldenFileScanFormats(t *testing.T) {
	for _, fc := range FileCases {
		fc := fc
		t.Run(fc.Name, func(t *testing.T) {
			tmpDir := caseTempDir(t, fc)
			path := writeFixture(t, tmpDir, fc) // forward-slash scan path

			res, err := core.ScanFile(core.ScanConfig{
				FilePath:            path,
				Checks:              fc.Checks,
				EnablePreprocessors: fc.EnablePreprocessors,
				LogWriter:           io.Discard, // payload-free; also keeps test output clean
			})
			if err != nil {
				t.Fatalf("ScanFile for case %q: %v", fc.Name, err)
			}

			matches := CanonicalSort(res.Matches)

			opts := formatters.FormatterOptions{
				ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
				NoColor:         true,
				ShowMatch:       true,
			}

			for _, format := range goldenFormats {
				out, err := formatFresh(t, format, matches, opts)
				if err != nil {
					t.Fatalf("format(%s) for case %q: %v", format, fc.Name, err)
				}
				// Path-normalize FIRST (raw temp path → <TMPDIR>), then the
				// generic timestamp/JSON canonicalization. Use the forward-slash
				// form of tmpDir to match the "/"-normalized scan path.
				got := NormalizeOutput(format, NormalizePaths(out, filepath.ToSlash(tmpDir)))
				checkGolden(t, fc.Name+"."+formatExt(format), got)
			}
		})
	}
}

// TestFileContentParity asserts that for plain-text/source inputs the file path
// (ScanFile) produces the SAME findings as the in-memory path (ScanContent) for
// identical bytes. This is the load-bearing invariant for the v2 consolidation:
// the worker-pool / FileRouter machinery must not change WHICH matches a
// document-body validator produces. (Metadata-bearing cases are excluded via
// Tier1Parity=false, since the file path legitimately adds the metadata branch.)
func TestFileContentParity(t *testing.T) {
	for _, fc := range FileCases {
		if !fc.Tier1Parity {
			continue
		}
		fc := fc
		t.Run(fc.Name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := writeFixture(t, tmpDir, fc)

			fileRes, err := core.ScanFile(core.ScanConfig{
				FilePath:  path,
				Checks:    fc.Checks,
				LogWriter: io.Discard,
			})
			if err != nil {
				t.Fatalf("ScanFile: %v", err)
			}

			contentRes, err := core.ScanContent(string(fc.Content), core.ContentScanConfig{
				VirtualPath: fc.Filename,
				Checks:      fc.Checks,
			})
			if err != nil {
				t.Fatalf("ScanContent: %v", err)
			}

			fileKeys := matchKeys(fileRes.Matches)
			contentKeys := matchKeys(contentRes.Matches)

			if len(fileKeys) != len(contentKeys) {
				t.Fatalf("parity mismatch: ScanFile produced %d findings, ScanContent produced %d\n  file:    %v\n  content: %v",
					len(fileKeys), len(contentKeys), fileKeys, contentKeys)
			}
			for i := range fileKeys {
				if fileKeys[i] != contentKeys[i] {
					t.Errorf("parity mismatch at %d:\n  file=%q\n  content=%q", i, fileKeys[i], contentKeys[i])
				}
			}
		})
	}
}

// writeFixture writes a FileCase's content into tmpDir under its basename and
// returns the path to scan, FORWARD-SLASH normalized (filepath.ToSlash).
//
// Why forward slashes: the text formatter's getSmartFilename and the path
// rendering in several formatters split on "/" only, so a native Windows path
// (with "\") renders differently than a Unix path — which would make the
// committed golden snapshots OS-dependent. Go's file APIs accept "/" on Windows
// too, so scanning a forward-slash path reads the same file while giving every
// OS identical formatter output. (This sidesteps a real getSmartFilename
// Windows-path quirk in product code; fixing that formatter is out of scope for
// the golden harness.)
func writeFixture(t *testing.T, tmpDir string, fc FileCase) string {
	t.Helper()
	nativePath := filepath.Join(tmpDir, fc.Filename) // native separators for the write
	if err := os.WriteFile(nativePath, fc.Content, 0o644); err != nil {
		t.Fatalf("write fixture %q: %v", fc.Filename, err)
	}
	return filepath.ToSlash(nativePath) // "/"-normalized path for the scan
}

// caseTempDir returns the directory a case's fixture is written to: t.TempDir()
// for every case.
//
// It used to hand OOXML cases a repo-relative directory instead, and the OOXML
// tests used to skip entirely on a checkout under /home/. Both existed to work
// around the Office metadata extractor's system-directory denylist, which refused
// /var/, /tmp/, /home/ and C:\Users\ — i.e. wherever t.TempDir() lives on every
// platform, and on GitHub's Linux runners the checkout itself. An Office fixture
// under a refused path silently lost the office_metadata extractor and the case
// recorded a scan that skipped the code under test.
//
// That denylist is gone (meta-extract-officelib/office-extractor.go
// validateFilePath), so a temp dir works everywhere and the six OOXML cases are
// real assertions on all three platforms instead of platform-dependent skips.
// TestOOXMLCasesReachTheCombinedArm still checks the precondition every run, so a
// regression that re-broke extraction under temp paths would fail rather than skip.
func caseTempDir(t *testing.T, _ FileCase) string {
	t.Helper()
	return t.TempDir()
}

// needsGuardFreePath reports whether a fixture is an OOXML container, and so
// routes through BOTH the text and Office metadata extractors — the
// dual-preprocessor arm the OOXML cases exist to lock.
func needsGuardFreePath(filename string) bool {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm":
		return true
	}
	return false
}

// matchKeys reduces a match slice to a sorted, path-independent identity list
// (validator|type|line|confidence|text). It deliberately excludes Filename so
// the file-vs-content comparison is not defeated by the differing source label.
func matchKeys(matches []detector.Match) []string {
	sorted := CanonicalSort(matches)
	keys := make([]string, 0, len(sorted))
	for _, m := range sorted {
		keys = append(keys, m.Validator+"|"+m.Type+"|"+itoa(m.LineNumber)+"|"+formatConf(m.Confidence)+"|"+m.Text)
	}
	return keys
}
