// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests lock the library-surface wiring of the live-bytes admission
// budget (v2 gap 2.3): ScanConfig.MaxLiveBytes must reach the worker pool's
// JobConfig, and a set budget must not change which findings are produced (it
// only sequences in-memory admission). This is the in-process embedder path
// (e.g. a Lambda handler), distinct from the CLI --max-live-bytes flag.

func writeScanFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// baseScanConfig returns a ScanConfig for a single file with output silenced.
func baseScanConfig(path string) ScanConfig {
	return ScanConfig{
		FilePath:            path,
		Checks:              []string{"EMAIL", "SSN"},
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	}
}

// TestScanFile_MaxLiveBytes_FindingsUnchanged proves that setting MaxLiveBytes
// does not alter the findings for a file scan: the same input yields the same
// matches with the budget disabled (0) and with a tight budget set. The budget
// only bounds concurrent memory; it must never change detection output.
func TestScanFile_MaxLiveBytes_FindingsUnchanged(t *testing.T) {
	dir := t.TempDir()
	body := "contact alice@example.com and bob@test.org\nSSN 123-45-6789\n"
	path := writeScanFile(t, dir, "sample.txt", body)

	// Disabled (historical behavior).
	cfgOff := baseScanConfig(path)
	resOff, err := ScanFile(cfgOff)
	if err != nil {
		t.Fatalf("scan with budget off failed: %v", err)
	}

	// Tight budget (smaller than the content) — a single file always runs
	// (oversized-item guard), so findings must be identical.
	cfgOn := baseScanConfig(path)
	cfgOn.MaxLiveBytes = 8 // bytes; far below the file size
	resOn, err := ScanFile(cfgOn)
	if err != nil {
		t.Fatalf("scan with tight budget failed: %v", err)
	}

	if len(resOff.Matches) != len(resOn.Matches) {
		t.Fatalf("match count changed with MaxLiveBytes set: off=%d on=%d",
			len(resOff.Matches), len(resOn.Matches))
	}
	if len(resOff.Matches) == 0 {
		t.Fatal("expected findings in the sample (email/SSN); got none — test input is wrong")
	}

	// Compare the match sets by (Type, Text) so ordering differences don't cause
	// a false failure.
	offSet := matchKeySet(resOff)
	onSet := matchKeySet(resOn)
	for k := range offSet {
		if !onSet[k] {
			t.Errorf("finding %q present without budget but missing with budget", k)
		}
	}
	for k := range onSet {
		if !offSet[k] {
			t.Errorf("finding %q present with budget but missing without", k)
		}
	}
}

// matchKeySet renders a result's matches as a set of stable keys.
func matchKeySet(r *ScanResult) map[string]bool {
	set := make(map[string]bool, len(r.Matches))
	for _, m := range r.Matches {
		set[m.Type+"|"+m.Text] = true
	}
	return set
}

// TestScanFile_MaxLiveBytes_OversizedFileStillScans confirms the deadlock guard
// at the library surface: a file larger than the entire budget is still scanned
// (it runs alone) rather than hanging.
func TestScanFile_MaxLiveBytes_OversizedFileStillScans(t *testing.T) {
	dir := t.TempDir()
	body := "email carol@example.net here\n"
	path := writeScanFile(t, dir, "big.txt", body)

	cfg := baseScanConfig(path)
	cfg.MaxLiveBytes = 1 // one byte — the file is larger; must still run alone

	res, err := ScanFile(cfg)
	if err != nil {
		t.Fatalf("oversized-vs-budget file should still scan, got error: %v", err)
	}
	if len(res.Matches) == 0 {
		t.Error("expected the email finding; oversized-item guard did not admit the file")
	}
}
