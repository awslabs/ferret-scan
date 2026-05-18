// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"os"
	"path/filepath"
	"testing"

	"ferret-scan/internal/observability"
)

// TestCleanupEmptyDirectories_RemovesEmptiesKeepsNonEmpties guards the
// os.Root-based cleanup. Builds an output tree with a mix of empty and
// populated directories and asserts only the empty ones get removed.
func TestCleanupEmptyDirectories_RemovesEmptiesKeepsNonEmpties(t *testing.T) {
	base := t.TempDir()

	// Layout:
	//   base/empty1/
	//   base/empty2/
	//   base/keep/file.txt
	//   base/nested/empty/
	//   base/nested/keep/file.txt
	mustMkdir(t, filepath.Join(base, "empty1"))
	mustMkdir(t, filepath.Join(base, "empty2"))
	mustMkdir(t, filepath.Join(base, "keep"))
	mustMkdir(t, filepath.Join(base, "nested", "empty"))
	mustMkdir(t, filepath.Join(base, "nested", "keep"))
	mustWriteFile(t, filepath.Join(base, "keep", "file.txt"), "x")
	mustWriteFile(t, filepath.Join(base, "nested", "keep", "file.txt"), "x")

	osm := &OutputStructureManager{
		baseOutputDir: base,
		observer:      observability.NewStandardObserver(observability.ObservabilityMetrics, nil),
	}
	if err := osm.CleanupEmptyDirectories(); err != nil {
		t.Fatalf("CleanupEmptyDirectories error: %v", err)
	}

	// Empties should be gone.
	for _, gone := range []string{
		filepath.Join(base, "empty1"),
		filepath.Join(base, "empty2"),
		filepath.Join(base, "nested", "empty"),
	} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("expected %q to be removed, got err=%v", gone, err)
		}
	}

	// Populated directories must remain.
	for _, kept := range []string{
		filepath.Join(base, "keep"),
		filepath.Join(base, "keep", "file.txt"),
		filepath.Join(base, "nested"),
		filepath.Join(base, "nested", "keep", "file.txt"),
	} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("expected %q to still exist: %v", kept, err)
		}
	}

	// The base directory itself is preserved (the walk skips it).
	if _, err := os.Stat(base); err != nil {
		t.Errorf("baseOutputDir was removed; should be preserved: %v", err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
