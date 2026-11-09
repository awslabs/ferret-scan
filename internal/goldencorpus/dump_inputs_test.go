// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// goldenDumpDirEnv names the directory TestDumpInputs writes the corpus inputs into.
const goldenDumpDirEnv = "GOLDEN_DUMP_DIR"

// TestDumpInputs writes every golden-corpus input to disk, so a process outside this test binary can
// scan the same bytes: scripts/surface-parity.sh runs them through the host CLI, the host web UI, the
// container CLI and the container web UI and diffs the four (#907).
//
//	GOLDEN_DUMP_DIR=/abs/dir go test -count=1 -run '^TestDumpInputs$' ./internal/goldencorpus/
//
// Without the variable it skips, so `go test ./...` writes nothing. It is in the style of
// UPDATE_CHECK_DOCS=1: an explicit opt-in that materialises something the tests already hold.
//
// Layout, chosen so every input has a distinct path and keeps the extension that routes it:
//
//	<dir>/content/<case>.txt         one per Case; the corpus scans Case.Input in memory, so it has
//	                                 no file name of its own and .txt is the plain-text route
//	<dir>/file/<case>/<Filename>     one per FileCase, at its own Filename, which may hold a
//	                                 directory (file_nested_path) and which several cases share
//	                                 (contacts.docx), hence the per-case directory
//
// Nothing else is written. The case's Checks, preprocessor setting and budgets are deliberately NOT
// carried over: the surface-parity script scans every input with every check, preprocessors on and no
// budget, the same options on every surface, because what it compares is the surfaces, not the corpus
// snapshots. The in-process comparison that does mirror each case's options is
// internal/web/surface_parity_test.go.
func TestDumpInputs(t *testing.T) {
	dir := os.Getenv(goldenDumpDirEnv)
	if dir == "" {
		t.Skip(goldenDumpDirEnv + " is not set; nothing to write")
	}
	// A relative path would resolve against this package's directory, the working directory of
	// `go test`, and litter the source tree.
	if !filepath.IsAbs(dir) {
		t.Fatalf("%s=%q must be an absolute path", goldenDumpDirEnv, dir)
	}

	written := map[string]string{} // relative path -> case name, to refuse a collision
	write := func(caseName, rel string, data []byte) {
		t.Helper()
		rel = filepath.ToSlash(rel)
		if prev, dup := written[rel]; dup {
			t.Fatalf("cases %q and %q both map to %s", prev, caseName, rel)
		}
		written[rel] = caseName
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	for _, c := range Cases {
		write(c.Name, "content/"+c.Name+".txt", []byte(c.Input))
	}
	for _, fc := range FileCases {
		write(fc.Name, "file/"+fc.Name+"/"+fc.Filename, fc.Content)
	}

	if got, want := len(written), len(Cases)+len(FileCases); got != want {
		t.Fatalf("wrote %d inputs, want %d (one per case)", got, want)
	}
	names := make([]string, 0, len(written))
	for rel := range written {
		names = append(names, rel)
	}
	sort.Strings(names)
	t.Logf("wrote %d inputs (%d content, %d file) under %s; first %s, last %s",
		len(names), len(Cases), len(FileCases), dir, names[0], names[len(names)-1])
}
