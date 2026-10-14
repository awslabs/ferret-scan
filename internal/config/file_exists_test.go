// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #776: fileExists treated only "does not exist" as absence, so any other Stat error reached
// info.IsDir() on a nil FileInfo and panicked. Discovery stats candidates under the home directory
// on every run without --config, so a home the process could not traverse (EACCES) or one beneath
// a regular file (ENOTDIR) killed that run at exit 2. ENOTDIR stands in for both here: it fails
// the same way for every user, root included, where an EACCES setup is bypassed by root.
func TestFileExistsTreatsAnyStatErrorAsAbsent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("defaults: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"regular file", file, true},
		{"directory", dir, false},
		{"missing", filepath.Join(dir, "absent.yaml"), false},
		{"beneath a regular file", filepath.Join(file, "config.yaml"), false}, // panicked before #776
	} {
		if got := fileExists(tc.path); got != tc.want {
			t.Errorf("%s: fileExists(%s) = %v, want %v", tc.name, tc.path, got, tc.want)
		}
	}
}

// The same defect reached the way a run without --config reaches it.
func TestFindConfigFileSurvivesAnUnusableHome(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(blocker, "home")
	// Every variable a discovery candidate is derived from, on each platform.
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"} {
		t.Setenv(name, home)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("FERRET_CONFIG_DIR", "")
	t.Chdir(t.TempDir()) // no project config in the working directory

	if got := FindConfigFile(); strings.HasPrefix(got, blocker) {
		t.Errorf("FindConfigFile() = %s, a path beneath a regular file", got)
	}
}
