// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A named input that does not exist is a bad argument, and README "Exit codes" says bad arguments
// exit 1 with nothing produced (#728). Before this, the discovery loop classified the case as a
// usage error, printed "Error processing", and then exited 0 with an empty report — a CI step with
// a typo'd path passed green having examined nothing.
//
// The table pins BOTH directions: the typo fails, and every legitimate empty scan — an empty
// directory, a glob with no matches, the stdin alias — keeps exiting 0. A fix that made
// "nothing to scan" fatal would break "scan this directory if anything is in it" pipelines, which
// is why the validation is scoped to literal, nonexistent paths.
func TestANonexistentInputIsABadArgument(t *testing.T) {
	name := "ferret-scan-728"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	dir := t.TempDir()
	existing := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(existing, []byte("nothing sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist")

	run := func(stdin string, args ...string) (int, string) {
		cmd := exec.Command(bin, append(args, "--config", os.DevNull, "--format", "json")...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, _ := cmd.CombinedOutput()
		return cmd.ProcessState.ExitCode(), string(out)
	}

	for _, tc := range []struct {
		name     string
		stdin    string
		args     []string
		wantCode int
		wantMsg  string
	}{
		{"nonexistent literal path fails", "", []string{"--file", missing}, 1, "does not exist"},
		{"one missing among several fails before scanning", "", []string{existing, missing}, 1, missing},
		{"existing file (control)", "", []string{"--file", existing}, 0, ""},
		{"empty directory stays a legitimate empty scan", "", []string{"--file", empty}, 0, ""},
		{"zero-match glob stays a legitimate empty scan", "", []string{"--file", filepath.Join(dir, "*.pdf")}, 0, ""},
		{"stdin alias is not a filesystem path", "ssn 456-78-9012\n", []string{"--file", "-"}, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out := run(tc.stdin, tc.args...)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, tc.wantCode, out)
			}
			if tc.wantMsg != "" && !strings.Contains(out, tc.wantMsg) {
				t.Errorf("output does not name the problem (%q):\n%s", tc.wantMsg, out)
			}
		})
	}
}
