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

// Exit-code semantics for files the tool could not examine, driven through the real
// binary because exit codes are a CLI contract, not a library one.
//
// The matrix measured on main before these fixes, in pre-commit mode:
//
//	scenario                    rc   output
//	clean                       0    (silent)
//	UNREADABLE, no findings     0    ZERO BYTES on stdout AND stderr
//	corrupt, no findings        2
//	MEDIUM finding              0    (default blocks on high only)
//
// Two defects there. An unreadable file and a corrupt one mean the same thing —
// the contents were never seen — yet produced different codes, because the old
// `hasErrors` was len(supportedFiles)-processedFiles and an unreadable file never
// enters supportedFiles. And the unreadable case was byte-for-byte identical to a
// clean pass, so a hook let the commit through with no stated reason (the #193
// shape).
//
// Exit code 2 is documented as "the tool failed". A file it could not read is a
// coverage gap, which is code 3, so the two no longer contend for one code.

func buildForExitTest(t *testing.T) string {
	t.Helper()
	name := "ferret-scan-exit-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

type exitRun struct {
	rc     int
	stdout string
	stderr string
}

func runForExit(t *testing.T, bin, dir string, env []string, extra ...string) exitRun {
	t.Helper()
	args := append([]string{
		"--file", dir, "--recursive", "--config", os.DevNull,
		"--checks", "SSN", "--limit", "0", "--enable-preprocessors",
	}, extra...)

	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()

	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	return exitRun{rc, so.String(), se.String()}
}

// scenarioDir builds a one-file directory for each shape.
func scenarioDir(t *testing.T, kind string) string {
	t.Helper()
	dir := t.TempDir()
	switch kind {
	case "clean":
		write(t, dir, "a.txt", "nothing sensitive at all\n", false)
	case "unreadable":
		write(t, dir, "a.txt", "SSN 130-07-5728\n", true)
	case "corrupt":
		write(t, dir, "a.docx", "PK\x03\x04truncated-not-a-zip", false)
	case "finding":
		write(t, dir, "a.csv", "ssn\n130-07-5728\n", false)
	default:
		t.Fatalf("unknown scenario %q", kind)
	}
	return dir
}

func write(t *testing.T, dir, name, body string, unreadable bool) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if unreadable {
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	}
}

// TestUnexaminedFilesGetOneExitCode — unreadable and corrupt must agree.
func TestUnexaminedFilesGetOneExitCode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o000 file is still readable")
	}
	if runtime.GOOS == "windows" {
		t.Skip("windows does not enforce POSIX mode bits for the unreadable case")
	}
	bin := buildForExitTest(t)

	for _, mode := range []struct {
		name string
		env  []string
	}{
		{"normal", nil},
		{"pre-commit", []string{"PRE_COMMIT=1"}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			unreadable := runForExit(t, bin, scenarioDir(t, "unreadable"), mode.env, "--fail-on-incomplete")
			corrupt := runForExit(t, bin, scenarioDir(t, "corrupt"), mode.env, "--fail-on-incomplete")

			if unreadable.rc != corrupt.rc {
				t.Errorf("unreadable exits %d but corrupt exits %d. Both mean the contents "+
					"were never seen, so an operator cannot act differently on them; the split "+
					"came from a counter that skipped unreadable files, not from a decision.",
					unreadable.rc, corrupt.rc)
			}
			if unreadable.rc != 3 {
				t.Errorf("unexamined file exits %d under --fail-on-incomplete, want 3. Code 2 "+
					"means the TOOL failed; an input it could not read is a coverage gap.",
					unreadable.rc)
			}
		})
	}
}

// TestPrecommitNeverSilentAboutUnexaminedFiles — the #193 shape.
func TestPrecommitNeverSilentAboutUnexaminedFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("cannot make a file unreadable in this environment")
	}
	bin := buildForExitTest(t)

	got := runForExit(t, bin, scenarioDir(t, "unreadable"), []string{"PRE_COMMIT=1"})

	if len(got.stdout)+len(got.stderr) == 0 {
		t.Fatalf("pre-commit produced ZERO bytes on both streams (rc=%d) for a file it "+
			"could not read. That is byte-identical to a clean pass, so the commit is "+
			"allowed and nothing says why.", got.rc)
	}
	combined := strings.ToLower(got.stdout + got.stderr)
	if !strings.Contains(combined, "not examined") {
		t.Errorf("pre-commit output does not say the file was not examined:\nstdout=%q\nstderr=%q",
			got.stdout, got.stderr)
	}
}

// TestCleanScanStaysSilentAndZero — the control.
//
// Without this, a change that made EVERY scan report an unexamined file would
// satisfy the two tests above and look correct.
func TestCleanScanStaysSilentAndZero(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)

	got := runForExit(t, bin, scenarioDir(t, "clean"), []string{"PRE_COMMIT=1"}, "--fail-on-incomplete")
	if got.rc != 0 {
		t.Errorf("a clean scan exited %d, want 0 (stderr: %q)", got.rc, got.stderr)
	}
	if strings.Contains(strings.ToLower(got.stdout+got.stderr), "not examined") {
		t.Errorf("a clean scan claimed files were not examined:\nstdout=%q\nstderr=%q",
			got.stdout, got.stderr)
	}
}
