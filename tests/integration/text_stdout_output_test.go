// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runStdinEnv is runStdin with extra environment variables. The pre-commit exit
// policy is only reachable through FERRET_PRECOMMIT_EXIT_ON, so the blocking case
// below needs to set it for the child process.
func runStdinEnv(t *testing.T, bin, input string, extraEnv []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...) //nolint:gosec // bin is built by the test
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("unexpected exec error: %v\nstderr=%s", err, stderr.String())
		}
		exitCode = ee.ExitCode()
	}
	return stdout.String(), stderr.String(), exitCode
}

// The text formatter signals "I already wrote to StreamWriter" by returning an
// empty string, and main.go used to suppress its own Println whenever streaming
// was *requested* — regardless of whether the formatter had actually streamed
// anything. Format has several early returns that build a string and never touch
// StreamWriter, so every one of them was silently discarded: a clean scan, a scan
// whose findings were all filtered out by --confidence, and (worst) a pre-commit
// run that found blocking secrets, exited 1, and printed nothing at all.
//
// These tests drive the real binary, because the defect only exists at the
// main.go/formatter seam — the formatter's return values were always correct.

// scanFixtures writes the two fixtures the cases below share and returns the dir.
func scanFixtures(t *testing.T) (dir, clean, withPII string) {
	t.Helper()
	dir = t.TempDir()
	clean = filepath.Join(dir, "clean.txt")
	withPII = filepath.Join(dir, "pii.txt")
	if err := os.WriteFile(clean, []byte("nothing sensitive here at all\njust plain words\n"), 0o600); err != nil {
		t.Fatalf("write clean fixture: %v", err)
	}
	// A structurally valid SSN with a "SSN:" label, so it lands at medium
	// confidence — high enough to be a finding, low enough that --confidence
	// high filters it out (which exercises a second early return).
	if err := os.WriteFile(withPII, []byte("Employee SSN: 456-78-9012\n"), 0o600); err != nil {
		t.Fatalf("write pii fixture: %v", err)
	}
	return dir, clean, withPII
}

// TestTextStdoutPrintsNoMatchesFound is the plainest form of the bug: a clean
// file produced zero bytes on stdout, so a user could not tell a successful scan
// from a crashed one.
func TestTextStdoutPrintsNoMatchesFound(t *testing.T) {
	bin := stdinBinary(t)
	_, clean, _ := scanFixtures(t)

	stdout, stderr, code := runStdin(t, bin, "", "--file", clean, "--checks", "ssn", "--format", "text")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("a clean scan printed nothing to stdout (stderr=%s)", stderr)
	}
	if !strings.Contains(stdout, "No matches found") {
		t.Fatalf("stdout = %q, want it to report that no matches were found", stdout)
	}
}

// TestTextStdoutPrintsConfidenceFilteredNotice covers the second early return:
// findings existed but were all filtered out by --confidence. Reporting nothing
// here is actively misleading — it looks identical to a clean file, when in fact
// the file has PII that was merely below the requested threshold.
func TestTextStdoutPrintsConfidenceFilteredNotice(t *testing.T) {
	bin := stdinBinary(t)
	_, _, withPII := scanFixtures(t)

	stdout, stderr, code := runStdin(t, bin,
		"", "--file", withPII, "--checks", "ssn", "--format", "text", "--confidence", "high")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("a scan whose findings were all confidence-filtered printed nothing (stderr=%s)", stderr)
	}
	if !strings.Contains(stdout, "confidence") {
		t.Fatalf("stdout = %q, want it to mention the confidence filter", stdout)
	}
}

// TestPrecommitTextStdoutPrintsBlockingFindings is the severe case. With
// FERRET_PRECOMMIT_EXIT_ON=medium the run exits 1 and blocks the commit; before
// the fix it did so having printed zero bytes to both stdout and stderr, so the
// developer got a failed commit with no indication of what was found or where.
func TestPrecommitTextStdoutPrintsBlockingFindings(t *testing.T) {
	bin := stdinBinary(t)
	_, _, withPII := scanFixtures(t)

	stdout, stderr, code := runStdinEnv(t, bin, "",
		[]string{"FERRET_PRECOMMIT_EXIT_ON=medium"},
		"--file", withPII, "--checks", "ssn", "--format", "text", "--pre-commit-mode")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (a medium finding must block) stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("pre-commit blocked the commit but printed nothing to stdout (stderr=%s)", stderr)
	}
	if !strings.Contains(stdout, "pii.txt") {
		t.Fatalf("stdout = %q, want the offending file named", stdout)
	}
	if !strings.Contains(stdout, "line 1") {
		t.Fatalf("stdout = %q, want the offending line reported", stdout)
	}
}

// TestPrecommitTextStdoutSilentOnCleanScan pins the intended silence. Pre-commit
// mode deliberately prints nothing when there is nothing to report, and the fix
// must not turn that into noise on every commit.
func TestPrecommitTextStdoutSilentOnCleanScan(t *testing.T) {
	bin := stdinBinary(t)
	_, clean, _ := scanFixtures(t)

	stdout, stderr, code := runStdin(t, bin, "",
		"--file", clean, "--checks", "ssn", "--format", "text", "--pre-commit-mode")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("pre-commit mode should be silent on a clean scan, got stdout=%q", stdout)
	}
}

// TestTextStdoutStreamsFindingsExactlyOnce is the anti-double-print guard. The
// streaming path is the one case where the formatter really does write to stdout
// itself, so printing the (empty) return value on top of it must not duplicate
// the report — and the header must appear exactly once.
func TestTextStdoutStreamsFindingsExactlyOnce(t *testing.T) {
	bin := stdinBinary(t)
	_, _, withPII := scanFixtures(t)

	stdout, stderr, code := runStdin(t, bin, "", "--file", withPII, "--checks", "ssn", "--format", "text")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
	}
	if n := strings.Count(stdout, "VALIDATOR"); n != 1 {
		t.Fatalf("table header appears %d times, want exactly 1:\n%s", n, stdout)
	}
	if n := strings.Count(stdout, "Scan Summary"); n != 1 {
		t.Fatalf("scan summary appears %d times, want exactly 1:\n%s", n, stdout)
	}
	if !strings.Contains(stdout, "SSN") {
		t.Fatalf("stdout = %q, want the SSN finding reported", stdout)
	}
}

// TestTextFileOutputUnaffected pins the --output path, which never streamed and
// must be byte-for-byte what it always was.
func TestTextFileOutputUnaffected(t *testing.T) {
	bin := stdinBinary(t)
	dir, clean, _ := scanFixtures(t)
	out := filepath.Join(dir, "report.txt")

	stdout, stderr, code := runStdin(t, bin, "",
		"--file", clean, "--checks", "ssn", "--format", "text", "--output", out)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("writing to --output should leave stdout empty, got %q", stdout)
	}
	body, err := os.ReadFile(out) //nolint:gosec // path is from t.TempDir()
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(body), "No matches found") {
		t.Fatalf("output file = %q, want the no-matches report", body)
	}
}

// TestNonTextFormatsUnaffected walks every other formatter to prove none of them
// gained or lost output. They never set StreamWriter, so they always went through
// the Println branch — but the branch condition changed, so pin them.
func TestNonTextFormatsUnaffected(t *testing.T) {
	bin := stdinBinary(t)
	_, _, withPII := scanFixtures(t)

	for _, format := range []string{"json", "csv", "yaml", "junit", "gitlab-sast", "sarif"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, code := runStdin(t, bin, "",
				"--file", withPII, "--checks", "ssn", "--format", format)
			if code != 0 {
				t.Fatalf("exit code = %d, want 0 (stderr=%s)", code, stderr)
			}
			if strings.TrimSpace(stdout) == "" {
				t.Fatalf("format %s printed nothing to stdout (stderr=%s)", format, stderr)
			}
		})
	}
}
