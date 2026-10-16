// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPreCommitGateIsNotOpenedByAFileWideMarker pins the exit-code half of #785 at the
// binary: --pre-commit-mode with the shipped default (exit on HIGH) must block a HIGH
// credential whether or not an unrelated comment elsewhere in the file contains a word the
// secrets validator uses as a test or development marker.
//
// Before the fix the comment decided the exit code. "pinned to the latest image" classified
// the whole file "test" because "latest" contains "test", every candidate in the file took
// -25, the GitHub token fell from HIGH 93 to MEDIUM 68, and the gate -- which exits on HIGH
// only -- let the commit through: rc 0 on the marker file, rc 1 on the control. That is the
// gate failing OPEN on a word in a comment, which is the one direction a pre-commit hook
// must never fail in.
//
// Each marker file is paired with a control that differs only in the comment line, so a
// difference in exit codes can only be the comment's doing, and the control is required to
// block so the comparison cannot pass vacuously on two files that both report nothing.
func TestPreCommitGateIsNotOpenedByAFileWideMarker(t *testing.T) {
	bin := buildForCLIContract(t)
	dir := t.TempDir()

	// Assembled at runtime so a static scanner reading this source does not report it.
	pat := "ghp_" + "Q7mZ2vX9pL4kR8tB1nW6yC3hJ5dF0sG2aE7u"
	const value = "Zq8vTtq2Lm4pQ9yHgRrWw7Kz"

	cases := []struct {
		name, marker, control string
	}{
		{
			name:    "latest above a GitHub token",
			marker:  "# CI settings\n# pinned to the latest image\n# rotate quarterly\nGITHUB_TOKEN=" + pat + "\n",
			control: "# CI settings\n# see the wiki\n# rotate quarterly\nGITHUB_TOKEN=" + pat + "\n",
		},
		{
			name:    "latest above a password",
			marker:  "# Database settings\n# pinned to the latest image\n# rotate quarterly\npassword=" + value + "\n",
			control: "# Database settings\n# see the wiki\n# rotate quarterly\npassword=" + value + "\n",
		},
		{
			name:    "example.com hostname above a password",
			marker:  "# Database settings\n# see https://wiki.example.com/setup\n# rotate quarterly\npassword=" + value + "\n",
			control: "# Database settings\n# see the wiki\n# rotate quarterly\npassword=" + value + "\n",
		},
	}

	run := func(t *testing.T, name, content string) int {
		t.Helper()
		in := filepath.Join(dir, name)
		if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c := exec.Command(bin,
			"--file", in,
			"--checks", "SECRETS",
			"--config", os.DevNull,
			"--pre-commit-mode",
			"--no-color", "--quiet",
		)
		// Built from scratch, as the other contract tests do, so no FERRET_PRECOMMIT_EXIT_ON in
		// the developer's shell or the CI runner can change which band the gate exits on: this
		// test is about the shipped default.
		c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		_, _ = c.CombinedOutput()
		return c.ProcessState.ExitCode()
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rcControl := run(t, "control"+string(rune('a'+i))+".txt", tc.control)
			rcMarker := run(t, "marker"+string(rune('a'+i))+".txt", tc.marker)
			if rcControl == 0 {
				t.Fatalf("control file exited 0 in --pre-commit-mode; its credential is not HIGH, so this pairing proves nothing")
			}
			if rcMarker != rcControl {
				t.Errorf("--pre-commit-mode exited %d on the marker file and %d on the control; the two differ only in a comment line, so the gate failed open on a word in a comment",
					rcMarker, rcControl)
			}
		})
	}
}
