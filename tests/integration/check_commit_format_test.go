// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scripts/check-commit-format.sh is the check docs/CONVENTIONAL_COMMITS.md tells contributors to
// run before they push, and it could not fail. Three separate defects:
//
//   - A subject that broke the format printed ❌ and the script still exited 0.
//   - `git log --pretty=format:` SEPARATES entries with a newline instead of terminating them, so
//     the last line of output, the range's oldest commit, had none and `while read` skipped it.
//     The default range, HEAD~1..HEAD, holds exactly one commit, so a default run checked nothing.
//   - git log ran at the head of a pipeline, so the loop at its tail decided the exit status, and a
//     range git could not read (a typo, or HEAD~1 in a one-commit or shallow clone) passed.
//
// Like the version-helper test beside it, each case builds a scratch repository and runs the real
// script against it. The script is executed directly, the way the docs and the Makefile run it.
func TestCheckCommitFormatChecksEveryCommitAndFailsOnABadOne(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("drives a bash script; contributors run it from a POSIX shell")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "check-commit-format.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script not found: %v", err)
	}

	const (
		good = "fix(scope): a conforming subject"
		bad  = "Update some things"
		// The per-commit verdict lines the script prints.
		validVerdict   = "Valid conventional commit format"
		invalidVerdict = "Invalid format"
	)

	cases := []struct {
		name        string
		subjects    []string // committed oldest first, on top of a conforming seed commit
		merge       bool     // finish with a git-generated merge of a one-commit side branch
		args        []string // script arguments; nil runs the default range
		wantExit    int
		wantValid   int // commits the script reports as valid
		wantInvalid int // commits the script reports as invalid
	}{
		{"the default range checks the last commit", []string{good}, false, nil, 0, 1, 0},
		{"the default range fails on a bad last commit", []string{bad}, false, nil, 1, 0, 1},
		{"a bad oldest commit in a range fails", []string{bad, good, good}, false, []string{"HEAD~3..HEAD"}, 1, 2, 1},
		{"every commit in a clean range is checked", []string{good, good, good}, false, []string{"HEAD~3..HEAD"}, 0, 3, 0},
		// HEAD~1..HEAD is then the merge plus the side branch's commit. The merge's subject is
		// git's ("Merge branch 'side'"), and scripts/version-helper.sh reads commit types with
		// --no-merges, so the check skips merges too.
		{"a merge commit is skipped, the merged commit is not", []string{good}, true, []string{"HEAD~1..HEAD"}, 0, 1, 0},
		{"an unreadable range is an error", []string{good}, false, []string{"no-such-ref..HEAD"}, 2, 0, 0},
		{"the default range in a one-commit clone is an error", nil, false, nil, 2, 0, 0},
		{"an empty range passes", []string{good}, false, []string{"HEAD..HEAD"}, 0, 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := append(os.Environ(),
				"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
				"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
				// The script must read THIS repo, unaffected by the caller's git configuration.
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			)
			git := func(args ...string) {
				cmd := exec.Command("git", args...)
				cmd.Dir = dir
				cmd.Env = env
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v: %v\n%s", args, err, out)
				}
			}
			commit := func(subject string) { git("commit", "-q", "--allow-empty", "-m", subject) }

			git("init", "-q", "-b", "main")
			commit("chore: seed")
			for _, s := range tc.subjects {
				commit(s)
			}
			if tc.merge {
				git("checkout", "-q", "-b", "side", "HEAD~1")
				// A subject of its own: an empty commit with main's last subject, parent and
				// timestamp would be main's last commit, byte for byte, and nothing would merge.
				commit("fix(side): a conforming subject on a side branch")
				git("checkout", "-q", "main")
				git("merge", "-q", "--no-ff", "--no-edit", "side")
				git("rev-parse", "-q", "--verify", "HEAD^2") // fails unless HEAD is a merge
			}

			cmd := exec.Command(script, tc.args...)
			cmd.Dir = dir
			cmd.Env = env
			raw, err := cmd.CombinedOutput()
			out := string(raw)
			exit := 0
			if err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("running the script: %v\n%s", err, out)
				}
				exit = ee.ExitCode()
			}

			if exit != tc.wantExit {
				t.Errorf("exit status %d, want %d", exit, tc.wantExit)
			}
			if got := strings.Count(out, validVerdict); got != tc.wantValid {
				t.Errorf("%d commits reported valid, want %d", got, tc.wantValid)
			}
			if got := strings.Count(out, invalidVerdict); got != tc.wantInvalid {
				t.Errorf("%d commits reported invalid, want %d", got, tc.wantInvalid)
			}
			if t.Failed() {
				t.Logf("script output:\n%s", out)
			}
		})
	}
}
