// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scripts/version-helper.sh is the only thing in the repository that can PROPOSE a release
// version, and until 2026-09-23 it could not: determine_bump_type grepped for the UNSCOPED
// conventional prefixes ("feat:", "fix!") while every commit here uses the scoped form
// ("fix(scope):"). Measured consequence, not hypothetical: with twelve commits between v2.5.0
// and HEAD — one of them breaking-flagged — `make version-next` proposed v2.5.0, the CURRENT
// tag. The release that followed was hand-cut as v2.5.1 and shipped the breaking-flagged #721
// (fix(json, yaml, csv)!:) under a PATCH bump.
//
// This test builds a scratch git repository per case and runs the real script against it, so
// the assertion is on the script's actual output rather than on a reimplementation of its
// greps. Each case tags v1.0.0, adds one commit with the subject under test, and asks for the
// bump.
func TestVersionHelperUnderstandsScopedConventionalCommits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("drives a bash script; the release flow it belongs to runs on POSIX runners")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "version-helper.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script not found: %v", err)
	}

	cases := []struct {
		name    string
		subject string
		want    string // expected `next` output
	}{
		// The four shapes that were BROKEN: scoped conventional commits.
		{"scoped fix is a patch", "fix(sarif): correct the uriBaseId", "v1.0.1"},
		{"scoped feat is a minor", "feat(stdin): accept --file -", "v1.1.0"},
		{"scoped breaking fix is a major", "fix(json, yaml, csv)!: report relative paths", "v2.0.0"},
		{"scoped breaking feat is a major", "feat(api)!: remove the legacy entry point", "v2.0.0"},
		// The shapes that already worked must keep working.
		{"unscoped fix is a patch", "fix: correct the uriBaseId", "v1.0.1"},
		{"unscoped feat is a minor", "feat: accept stdin", "v1.1.0"},
		{"BREAKING CHANGE footer is a major", "chore: retune\n\nBREAKING CHANGE: output moved", "v2.0.0"},
		// Non-release subjects must NOT propose a bump.
		{"chore alone is none", "chore(deps): bump actions group", "v1.0.0"},
		{"docs alone is none", "docs: fix a typo", "v1.0.0"},
		// The anchoring case: a prefix QUOTED IN PROSE is not a commit type. Without the
		// leading-sha anchor this subject reads as a feat and proposes a minor.
		{"a subject quoting feat: is none", "docs: explain what feat: means", "v1.0.0"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			run := func(args ...string) string {
				cmd := exec.Command(args[0], args[1:]...)
				cmd.Dir = dir
				cmd.Env = append(os.Environ(),
					"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
					"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
					// The script must read THIS repo's tags, not the enclosing checkout's.
					"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
				)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: %v\n%s", args, err, out)
				}
				return string(out)
			}
			run("git", "init", "-q", "-b", "main")
			os.WriteFile(filepath.Join(dir, "f"), []byte("0"), 0o600)
			run("git", "add", "f")
			run("git", "commit", "-q", "-m", "seed")
			run("git", "tag", "v1.0.0")
			os.WriteFile(filepath.Join(dir, "f"), []byte("1"), 0o600)
			run("git", "add", "f")
			run("git", "commit", "-q", "-m", tc.subject)

			got := strings.TrimSpace(run("bash", script, "next"))
			// The script may print a bare version or prose around it; take the last field
			// that looks like a version.
			ver := ""
			for _, f := range strings.Fields(got) {
				if strings.HasPrefix(f, "v") && strings.Count(f, ".") == 2 {
					ver = f
				}
			}
			if ver != tc.want {
				t.Errorf("subject %q: proposed %q, want %s (raw output: %q)", tc.subject, ver, tc.want, got)
			}
		})
	}
}
