// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitignore

import (
	"os"
	"path/filepath"
	"testing"
)

// The fixtures here are built by hand rather than by shelling out to `git`: the tests run
// on runners where a git binary is not guaranteed, and `git worktree add` needs a
// repository with a commit. Each shape below was measured against real git 2.x with
// `git check-ignore -v` before being written down:
//
//	submodule   .git file "gitdir: ../.git/modules/sub" (relative), no commondir,
//	            rules read from <outer>/.git/modules/sub/info/exclude
//	worktree    .git file "gitdir: <abs>/.git/worktrees/wt" (absolute) plus a commondir
//	            file "../..", rules read from the COMMON dir <abs>/.git/info/exclude

// writeDotGitFile writes the `gitdir:` pointer file git puts at a worktree or submodule
// root. Trailing newline included, as git writes it.
func writeDotGitFile(t *testing.T, dir, gitdir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, ".git"), "gitdir: "+gitdir+"\n")
}

func TestInfoExclude_WorktreeReadsCommonDir(t *testing.T) {
	base := t.TempDir()
	mainRepo := filepath.Join(base, "repo")
	worktree := filepath.Join(base, "wt")
	perWorktree := filepath.Join(mainRepo, ".git", "worktrees", "wt")

	// The rule git actually honours lives in the common dir.
	writeFile(t, filepath.Join(mainRepo, ".git", "info", "exclude"), "common.txt\n")
	// One in the per-worktree dir, which git does NOT read. Present so a fix that stops
	// at the pointer instead of resolving commondir fails this test rather than passing it.
	writeFile(t, filepath.Join(perWorktree, "info", "exclude"), "per-worktree.txt\n")
	writeFile(t, filepath.Join(perWorktree, "commondir"), "../..\n")
	if err := os.MkdirAll(worktree, 0o755); err != nil {
		t.Fatalf("mkdir worktree: %v", err)
	}
	writeDotGitFile(t, worktree, perWorktree)

	m, err := New(worktree)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Match(filepath.Join(worktree, "common.txt")) {
		t.Error("a worktree must honour the common dir's info/exclude; " +
			"the .git FILE was walked past and no rules applied")
	}
	if m.Match(filepath.Join(worktree, "per-worktree.txt")) {
		t.Error("rules were read from .git/worktrees/<name>/info/exclude, which git ignores")
	}
}

func TestInfoExclude_SubmoduleResolvesRelativePointer(t *testing.T) {
	outer := t.TempDir()
	sub := filepath.Join(outer, "sub")
	moduleDir := filepath.Join(outer, ".git", "modules", "sub")

	// The OUTER repository is a real .git directory with its own rules, which must not
	// govern the submodule: measured, git applies neither the outer exclude nor anything
	// above it inside a submodule.
	writeFile(t, filepath.Join(outer, ".git", "info", "exclude"), "outer-only.txt\n")
	writeFile(t, filepath.Join(moduleDir, "info", "exclude"), "sub-only.txt\n")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	writeDotGitFile(t, sub, filepath.Join("..", ".git", "modules", "sub"))

	m, err := New(sub)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Match(filepath.Join(sub, "sub-only.txt")) {
		t.Error("a submodule must honour its own module dir's info/exclude")
	}
	if m.Match(filepath.Join(sub, "outer-only.txt")) {
		t.Error("the OUTER repository's exclude rules were applied to the submodule: " +
			"an unrelated project silently governs what gets scanned")
	}
}

// TestInfoExclude_UnresolvablePointerStopsWalk pins the refusal shape: a .git file we
// cannot follow still marks a repository root, so no outer repository's rules leak in.
func TestInfoExclude_UnresolvablePointerStopsWalk(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")

	writeFile(t, filepath.Join(outer, ".git", "info", "exclude"), "outer-only.txt\n")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatalf("mkdir inner: %v", err)
	}

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"no gitdir line", "this is not a git pointer\n"},
		{"empty gitdir value", "gitdir:\n"},
		{"pointer to a path that does not exist", "gitdir: /nonexistent/ferret-scan/gitdir\n"},
		{"pointer to a FILE, not a directory", "gitdir: ../.git/info/exclude\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeFile(t, filepath.Join(inner, ".git"), tc.content)

			m, err := New(inner)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if m.Match(filepath.Join(inner, "outer-only.txt")) {
				t.Error("walked PAST an unfollowable .git file and applied the outer " +
					"repository's rules")
			}
		})
	}
}

// TestInfoExclude_PlainRepositoryUnchanged is the regression guard for the shape that
// already worked: .git as a real directory, rules read from it, scoped to its own root.
func TestInfoExclude_PlainRepositoryUnchanged(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".git", "info", "exclude"), "local.txt\n")

	m, err := New(repo)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Match(filepath.Join(repo, "local.txt")) {
		t.Error("a plain .git directory's info/exclude no longer applies")
	}
}

// TestInfoExclude_DotGitSymlinkToDirectory keeps the pre-existing Stat (follow-links)
// behaviour: a .git symlink pointing at a real repository directory is still a
// repository, and must not be mistaken for a `gitdir:` pointer file.
func TestInfoExclude_DotGitSymlinkToDirectory(t *testing.T) {
	base := t.TempDir()
	realGit := filepath.Join(base, "real-git")
	work := filepath.Join(base, "work")

	writeFile(t, filepath.Join(realGit, "info", "exclude"), "linked.txt\n")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}
	if err := os.Symlink(realGit, filepath.Join(work, ".git")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	m, err := New(work)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Match(filepath.Join(work, "linked.txt")) {
		t.Error("a .git symlink to a repository directory no longer resolves")
	}
}
