// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRelInside_LexicalCases(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "repo")

	cases := []struct {
		name       string
		root       string
		target     string
		wantRel    string
		wantInside bool
	}{
		{
			name:       "nested file keeps every segment below the root",
			root:       root,
			target:     filepath.Join(root, "src", "nested", "config.py"),
			wantRel:    filepath.Join("src", "nested", "config.py"),
			wantInside: true,
		},
		{
			name:       "the root itself is inside itself",
			root:       root,
			target:     root,
			wantRel:    ".",
			wantInside: true,
		},
		{
			name: "a sibling whose name merely STARTS with the root is outside",
			// The prefix-test mistake: strings.HasPrefix("/repo-archive/x.py", "/repo")
			// is true, and would claim a wholly unrelated tree.
			root:       root,
			target:     filepath.Join(string(filepath.Separator), "repo-archive", "x.py"),
			wantInside: false,
		},
		{
			name:       "a parent directory is outside",
			root:       root,
			target:     filepath.Join(string(filepath.Separator), "x.py"),
			wantInside: false,
		},
		{
			name:       "an empty root is not a root",
			root:       "",
			target:     filepath.Join(root, "x.py"),
			wantInside: false,
		},
		{
			name:       "an empty target is nothing",
			root:       root,
			target:     "",
			wantInside: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel, inside := RelInside(tc.root, tc.target)
			if inside != tc.wantInside {
				t.Fatalf("RelInside(%q, %q) inside = %v, want %v", tc.root, tc.target, inside, tc.wantInside)
			}
			if inside && rel != tc.wantRel {
				t.Errorf("RelInside(%q, %q) rel = %q, want %q", tc.root, tc.target, rel, tc.wantRel)
			}
		})
	}
}

// TestRelInside_SymlinkedRoot is the case that took a gitlab-sast report from 2 vulnerabilities
// to 0 on the first revision of #707: the root spelled through a link, the paths resolved.
func TestRelInside_SymlinkedRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "src"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(real, "src", "config.py")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	// Root spelled through the link, target resolved: lexically unrelated.
	rel, inside := RelInside(link, target)
	if !inside {
		t.Fatalf("RelInside(%q, %q) = outside; a root spelled through a symlink must still "+
			"contain the paths the walker resolved", link, target)
	}
	if want := filepath.Join("src", "config.py"); rel != want {
		t.Errorf("rel = %q, want %q", rel, want)
	}

	// And the reverse spelling, which is what macOS produces for /tmp roots.
	if _, inside := RelInside(real, filepath.Join(link, "src", "config.py")); !inside {
		t.Error("a target spelled through the symlink is outside a resolved root")
	}
}

// TestRelInside_LexicalWinsWhenTargetCannotResolve pins the ordering. A resolve-first
// implementation compares a RESOLVED root against an UNRESOLVED target and refuses.
func TestRelInside_LexicalWinsWhenTargetCannotResolve(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("/var vs /private/var is a macOS shape; the property is covered above")
	}
	base := t.TempDir() // on macOS this is under /var, itself a link to /private/var
	missing := filepath.Join(base, "deleted-since-the-walk.txt")

	rel, inside := RelInside(base, missing)
	if !inside {
		t.Fatalf("RelInside(%q, %q) = outside; a path that no longer exists is still inside "+
			"the root it was spelled under", base, missing)
	}
	if rel != "deleted-since-the-walk.txt" {
		t.Errorf("rel = %q, want the basename", rel)
	}
}

func TestInside_MatchesRelInside(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "repo")
	if !Inside(root, filepath.Join(root, "a", "b")) {
		t.Error("Inside disagrees with RelInside for a contained path")
	}
	if Inside(root, filepath.Join(string(filepath.Separator), "elsewhere")) {
		t.Error("Inside disagrees with RelInside for an outside path")
	}
}
