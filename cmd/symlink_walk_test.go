// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A symlink in a scanned directory must be scanned or DISCLOSED, never dropped.
//
// filepath.Walk supplies Lstat info, so a symlink's mode is ModeSymlink and never
// ModeRegular. The walk's "only add regular files" branch had no else, so links were
// dropped with no record: absent from filesToProcess, from SkippedFiles, from
// total_files, from files_skipped and from files_not_examined, with nothing printed.
//
// Measured on a directory of three entries — a normal file with an SSN, a symlink to a
// file holding a card number, and a dangling symlink:
//
//	Files: 1 scanned | Findings: 1
//	exit 0, no NOT FULLY EXAMINED block, card number neither reported nor disclosed
//
// The SAME symlink named directly on the command line was scanned and the card found,
// because that path uses os.Stat which follows links. Identical bytes, different outcome
// depending on how the path was spelled. cmd/main.go's exitCodeIncompleteCoverage comment
// also promises exit 3 for a dangling symlink; it delivered 0. See #326.

const symlinkSizeLimit = 100 * 1024 * 1024

// linkTo creates dir/name -> target and returns the link path.
func linkTo(t *testing.T, dir, name, target string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	return p
}

func writeFileAt(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClassifySymlinkFollowsInTreeRegularFile(t *testing.T) {
	root := t.TempDir()
	target := writeFileAt(t, filepath.Join(root, "sub", "doc.txt"), "SSN: 452-11-9384\n")
	link := linkTo(t, root, "link.txt", target)

	d, resolved, reason := classifySymlink(link, root, symlinkSizeLimit)
	if d != symlinkFollow {
		t.Errorf("disposition = %v, want symlinkFollow (%q). A link to a regular file inside "+
			"the scanned tree must be scanned — the single-file path already does, so "+
			"refusing here means identical bytes get different treatment depending on how "+
			"the path is spelled.", d, reason)
	}
	// The resolved path is what the caller deduplicates on, so it must be absolute and
	// point at the target rather than the link.
	if !filepath.IsAbs(resolved) {
		t.Errorf("resolved = %q, want an absolute path", resolved)
	}
	if filepath.Base(resolved) != "doc.txt" {
		t.Errorf("resolved = %q, want it to name the target", resolved)
	}
}

func TestClassifySymlinkDisclosesEveryRefusal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// Each of these is a real shape that occurs on disk, and each used to vanish.
	cases := []struct {
		name  string
		build func() string
		want  string // substring the reason must contain
	}{
		{
			name: "dangling",
			build: func() string {
				return linkTo(t, root, "dangling.txt", filepath.Join(root, "nope.txt"))
			},
			want: "dangling",
		},
		{
			name: "outside the scanned tree",
			build: func() string {
				tgt := writeFileAt(t, filepath.Join(outside, "secret.txt"), "Card: 4111111111111111\n")
				return linkTo(t, root, "outside.txt", tgt)
			},
			want: "outside the scanned directory",
		},
		{
			name: "directory",
			build: func() string {
				if err := os.MkdirAll(filepath.Join(root, "realdir"), 0o755); err != nil {
					t.Fatal(err)
				}
				return linkTo(t, root, "dirlink", filepath.Join(root, "realdir"))
			},
			want: "directory",
		},
		{
			name: "loop",
			build: func() string {
				a := filepath.Join(root, "loopA")
				b := filepath.Join(root, "loopB")
				if err := os.Symlink(b, a); err != nil {
					t.Skipf("cannot create symlinks here: %v", err)
				}
				if err := os.Symlink(a, b); err != nil {
					t.Skipf("cannot create symlinks here: %v", err)
				}
				return a
			},
			want: "loop",
		},
		{
			name: "target over the size limit",
			build: func() string {
				big := filepath.Join(root, "big.bin")
				f, err := os.Create(big) // #nosec G304 -- test temp dir
				if err != nil {
					t.Fatal(err)
				}
				// Sparse: no bytes written, but Stat reports the size. This is also the
				// case that proves the limit is applied to the TARGET — Lstat on the link
				// reports the length of the link text, so a link to a 200MB file looked
				// like a 30-byte entry.
				if err := f.Truncate(symlinkSizeLimit + 1); err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
				return linkTo(t, root, "biglink.bin", big)
			},
			want: "too large",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link := tc.build()
			d, _, reason := classifySymlink(link, root, symlinkSizeLimit)
			if d != symlinkDisclose {
				t.Fatalf("disposition = %v, want symlinkDisclose. Dropping it silently is the "+
					"bug: the entry reaches no counter and nothing is printed.", d)
			}
			if reason == "" {
				t.Fatal("empty reason; the operator needs to know WHY it was not examined")
			}
			if !strings.Contains(reason, tc.want) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.want)
			}
			// Payload-free: a reason reaches stderr and every machine format.
			for _, leak := range []string{"452-11-9384", "4111111111111111"} {
				if strings.Contains(reason, leak) {
					t.Errorf("reason %q leaked file content", reason)
				}
			}
		})
	}
}

// TestWithinRootResolvesTheRootItself is the macOS trap.
//
// /tmp is a symlink to /private/tmp, so a purely lexical prefix compare calls every
// in-tree target "outside" and discloses the entire directory as skipped — turning a
// disclosure fix into a total loss of coverage on the platform it was developed on.
func TestWithinRootResolvesTheRootItself(t *testing.T) {
	root := t.TempDir()
	inside := writeFileAt(t, filepath.Join(root, "a", "b.txt"), "x")

	if !withinRoot(inside, root) {
		t.Errorf("withinRoot(%q, %q) = false for a file plainly inside the tree", inside, root)
	}
	if !withinRoot(root, root) {
		t.Error("the root is not within itself")
	}

	outside := t.TempDir()
	if withinRoot(filepath.Join(outside, "x.txt"), root) {
		t.Error("a path in a different directory was reported as inside the tree")
	}
	// A sibling whose name shares the root's prefix must not count as inside: a lexical
	// strings.HasPrefix would wrongly accept "/tmp/scanroot-evil" for root
	// "/tmp/scanroot".
	//
	// The sibling must actually EXIST. A first version used a non-existent path, and the
	// test passed even with a HasPrefix shortcut spliced in — because withinRoot resolves
	// both sides with EvalSymlinks, which succeeded on the root (/var -> /private/var) and
	// failed on the missing target, leaving the two with different prefixes. It passed by
	// accident, on this platform only, and a mutation proved the assertion was inert.
	sibling := root + "-evil"
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sibling) })
	siblingFile := writeFileAt(t, filepath.Join(sibling, "x.txt"), "x")
	if withinRoot(siblingFile, root) {
		t.Errorf("withinRoot(%q, %q) = true for a sibling sharing the root's name prefix; "+
			"containment must be path-segment based, not a string prefix", siblingFile, root)
	}
}

// TestResolveSymlinkCandidatesDeduplicatesAgainstRealFiles.
//
// A link whose target the walk already queued under its real name must NOT be queued
// again. Scanning the same bytes twice produces two findings that are byte-identical in
// every reported field, which is exactly the confusion of #321 — and here it would be
// self-inflicted.
func TestResolveSymlinkCandidatesDeduplicatesAgainstRealFiles(t *testing.T) {
	root := t.TempDir()
	real1 := writeFileAt(t, filepath.Join(root, "doc.txt"), "SSN: 452-11-9384\n")
	link := linkTo(t, root, "link.txt", real1)

	d, resolved, _ := classifySymlink(link, root, symlinkSizeLimit)
	if d != symlinkFollow {
		t.Fatalf("fixture: expected the link to be followable, got %v", d)
	}

	follow, disclose := resolveSymlinkCandidates(
		[]symlinkCandidate{{linkPath: link, resolved: resolved, disp: d}},
		[]string{real1}, // the walk already queued the target under its real name
	)
	if len(follow) != 0 {
		t.Errorf("queued %v in addition to the real file; the same content would be scanned "+
			"twice and reported as two identical findings", follow)
	}
	if len(disclose) != 0 {
		t.Errorf("disclosed %v; there is no coverage loss to report when the content is "+
			"scanned through its real path", disclose)
	}
}

// TestResolveSymlinkCandidatesQueuesAnOtherwiseUnreachableTarget is the other half.
//
// Deduplication must not swallow a link that is the ONLY route to its target — which
// happens on a non-recursive scan, where the target sits in a subdirectory the walk never
// enters.
func TestResolveSymlinkCandidatesQueuesAnOtherwiseUnreachableTarget(t *testing.T) {
	root := t.TempDir()
	target := writeFileAt(t, filepath.Join(root, "sub", "deep.txt"), "Card: 4111111111111111\n")
	link := linkTo(t, root, "link.txt", target)

	d, resolved, _ := classifySymlink(link, root, symlinkSizeLimit)
	follow, disclose := resolveSymlinkCandidates(
		[]symlinkCandidate{{linkPath: link, resolved: resolved, disp: d}},
		[]string{filepath.Join(root, "other.txt")}, // target NOT queued
	)
	if len(follow) != 1 || follow[0] != link {
		t.Errorf("follow = %v, want the link queued: it is the only path by which this "+
			"content is reachable, so dropping it loses the finding entirely", follow)
	}
	if len(disclose) != 0 {
		t.Errorf("disclose = %v, want none", disclose)
	}
}

// TestResolveSymlinkCandidatesIsOrderIndependent.
//
// The follow/dedup decision must not depend on the order the walk happened to visit
// entries, or the same tree would scan a file once or twice run to run.
func TestResolveSymlinkCandidatesIsOrderIndependent(t *testing.T) {
	root := t.TempDir()
	real1 := writeFileAt(t, filepath.Join(root, "a.txt"), "x")
	l1 := linkTo(t, root, "l1.txt", real1)
	l2 := linkTo(t, root, "l2.txt", real1)

	d1, r1, _ := classifySymlink(l1, root, symlinkSizeLimit)
	d2, r2, _ := classifySymlink(l2, root, symlinkSizeLimit)
	c1 := symlinkCandidate{linkPath: l1, resolved: r1, disp: d1}
	c2 := symlinkCandidate{linkPath: l2, resolved: r2, disp: d2}

	// Two links to the SAME target, with the target NOT already queued: exactly one
	// should be followed, whichever order they arrive in.
	for _, order := range [][]symlinkCandidate{{c1, c2}, {c2, c1}} {
		follow, _ := resolveSymlinkCandidates(order, nil)
		if len(follow) != 1 {
			t.Errorf("order %v: followed %d links to one target, want exactly 1 — the same "+
				"bytes must not be scanned twice", []string{order[0].linkPath, order[1].linkPath}, len(follow))
		}
	}
}

// TestNotFollowedCauseIsDistinctFromCannotRead.
//
// All refusals initially landed under "cannot read", which asserts a failure that did not
// happen: a link resolving outside the tree is perfectly readable, the tool declined. The
// operator's remedy differs too — chmod versus scanning the target explicitly.
func TestNotFollowedCauseIsDistinctFromCannotRead(t *testing.T) {
	if causeNotFollowed == causeUnreadable {
		t.Fatal("causeNotFollowed and causeUnreadable are the same value")
	}
	got := causeNotFollowed.String()
	if got == causeUnreadable.String() {
		t.Errorf("causeNotFollowed renders as %q, identical to causeUnreadable; the report "+
			"groups by cause, so the two would be indistinguishable", got)
	}
	if !strings.Contains(got, "symlink") {
		t.Errorf("causeNotFollowed = %q, want it to name symlinks so the group is actionable", got)
	}
}
