// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Symlink handling for directory walks.
//
// filepath.Walk supplies os.Lstat information, so a symlink's mode is ModeSymlink and
// never ModeRegular. The walk's "only add regular files" branch had NO else, so every
// symlink was dropped: absent from filesToProcess, from result.SkippedFiles, from
// total_files, from files_skipped and from files_not_examined. Nothing was printed.
//
// Measured on a directory holding three entries — a normal file with an SSN, a symlink
// to a file containing a card number, and a dangling symlink:
//
//	Files: 1 scanned | Findings: 1
//	exit 0, no NOT FULLY EXAMINED block, card number neither reported nor disclosed
//
// The same symlink named DIRECTLY on the command line was scanned and the card found,
// because the single-file path uses os.Stat, which follows links. So identical bytes were
// scanned or ignored depending on how the path was spelled — an inconsistency, not a
// policy. cmd/main.go's exitCodeIncompleteCoverage comment also states that a dangling
// symlink should produce exit 3; it produced 0. See #326.
//
// The policy implemented here:
//
//   - a link resolving to a regular file INSIDE the scanned tree is FOLLOWED, matching
//     the single-file path so the same bytes get the same treatment;
//   - anything else — dangling, a loop, a directory, a device, or a target outside the
//     scanned tree — is REFUSED and DISCLOSED, so it reaches files_not_examined and
//     --fail-on-incomplete rather than vanishing;
//   - a link whose target is already covered by a real file in the same walk is skipped
//     SILENTLY, because its content is scanned once already and reporting it twice would
//     manufacture the duplicate-looking findings of #321.
//
// Directory links are refused rather than followed on purpose: filepath.Walk does not
// follow them either, and following would risk unbounded traversal and re-scanning the
// same subtree through several paths.

// symlinkDisposition is what to do with a symlink found during a walk.
type symlinkDisposition int

const (
	// symlinkFollow: scan it. The LINK path is queued, not the target, so findings are
	// attributed to the path the user can actually see in their tree — which is also
	// what the single-file path reports.
	symlinkFollow symlinkDisposition = iota
	// symlinkDisclose: do not scan, but record it so the coverage loss is visible.
	symlinkDisclose
	// symlinkCoveredElsewhere: the target is already queued via its real path.
	symlinkCoveredElsewhere
)

// classifySymlink decides how a symlink encountered during a walk should be handled.
//
// scanRoot is the directory the user asked to scan; it bounds what "inside the tree"
// means. sizeLimit mirrors the walk's own cap and is applied to the TARGET's size,
// because Lstat reports the length of the link text rather than of the file it names —
// so a link to a 200MB file looked like a 30-byte entry.
//
// resolved is the absolute target path, returned so the caller can deduplicate against
// files it has already queued. reason is human-facing and payload-free: it names the
// condition, never file contents.
func classifySymlink(linkPath, scanRoot string, sizeLimit int64) (d symlinkDisposition, resolved, reason string) {
	// EvalSymlinks resolves the whole chain and returns an error for a dangling link or
	// a loop (ELOOP), which is why loop protection needs no separate counter here.
	target, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return symlinkDisclose, "", "symlink could not be resolved (dangling target or link loop)"
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return symlinkDisclose, "", "symlink target path could not be resolved"
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		return symlinkDisclose, absTarget, "symlink target could not be read"
	}

	if info.IsDir() {
		// Not followed by design — see the package comment. Disclosed rather than
		// dropped, because a linked-in directory of real documents is exactly the case
		// where silence is most costly.
		return symlinkDisclose, absTarget, "symlink points to a directory (directory links are not followed)"
	}
	if !info.Mode().IsRegular() {
		// A device, FIFO or socket has no size and may never end. The router refuses
		// these for the same reason.
		return symlinkDisclose, absTarget, "symlink target is not a regular file"
	}
	if sizeLimit > 0 && info.Size() > sizeLimit {
		return symlinkDisclose, absTarget,
			fmt.Sprintf("symlink target is too large (%d bytes, limit %d)", info.Size(), sizeLimit)
	}

	// Containment. A link out of the tree would pull in files the user never named —
	// scanning ~/.ssh because a repo contains a convenience link is a surprise, and
	// reporting findings from paths outside the requested directory is confusing. It is
	// refused, but SAID, which is the part that was missing.
	if !withinRoot(absTarget, scanRoot) {
		return symlinkDisclose, absTarget, "symlink resolves outside the scanned directory"
	}

	return symlinkFollow, absTarget, ""
}

// withinRoot reports whether target is inside root.
//
// Both sides are resolved with EvalSymlinks first: on macOS the scan root is routinely
// given as /tmp/... which is itself a link to /private/tmp, so a purely lexical compare
// would call every in-tree target "outside" and disclose the whole directory as skipped.
func withinRoot(target, root string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = r
	}
	if t, err := filepath.EvalSymlinks(target); err == nil {
		target = t
	}

	rel, err := filepath.Rel(absRoot, target)
	if err != nil {
		return false
	}
	// Rel yields ".." or a "../" prefix exactly when target sits outside absRoot.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// symlinkCandidate is a symlink seen during a walk, held until the walk finishes.
//
// The decision to follow depends on whether the target is ALSO reachable as a real file
// in the same walk, and that is not known until every entry has been visited. Deciding
// inline would make the outcome depend on directory iteration order: the same tree could
// scan a file once or twice depending on which name the walk happened to reach first.
type symlinkCandidate struct {
	linkPath string
	resolved string
	reason   string
	disp     symlinkDisposition
}

// resolveSymlinkCandidates turns collected candidates into files to scan and refusals to
// disclose, deduplicating against the regular files the walk already queued.
//
// queued is the set of regular-file paths found by the walk, and is matched on RESOLVED
// absolute paths so that a link and its target are recognised as the same content.
func resolveSymlinkCandidates(cands []symlinkCandidate, queued []string) (follow []string, disclose []SkippedFile) {
	covered := make(map[string]struct{}, len(queued))
	for _, p := range queued {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if r, err := filepath.EvalSymlinks(abs); err == nil {
			abs = r
		}
		covered[abs] = struct{}{}
	}

	for _, c := range cands {
		switch c.disp {
		case symlinkDisclose:
			// Cause must be set explicitly. It reaches the not-examined report, and the
			// zero value is causeUnreadable — which would claim the link could not be
			// opened, a failure that did not happen for anything refused on purpose.
			disclose = append(disclose, SkippedFile{
				Path:   c.linkPath,
				Reason: c.reason,
				Cause:  causeNotFollowed,
			})
		case symlinkFollow:
			if _, dup := covered[c.resolved]; dup {
				// Content already scanned through its real path. Silent on purpose:
				// there is no coverage loss to report, and a note per link would be
				// noise on trees that use links heavily.
				continue
			}
			covered[c.resolved] = struct{}{}
			follow = append(follow, c.linkPath)
		case symlinkCoveredElsewhere:
			continue
		}
	}
	return follow, disclose
}
