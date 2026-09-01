// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
)

// Path-traversal gating, as a path-SEGMENT test rather than a substring test.
//
// Eight sites in cmd asked `strings.Contains(p, "..")`. Two consecutive dots are an
// ordinary run of bytes in a filename — `report..final.txt`, a date range
// `2024..2025.csv`, anything from a tool that writes `name..ext` — and none of them
// is a traversal. Measured on the shipped binary at a0e983c, two byte-identical
// files in one directory each carrying `SSN: 452-11-9384`:
//
//	--file <dir>/normal.txt              1 finding    rc 0
//	--file <dir>/report..final.txt       0 findings   rc 0   "No files to process"
//	  ... --fail-on-incomplete           0 findings   rc 0
//	--format json --file <dir>           total_files 1, files_processed 1,
//	                                     files_skipped 0, no files_not_examined key
//
// The last line is the harm. Only REPORTED findings reach the redactor, so the SSN in
// the second file stayed in cleartext, and the run said nothing: the walk dropped the
// path with a bare `return nil`, so it entered neither the numerator nor the
// DENOMINATOR. A consumer reading "1 of 1 processed, 0 skipped" concludes the scan was
// complete. It was complete over the file set the tool chose to admit.
//
// # The decision: post-Clean leading "..", not any ".."
//
// filepath.Clean resolves an interior ".." away, so after cleaning the only ".." left
// is one that could not be resolved — i.e. one that climbs ABOVE the path's own base.
// That is the only shape that means "escape".
//
// This repo already made and documented this exact call once, for the Office metadata
// path guard: see internal/preprocessors/meta-extractors/meta-extract-officelib.
// `/home/a/../../etc/x` cleans to `/etc/x`, an ordinary absolute path with no ".." left
// in it, and is accepted — because it names the same file the caller could have named
// directly, and neither that guard nor this one fronts a sandbox or a document root.
// `../../etc/passwd` cleans to itself, still climbs, and is refused. Adopting the same
// boundary here means the two guards cannot drift apart.
//
// What is deliberately NOT added: a refusal of absolute paths outside the working
// directory. `--file /etc/hosts` is accepted today, so refusing an absolute path would
// be a NEW restriction that silently drops coverage — the defect this file exists to
// remove, reintroduced one shape over.

// pathEscapesBase reports whether p, once cleaned, still climbs above the directory it
// is relative to.
//
// Windows: the volume name is stripped first, because filepath.Clean keeps it and
// `C:..\secret` is a drive-relative path that DOES climb — its cleaned form is
// `C:..\secret`, which has no leading ".." to find until `C:` is removed.
// filepath.VolumeName returns "" on Unix, so the strip is a no-op there.
//
// The comparison is made on the forward-slash form so one expression covers both
// separators on Windows, where filepath.Clean may leave either. It is NOT made on the
// raw argument: on Unix a backslash is a legitimate filename byte, so `..\x` is a
// one-segment name that must be scanned, and ToSlash correctly leaves it alone there.
func pathEscapesBase(p string) bool {
	c := filepath.Clean(p)
	c = c[len(filepath.VolumeName(c)):]
	s := filepath.ToSlash(c)
	return s == ".." || strings.HasPrefix(s, "../")
}

// pathEscapesRoot reports whether target lies outside root.
//
// Used where a real root EXISTS — the directory a walk was asked to descend — for which
// "outside" is a statement about containment rather than about the working directory.
//
// Purely lexical: no os.Stat, no filepath.EvalSymlinks. It is called once per entry of
// every walked tree, so it must not add syscalls per file. The symlink case, which does
// need EvalSymlinks because a link's target is only knowable by resolving it, is handled
// separately by withinRoot in symlink_walk.go and disclosed as causeNotFollowed.
//
// A Rel error means the two paths cannot be expressed relative to one another at all —
// one absolute and one relative, or different Windows volumes — and the safe answer to
// "is this inside" is then no.
func pathEscapesRoot(root, target string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return true
	}
	return pathEscapesBase(rel)
}

// traversalRefusedDetail is the operator-facing remedy for a refused input path.
//
// It names the action, because the cause label alone ("path refused as traversal") does
// not tell a person what to type instead. An absolute path always passes the gate.
const traversalRefusedDetail = "path climbs above the working directory; pass an absolute path instead"
