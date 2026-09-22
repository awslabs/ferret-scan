// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// resolveReportRoot picks the directory a machine report's file locations are made
// relative to: the SCAN TARGET, not the working directory.
//
// The working directory is incidental — it is wherever the shell happened to be — and it
// is measurably wrong for one of the two documented GitLab invocations. `docs/
// DOCKER_INTEGRATION.md` runs
//
//	docker run --rm -v $PWD:/data ferret-scan:latest --file /data --recursive --format gitlab-sast
//
// and the final image is FROM scratch with no WORKDIR (the `WORKDIR /app` in the Dockerfile
// belongs to the builder stage), so the container's working directory is "/". Every
// /data/... path is then inside the root, and the MOUNT POINT survives into the report:
// GitLab resolves `data/src/config.py` from the repository root and finds nothing.
//
// The scan target has none of that dependence on context: the user named it, so a path
// relative to it is self-describing. It is also the only root that is always defined —
// ferret-scan runs on arbitrary directories and on phones through the mobile app, where
// neither a git root nor a meaningful working directory exists — which is why this does
// NOT walk up looking for .git. Both documented GitLab invocations already have
// target == repository root (`--file .` from the checkout, `--file /data` with
// `-v $PWD:/data`), so nothing is lost by not discovering it.
//
// The cost, as a decision rather than an oversight: `--file src --recursive` inside a
// repository now reports `first/config.py` where the working directory would have given
// `src/first/config.py`, so a GitLab dashboard link for that undocumented usage 404s. The
// remedy is `--file .`. There is no --source-root override, because the flag cannot
// express the worst variant anyway — `-v $PWD/src:/data`, where the repository root is not
// inside the container at all and what is needed is a prefix, not a root.
//
// An empty return means "no root known", which every formatter degrades to a basename.
func resolveReportRoot(inputPaths []string) string {
	root := ""
	for _, inputPath := range inputPaths {
		if inputPath == "" {
			continue
		}
		// An input the scan will REFUSE must not steer the root. pathEscapesBase is the
		// same gate main applies before walking, so a refused argument contributes
		// nothing here either — otherwise `--file ../elsewhere` would move the root for
		// the inputs that are actually scanned.
		if pathEscapesBase(inputPath) {
			continue
		}

		candidate := rootForInput(inputPath)
		if candidate == "" {
			continue
		}
		if root == "" {
			root = candidate
			continue
		}
		root = commonAncestor(root, candidate)
		if root == "" {
			// Nothing in common at all: different Windows volumes. No single root can
			// describe both, and reporting relative to one of them would silently
			// mis-attribute the other's findings.
			return ""
		}
	}
	return root
}

// rootForInput returns the directory a single scan target's findings are relative to.
//
//	directory      itself            --file /data      -> /data/src/x.py becomes src/x.py
//	regular file   its parent        --file /d/x.py    -> x.py
//	glob           non-magic prefix  --file '/a/*/b'   -> /a
//	bare glob      working directory --file '*.py'     -> filepath.Abs("") is the cwd
//
// A path that does not exist is treated as a file rather than a directory. It contributes
// no findings either way — a typo is a usage error, not a scanned target — and taking the
// parent is the choice that cannot swallow a real sibling target into a deeper root.
func rootForInput(inputPath string) string {
	if hasGlobMagic(inputPath) {
		return globRoot(inputPath)
	}

	abs, err := filepath.Abs(filepath.Clean(inputPath))
	if err != nil {
		return ""
	}
	if info, err := os.Stat(abs); err == nil && info.IsDir() {
		return abs
	}
	return filepath.Dir(abs)
}

// hasGlobMagic reports whether the path is a pattern rather than a name. Same test
// getFilesToProcess uses to decide whether to expand it, so the two cannot disagree about
// which inputs are patterns.
func hasGlobMagic(p string) bool {
	return strings.ContainsAny(p, "*?") || (strings.Contains(p, "[") && strings.Contains(p, "]"))
}

// globRoot returns the deepest directory a pattern cannot escape upward from: the segments
// before the first one containing magic characters.
//
// `~/` is expanded first, as the glob branch in getFilesToProcess does, so `~/*.py` roots
// at the home directory rather than at a literal "~" beside the working directory.
func globRoot(pattern string) string {
	expanded := pattern
	if strings.HasPrefix(pattern, "~/") {
		if homeDir, err := os.UserHomeDir(); err == nil {
			expanded = filepath.Join(homeDir, pattern[2:])
		}
	}

	// Split on the SLASH-normalised form: on Windows both separators are legal in a
	// pattern, and filepath.Glob accepts either.
	segments := strings.Split(filepath.ToSlash(expanded), "/")
	literal := segments
	for i, segment := range segments {
		if hasGlobMagic(segment) {
			literal = segments[:i]
			break
		}
	}

	prefix := strings.Join(literal, "/")
	if prefix == "" && strings.HasPrefix(filepath.ToSlash(expanded), "/") {
		// Absolute pattern whose FIRST segment is magic: /*/x. The root is "/".
		prefix = "/"
	}
	abs, err := filepath.Abs(filepath.FromSlash(prefix))
	if err != nil {
		return ""
	}
	return abs
}

// commonAncestor returns the deepest directory containing both a and b, or "" when they
// share nothing — different Windows volumes.
//
// Multiple targets are legal (`ferret-scan --file a/ b/ c/`: inputPaths is the --file value
// plus positional args), and one report has one root, so the roots have to be combined.
// Common ancestor is chosen over one-root-per-target because it keeps every path in a
// single report comparable with every other: per-target roots would let two findings in
// different trees print the same relative path.
//
// For disjoint absolute targets this degrades to the volume root, which makes a path read
// like the absolute one with its leading separator removed. That is the honest answer for
// "these findings have no shared root" and it is still inert rather than misleading — a
// consumer resolving it from a repository root gets a miss, not a different real file,
// which is the failure mode a basename would reintroduce.
func commonAncestor(a, b string) string {
	if a == b {
		return a
	}

	volA, volB := filepath.VolumeName(a), filepath.VolumeName(b)
	// Windows volume names are case-insensitive (C: and c: are one volume); the path
	// segments below are compared exactly, because a case-insensitive FILE SYSTEM is not
	// something a path string can be asked about.
	if !strings.EqualFold(volA, volB) {
		return ""
	}

	segsA := strings.Split(filepath.ToSlash(a[len(volA):]), "/")
	segsB := strings.Split(filepath.ToSlash(b[len(volB):]), "/")

	shared := make([]string, 0, len(segsA))
	for i := 0; i < len(segsA) && i < len(segsB); i++ {
		if segsA[i] != segsB[i] {
			break
		}
		shared = append(shared, segsA[i])
	}
	if len(shared) == 0 {
		return ""
	}

	joined := strings.Join(shared, "/")
	if joined == "" {
		// Only the leading empty segment matched: both are absolute and share nothing
		// below the volume root.
		joined = "/"
	}
	return filepath.Clean(volA + filepath.FromSlash(joined))
}
