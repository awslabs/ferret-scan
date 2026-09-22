// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"path/filepath"
	"strings"
)

// RelInside reports target's path relative to root, and whether target is inside root at
// all. It is the one containment answer for the whole tool.
//
// Four call sites had grown their own `filepath.Rel` plus a ".." prefix test — the symlink
// walker's containment gate, the config-provenance note in cmd, the gitlab-sast report
// path, and now the report root — and they DISAGREED about symlinks, which is not a
// cosmetic difference. Measured while fixing #705: a root spelled through /tmp against
// paths the walker had resolved to /private/tmp took a report from 2 vulnerabilities to 0,
// because a purely lexical Rel calls every in-tree path "outside".
//
// LEXICAL FIRST, then both sides through EvalSymlinks. The order carries two properties
// that a resolve-then-compare implementation does not have:
//
//   - Cost. The common case — a path genuinely inside the root, spelled the same way — is
//     answered with no syscall at all. That matters because the formatters run this once
//     per finding. (cmd's pathEscapesRoot, which runs once per directory ENTRY of every
//     scanned tree, deliberately stays lexical-only and does not call this: there,
//     "outside" is a refusal, and escalating to EvalSymlinks would turn a refusal into a
//     scan. See its own comment.)
//   - Correctness when only ONE side resolves. A root under /var resolves to /private/var
//     while a file that has since been deleted does not resolve at all, and a Rel between
//     a resolved root and an unresolved target is exactly the mismatch being avoided.
//     Resolution is therefore an escalation, used only when the lexical answer is "outside"
//     and only when BOTH sides resolve.
//
// An empty root means "no root known" and is reported as not-inside rather than silently
// meaning the working directory: a caller with no root has to choose its own fallback, and
// the two callers here choose differently (the formatter degrades to a basename, the
// provenance note stays quiet).
func RelInside(root, target string) (string, bool) {
	if root == "" || target == "" {
		return "", false
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", false
	}

	if rel, ok := relNoClimb(absRoot, absTarget); ok {
		return rel, true
	}

	resolvedRoot, rootErr := filepath.EvalSymlinks(absRoot)
	resolvedTarget, targetErr := filepath.EvalSymlinks(absTarget)
	if rootErr != nil || targetErr != nil {
		return "", false
	}
	return relNoClimb(resolvedRoot, resolvedTarget)
}

// Inside is RelInside without the relative path, for callers that only need the predicate.
func Inside(root, target string) bool {
	_, ok := RelInside(root, target)
	return ok
}

// relNoClimb is filepath.Rel with "outside the root" folded into the ok result. Rel yields
// ".." or a "../" prefix exactly when target sits outside root, and an error when the two
// cannot be expressed relative to one another at all — different Windows volumes, or one
// side relative — for which the safe answer to "is this inside" is no.
func relNoClimb(root, target string) (string, bool) {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}
