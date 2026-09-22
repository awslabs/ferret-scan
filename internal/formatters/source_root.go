// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"path/filepath"

	"github.com/awslabs/ferret-scan/v2/internal/paths"
)

// RelativeToRoot renders a scanned file's path the way FormatterOptions.SourceRoot says a
// machine report should carry it: relative to the root, with forward slashes.
//
// It lives beside the SourceRoot field rather than in one formatter because every machine
// format has the same problem with the same answer. The CLI hands formatters ABSOLUTE
// paths — cmd/main.go resolves every input with filepath.Abs before the walk — so without
// this each format printed either the operator's whole home directory (json, yaml, csv,
// sarif) or a bare basename that collapsed two files with the same name into one location
// (gitlab-sast, #705).
//
// Three cases, in order:
//
//	already relative   returned as-is, forward-slashed. Library callers pass these; there
//	                   is no root to make them relative to.
//	inside the root    made relative and keeps every segment below the root.
//	anything else      DEGRADED TO THE BASENAME: no root known, another volume, or a path
//	                   that would have to climb out of the root to be expressed.
//
// The degradation is deliberate, and it is not a refusal. A formatter that errored here
// would lose the finding: gitlab-sast's mapper error return is consumed by a loop that
// `continue`s past the match and logs it only under --verbose, which is the shape #562
// measured — a report with "status": "success" and a real finding missing from it. A
// finding at a lossy path can still be found; a finding absent from the report cannot.
//
// Forward slashes come from filepath.ToSlash, which converts the host separator and
// nothing else. An unconditional backslash rewrite would corrupt POSIX filenames, where a
// backslash is an ordinary character — reporting `we\ird.txt` as a directory that does not
// exist, the class #637 fixed in the redaction path.
func RelativeToRoot(path, root string) string {
	if rel, ok := RelativeToRootOK(path, root); ok {
		return rel
	}
	return filepath.Base(filepath.Clean(path))
}

// RelativeToRootOK is RelativeToRoot without the basename fallback: ok is false when the path
// could NOT be expressed relative to the root, leaving the choice of fallback to the caller.
//
// SARIF is why this is separate. There, a path outside the root falls back to an absolute
// file: URI rather than to a basename, because SARIF's artifactLocation.uri is only resolvable
// by a consumer if it is either root-relative WITH a uriBaseId or absolute — a bare basename is
// neither, and #633 exists because that URI has to be well-formed. A relative input path is
// reported as root-relative (ok true) with nothing changed: a library caller passing relative
// paths has already expressed them against its own root, which is what %SRCROOT% names.
func RelativeToRootOK(path, root string) (string, bool) {
	cleaned := filepath.Clean(path)

	if !filepath.IsAbs(cleaned) {
		return filepath.ToSlash(cleaned), true
	}
	if rel, inside := paths.RelInside(root, cleaned); inside {
		return filepath.ToSlash(rel), true
	}
	return "", false
}

// ReportPath is RelativeToRoot bound to these options' SourceRoot, for the common call.
func (o FormatterOptions) ReportPath(path string) string {
	return RelativeToRoot(path, o.SourceRoot)
}
