// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// excludeMatcher answers "should this path be left out" for one scan, carrying the two things the
// bare pattern list could not (#729):
//
//   - THE SCAN ROOT. Every input path is absolutized before matching, and filepath.Match's `*`
//     stops at a separator — so a RELATIVE pattern containing a separator (`nest/sub`,
//     `build/out`, `nest/*/mid.txt`) could never match anything, silently. Measured: `--exclude
//     nest/sub` scanned nest/sub and warned nothing, while the same pattern spelled absolutely
//     worked. The rel arm below matches such patterns against the path RELATIVE TO THE SCAN ROOT,
//     which is the spelling a user reading their own tree naturally writes.
//
//   - PER-PATTERN HIT COUNTS. The silent-no-op class is wider than the separator case ('**' is
//     not glob syntax filepath.Match knows; a typo'd name matches nothing) and cannot be closed
//     pattern-shape by pattern-shape. What CAN be closed is the silence: a pattern that matched
//     nothing by the end of the walk is reported, once, with the likely reasons. For a scanner,
//     scanning MORE than intended is the safe failure direction — but only if the user is told.
type excludeMatcher struct {
	patterns []string
	root     string // absolute scan root; "" disables the rel arm
	hits     []int  // parallel to patterns; the walk is sequential, so plain ints
}

func newExcludeMatcher(patterns []string, root string) *excludeMatcher {
	if root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			root = filepath.Clean(abs)
		} else {
			root = ""
		}
	}
	return &excludeMatcher{patterns: patterns, root: root, hits: make([]int, len(patterns))}
}

// match reports whether filePath is excluded, crediting the first pattern that claims it.
func (m *excludeMatcher) match(filePath string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}
	cleanPath := filepath.Clean(filePath)
	fileName := filepath.Base(cleanPath)
	segments := strings.Split(cleanPath, string(filepath.Separator))

	rel := ""
	if m.root != "" {
		if r, err := filepath.Rel(m.root, cleanPath); err == nil && r != ".." &&
			!strings.HasPrefix(r, ".."+string(filepath.Separator)) && r != "." {
			rel = r
		}
	}

	for i, pattern := range m.patterns {
		// A trailing "/" means "this is a directory name". Strip it and let the segment arm
		// do the work; a separate arm would be a second spelling of the same rule.
		trimmed := strings.TrimSuffix(pattern, "/")
		if trimmed == "" {
			continue
		}

		// The whole path, and the basename.
		if matched, err := filepath.Match(trimmed, cleanPath); err == nil && matched {
			m.hits[i]++
			return true
		}
		if matched, err := filepath.Match(trimmed, fileName); err == nil && matched {
			m.hits[i]++
			return true
		}

		// Each path segment, which is what makes "--exclude .git" work at any depth.
		matchedSegment := false
		for _, segment := range segments {
			if segment == "" {
				continue
			}
			if matched, err := filepath.Match(trimmed, segment); err == nil && matched {
				matchedSegment = true
				break
			}
		}
		if matchedSegment {
			m.hits[i]++
			return true
		}

		// The rel arm, only for patterns that CONTAIN a separator — single-segment patterns are
		// fully served above, and running them here would change no verdict while doubling the
		// work. The pattern is matched against the root-relative path, and against each ancestor
		// prefix of it, so `nest/sub` excludes the directory and everything under it exactly as
		// the segment arm does for single names.
		if rel != "" && strings.ContainsRune(trimmed, filepath.Separator) {
			if matchRelPattern(trimmed, rel) {
				m.hits[i]++
				return true
			}
			parts := strings.Split(rel, string(filepath.Separator))
			prefix := ""
			for _, p := range parts[:len(parts)-1] {
				if prefix == "" {
					prefix = p
				} else {
					prefix += string(filepath.Separator) + p
				}
				if matchRelPattern(trimmed, prefix) {
					m.hits[i]++
					return true
				}
			}
		}
	}
	return false
}

// zeroHitNote returns one stderr-ready line naming patterns that matched nothing this scan, or ""
// when every pattern earned its place. One line for all of them, not one per pattern: an exclude
// list shared across repositories legitimately carries entries for trees this repo does not have,
// and a per-pattern warning would train users to ignore the channel.
func (m *excludeMatcher) zeroHitNote() string {
	if m == nil {
		return ""
	}
	var misses []string
	for i, p := range m.patterns {
		if strings.TrimSuffix(p, "/") == "" {
			continue
		}
		if m.hits[i] == 0 {
			misses = append(misses, p)
		}
	}
	if len(misses) == 0 {
		return ""
	}
	return fmt.Sprintf("Note: %d --exclude pattern(s) matched nothing in this scan: %v — "+
		"patterns are globs ('**' is not supported); a relative pattern with '/' is resolved "+
		"against the scan root", len(misses), misses)
}

// matchRelPattern matches a root-relative path against a multi-segment pattern, with real `**`
// support — because without it, `**` is worse than unsupported. filepath.Match treats `**` as `*`,
// so `**/*.pyc` silently matched at exactly ONE directory level: deeper files stayed in while the
// pattern "worked" enough to suppress the zero-hit note. A pattern that half-works is the same
// silent class #729 exists to close, one layer down.
//
// Semantics: the pattern is split on the separator; `**` as a whole segment matches ZERO OR MORE
// path segments; every other segment is a filepath.Match glob against exactly one path segment.
// Classic doublestar recursion; both inputs are short (path depth), so the worst case is trivial.
func matchRelPattern(pattern, rel string) bool {
	if !strings.Contains(pattern, "**") {
		ok, err := filepath.Match(pattern, rel)
		return err == nil && ok
	}
	return matchSegments(
		strings.Split(pattern, string(filepath.Separator)),
		strings.Split(rel, string(filepath.Separator)))
}

func matchSegments(pat, segs []string) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		// Zero segments, or consume one and stay on the same **.
		if matchSegments(pat[1:], segs) {
			return true
		}
		return len(segs) > 0 && matchSegments(pat, segs[1:])
	}
	if len(segs) == 0 {
		return false
	}
	ok, err := filepath.Match(pat[0], segs[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pat[1:], segs[1:])
}
