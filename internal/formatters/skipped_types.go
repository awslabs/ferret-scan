// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// A count of skipped files is not a disclosure. It is a number the operator has to take on trust.
//
// Scanning this repository reported "Filtered out 14 unsupported file types" and "14 skipped", and
// nothing anywhere said WHICH 14. No flag would tell you: --verbose adds only the same count, and the
// NotExaminedFooter deliberately does not cover this cause, because docs/COVERAGE_DISCLOSURE.md argues
// — correctly — that an unprocessable type is a genuine skip rather than lost coverage, so listing it
// in a footer meaning "we may have missed something here" would be reporting a non-event.
//
// That argument is about the FOOTER, not about naming the files, and the gap it leaves is real: the
// output is byte-identical whether those 14 are build detritus or fourteen customer documents. Here
// they were 13 compiled Go test binaries and a .DS_Store, so no coverage was lost — but the operator
// had no way to establish that, on the one axis where a mistake is silent.
//
// It matters more than it sounds because the supported-type list has been wrong before. #421 is open
// for `.rtf`; `.rtf`, `.tmp` and `.pages` were once advertised by the finder and then reported CLEAN by
// the scanner; and registering `.3gp` reached the preprocessor and still produced nothing, because
// three separate places have to agree before a type is really handled. Each was a file the tool
// BELIEVED it could not usefully process while a user believed otherwise, and a bare count makes that
// entire class invisible.
//
// # Grouped by extension, and why not by reason
//
// Measured: all 14 skips on this repository return the single reason "Unsupported file type", so a
// reason histogram has one bucket and says nothing. Extension is the axis that discriminates, and it
// is what the operator recognises — ".test × 13" is immediately identifiable as build output.
//
// The skip decision is NOT extension-based: a one-byte file named f.test IS scanned while a 20MB Mach-O
// of the same name is not. So this histogram describes the FILES, not the rule. That is the right way
// round for a disclosure — it tells the operator what was declined, not how the router decided.

// MaxSkippedTypesShown bounds the histogram so a large tree cannot produce an unbounded line.
//
// 6, and the overflow is DISCLOSED rather than silently dropped: a truncation that reads as
// completeness is the defect this whole change exists to fix, so "and N more types" is not optional.
const MaxSkippedTypesShown = 6

// SkippedTypeLabel names a file's type for grouping.
//
// filepath.Ext is not enough alone. For a dotfile with no second dot it returns the WHOLE name —
// filepath.Ext(".DS_Store") is ".DS_Store", not "" — which happens to read well here but would render
// ".gitignore" as an extension. Both are named as the file itself, which is what an operator would call
// them, and a file with no extension is grouped as "(no extension)" rather than silently sharing a
// bucket with dotfiles.
func SkippedTypeLabel(path string) string {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") && strings.Count(base, ".") == 1 {
		return base
	}
	if ext := filepath.Ext(base); ext != "" {
		return strings.ToLower(ext)
	}
	return "(no extension)"
}

// SkippedTypeCounts groups skipped file paths into a type histogram.
//
// Returned as a map so machine formats can carry the structured value — ScanStats.SkippedTypes is
// serialised to json and yaml — while FormatSkippedTypes renders the same data for human output. One
// producer, two renderings, so the two cannot disagree about what was skipped.
func SkippedTypeCounts(paths []string) map[string]int {
	if len(paths) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, p := range paths {
		counts[SkippedTypeLabel(p)]++
	}
	return counts
}

// FormatSkippedTypes renders a parenthesised histogram, or "" when there is nothing to say.
//
// Sorted by descending count then by label, so the same input always renders the same string. Ranging
// the map directly would make this nondeterministic, and this line goes into CI logs people diff and
// into test output.
func FormatSkippedTypes(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}

	type entry struct {
		label string
		n     int
	}
	entries := make([]entry, 0, len(counts))
	for l, n := range counts {
		entries = append(entries, entry{l, n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].n != entries[j].n {
			return entries[i].n > entries[j].n
		}
		return entries[i].label < entries[j].label
	})

	shown, hidden := entries, 0
	if len(entries) > MaxSkippedTypesShown {
		shown, hidden = entries[:MaxSkippedTypesShown], len(entries)-MaxSkippedTypesShown
	}

	parts := make([]string, 0, len(shown)+1)
	for _, e := range shown {
		parts = append(parts, fmt.Sprintf("%s × %d", e.label, e.n))
	}
	if hidden > 0 {
		noun := "types"
		if hidden == 1 {
			noun = "type"
		}
		parts = append(parts, fmt.Sprintf("and %d more %s", hidden, noun))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// SummarizeSkippedTypes is the path-list convenience form of FormatSkippedTypes.
func SummarizeSkippedTypes(paths []string) string {
	return FormatSkippedTypes(SkippedTypeCounts(paths))
}
