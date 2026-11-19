// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"

	"github.com/awslabs/ferret-scan/v2/internal/displaytext"
)

// writeExcludedSummary says, once, how many paths the operator's own --exclude patterns and
// .gitignore rules left out of the scan (#1008).
//
// It replaces one "Warning: Skipping <path>: excluded by .gitignore" line per path. An exclusion the
// operator asked for is honoured, not a warning, and a line per path is the pattern the not-examined
// report was built to avoid. The paths themselves are listed only when list is true (--verbose or
// --debug). The counts are still in the run's own accounting (files_skipped and the skipped-type
// histogram), so nothing is lost by withholding the note under --quiet.
//
// shortcut: the list is not capped; it is opt-in, and the cap the not-examined report uses protects a
// default-on channel. Cap it here if --verbose output on a huge tree is ever reported as unreadable.
func writeExcludedSummary(w io.Writer, excluded []SkippedFile, list bool) {
	if len(excluded) == 0 {
		return
	}
	var byIgnore, byPattern int
	for _, e := range excluded {
		if e.Reason == excludedByGitignore {
			byIgnore++
		} else {
			byPattern++
		}
	}
	by := ""
	switch {
	case byIgnore > 0 && byPattern > 0:
		by = fmt.Sprintf(" (.gitignore: %d, --exclude: %d)", byIgnore, byPattern)
	case byIgnore > 0:
		by = " (.gitignore)"
	default:
		by = " (--exclude)"
	}
	if list {
		fmt.Fprintf(w, "Note: %d path(s) left out as requested%s:\n", len(excluded), by)
		for _, e := range excluded {
			fmt.Fprintf(w, "  %s: %s\n", displaytext.SanitizeDisplayText(e.Path), e.Reason)
		}
		return
	}
	fmt.Fprintf(w, "Note: %d path(s) left out as requested%s. Re-run with --verbose to list them.\n", len(excluded), by)
}
