// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// webScanStats is the stats block of one /scan, kept so /export can render it as the CLI's --file report
// does (#904). Counts are over the findings the scan's confidence filter reports, banded as cmd/main.go
// bands them (>= 90 high, >= 60 medium, else low).
//
// shortcut: a file whose text extraction came back empty is counted as processed here; the CLI moves
// one that produced no finding to not-examined. Upgrade when the upload path reports empty extractions.
func webScanStats(uploaded int, matches []detector.Match, suppressed int, incomplete []parallel.FileDiagnostic,
	skippedPaths []string, confidence map[string]bool) formatters.ScanStats {
	st := formatters.ScanStats{
		TotalFiles:       uploaded,
		FilesSkipped:     len(skippedPaths),
		SkippedTypes:     formatters.SkippedTypeCounts(skippedPaths),
		FilesNotExamined: distinctPaths(incomplete),
		Suppressed:       suppressed,
	}
	if p := uploaded - st.FilesSkipped - st.FilesNotExamined; p > 0 {
		st.FilesProcessed = p
	}
	for _, m := range matches {
		switch {
		case m.Confidence >= 90:
			if confidence["high"] {
				st.High++
			}
		case m.Confidence >= 60:
			if confidence["medium"] {
				st.Medium++
			}
		default:
			if confidence["low"] {
				st.Low++
			}
		}
	}
	st.TotalFindings = st.High + st.Medium + st.Low
	return st
}

func distinctPaths(diags []parallel.FileDiagnostic) int {
	seen := map[string]bool{}
	for _, d := range diags {
		seen[d.FilePath] = true
	}
	return len(seen)
}

// addScanStats adds two scans' stats for an /export of several scans run with the same settings. The
// disclosure fields (disabled types, config warnings) come from the same configuration, so a's are kept.
func addScanStats(a, b formatters.ScanStats) formatters.ScanStats {
	a.TotalFiles += b.TotalFiles
	a.FilesProcessed += b.FilesProcessed
	a.FilesSkipped += b.FilesSkipped
	a.FilesNotExamined += b.FilesNotExamined
	a.TotalFindings += b.TotalFindings
	a.High += b.High
	a.Medium += b.Medium
	a.Low += b.Low
	a.Suppressed += b.Suppressed
	a.Duration += b.Duration
	if len(b.SkippedTypes) > 0 {
		merged := map[string]int{}
		for k, v := range a.SkippedTypes {
			merged[k] = v
		}
		for k, v := range b.SkippedTypes {
			merged[k] += v
		}
		a.SkippedTypes = merged
	}
	return a
}
