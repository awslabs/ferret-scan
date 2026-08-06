// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// formatsDisclosingTruncationInBand are the formats that already say, inside the
// report itself, that --limit dropped findings.
//
// Measured on a 3-finding scan at --limit 1: text prints "... and 2 more
// findings", json/yaml carry `truncated: true` with the real total, junit uses
// <system-out>, sarif uses run properties, gitlab-sast uses the scan block. Only
// CSV has nowhere to put it — a comment line is not CSV syntax and an extra data
// row inflates the count consumers read.
var formatsDisclosingTruncationInBand = map[string]bool{
	"text":        true,
	"json":        true,
	"yaml":        true,
	"junit":       true,
	"sarif":       true,
	"gitlab-sast": true,
}

// truncationNote returns the out-of-band message announcing that --limit dropped
// findings, or "" when the report is complete or already says so itself.
//
// It used to be emitted for EVERY format "since it costs nothing to be
// consistent". It does cost something: on six of the seven formats it repeats a
// disclosure the report already contains, immediately after it, so the tail of a
// truncated scan said the same thing twice in different words. Consistency across
// formats is not worth a duplicated line in the common case, so the note is now
// scoped to the one format that needs it.
//
// Without any disclosure a truncated report is indistinguishable from a complete
// one: the count looks authoritative, so silently under-reporting is worse for a
// security tool than reporting nothing at all. That is why CSV still gets it.
func truncationNote(matches []detector.Match, options formatters.FormatterOptions, limit int, format string) string {
	if limit <= 0 {
		return ""
	}
	if formatsDisclosingTruncationInBand[format] {
		return ""
	}

	// Count the CONFIDENCE-FILTERED set, not every unsuppressed match. Formatters
	// filter by confidence and only then apply the limit, so the two sets diverge
	// whenever --confidence is narrowed: on a 37-finding scan holding one HIGH
	// finding, `--confidence high --limit 3` emits a complete 1-row report, and
	// counting the unfiltered set announced "limited to 3 of 37". Announcing
	// truncation that did not happen is the same class of bug as hiding truncation
	// that did, so this reuses the formatters' own filter instead of reimplementing
	// the predicate and letting the two drift.
	shown := shared.FilterMatchesByConfidence(matches, options)
	if len(shown) <= limit {
		return ""
	}

	// CSV only. Named as a CSV limitation so the reader knows why this one format
	// needs an out-of-band line when the others do not.
	return fmt.Sprintf(
		"NOTE: csv cannot carry metadata, so this is out of band — %d of %d findings "+
			"shown (--limit %d). Use --limit 0 for all.\n",
		limit, len(shown), limit)
}
