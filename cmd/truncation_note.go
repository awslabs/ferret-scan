// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// truncationNote returns the out-of-band message announcing that --limit dropped
// findings, or "" when the report is complete.
//
// The four machine-readable formats declare truncation in band (SARIF run
// properties, the GitLab scan block, JUnit <system-out>), but CSV cannot: it is a
// pure tabular format with nowhere to put metadata. A comment line is not CSV
// syntax and a strict parser rejects it, and an extra data row inflates the row
// count consumers use to count findings — TestLimit_EveryFormatHonorsIt asserts
// exactly that contract and caught the attempt.
//
// So CSV's disclosure is out of band, and since it costs nothing to be consistent
// it is emitted for every format. The caller writes it to stderr, not stdout, so
// redirecting a report to a file still yields a clean parseable artifact.
//
// Without any disclosure a truncated report is indistinguishable from a complete
// one: the count looks authoritative, so silently under-reporting is worse for a
// security tool than reporting nothing at all.
func truncationNote(matches []detector.Match, options formatters.FormatterOptions, limit int) string {
	if limit <= 0 {
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

	return fmt.Sprintf(
		"NOTE: output limited to %d of %d findings by --limit. Re-run with --limit 0 to see all.\n",
		limit, len(shown))
}
