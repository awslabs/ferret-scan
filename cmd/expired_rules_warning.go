// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"time"
)

// writeExpiredRulesWarning says that n findings are in the report because the rule that would have
// suppressed them has EXPIRED. Both input paths print it; it is silent for n == 0.
//
// IsSuppressed passes over an expired rule with a bare `continue`, so a baseline could stop working
// entirely and every run still looked normal. That is exactly what happened to this repository's own
// committed baseline: all 245 rules carried a one-week expiry, and had been inert for about four months
// while the file's header claimed contributors and CI shared it (#696). Counted at MATCH time rather than
// by walking the file, because "3 findings are in your report that your own rules were meant to suppress"
// is actionable, where "the file holds 245 expired rules" does not say whether any of them mattered.
//
// The remedies are ones a release can carry out. The warning used to end "or run `ferret-scan-suppress
// --action cleanup` to drop them", a binary no release builds (.goreleaser.yml builds ./cmd only, and
// cmd/suppress calls itself ferret-suppress), and "regenerate the rules", which re-running
// --generate-suppressions on the same file does not do: it updates an existing rule's last_seen_at and
// keeps its expires_at, so the next run warns again. Measured on two expired rules: 2 still expired after
// the re-run, and the same "2 finding(s)" warning.
func writeExpiredRulesWarning(w io.Writer, n int, oldest *time.Time) {
	if n <= 0 {
		return
	}
	when := ""
	if oldest != nil {
		when = fmt.Sprintf(", oldest expired %s", oldest.Format("2006-01-02"))
	}
	fmt.Fprintf(w,
		"WARNING: %d finding(s) are reported because their suppression rule has EXPIRED%s. "+
			"An expired rule is skipped, so a baseline can stop working without any other sign. "+
			"Edit or remove the expires_at field, use the web UI's bulk expiration control, or delete the "+
			"expired rules and regenerate them.\n", n, when)
}
