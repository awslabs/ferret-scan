// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"io"
)

// GenerationReport counts what one GenerateSuppressionRules call did to the rule file.
type GenerationReport struct {
	// Added is the number of rules appended for findings no rule matched.
	Added int
	// Refreshed is the number of findings whose existing rule had last_seen_at updated; it includes
	// the findings of the Migrated rules.
	Refreshed int
	// Migrated is the number of existing rules, matched through an older hash formula, whose hash was
	// rewritten to the current one (#885). Their other fields are unchanged. A binary older than this
	// one does not read the current formula, so it stops matching a migrated rule whose finding has
	// whitespace or a `\r` at a window edge.
	Migrated int
	// ReAnchored is the number of rules that matched no finding and were moved to the finding they
	// identify at the line number they recorded: their hash (in the current formula),
	// metadata.line_number and last_seen_at were rewritten, and nothing else. Their findings are not
	// counted in Refreshed, nor the rules in Migrated.
	ReAnchored int
	// Ambiguous is the number of rules left as they are because the move was not one-to-one: the rule
	// fits more than one finding (a repeated line, or same-named files with the finding at different
	// lines), or its finding fits another rule as well.
	Ambiguous int
	// Unmatched is the number of rules for a basename and finding type this run has findings of that
	// fit none of them, left as they are: the line was edited or the finding removed, or the rule
	// records no usable line number to re-anchor from. Rules for files or types without findings in the
	// run are not counted, because the run may not have scanned them.
	Unmatched int
	// NotEvaluated is the number of rules the re-anchoring search did not consider because it reached
	// MaxReanchorComparisons; they are left as they are.
	NotEvaluated int
}

// LastGeneration reports what the most recent GenerateSuppressionRules call wrote: the zero report
// before the first call and after one whose save failed. Like the mutators, it is not safe for use
// concurrently with them.
func (sm *SuppressionManager) LastGeneration() GenerationReport {
	return sm.lastGeneration
}

// WriteGenerationReport prints r, the counts --generate-suppressions reports: one line of counts, and a
// note for each kind of rule it left alone that the operator may want to look at.
func WriteGenerationReport(w io.Writer, r GenerationReport) {
	fmt.Fprintf(w, "Updated suppression rules: added %d (disabled by default), refreshed %d, re-anchored %d, "+
		"migrated %d to the current hash formula\n", r.Added, r.Refreshed, r.ReAnchored, r.Migrated)
	if r.ReAnchored > 0 {
		fmt.Fprintf(w, "Note: %d rule(s) whose finding moved to another line now name that line "+
			"(hash, metadata.line_number and last_seen_at rewritten; enabled, expiry and reason kept)\n", r.ReAnchored)
	}
	if r.Ambiguous > 0 {
		fmt.Fprintf(w, "Note: %d rule(s) were not re-anchored because their finding cannot be told apart "+
			"from another (a repeated line, or a file of the same name elsewhere); they are unchanged\n", r.Ambiguous)
	}
	if r.Unmatched > 0 {
		fmt.Fprintf(w, "Note: %d rule(s) for files with findings in this run matched none of them (the line "+
			"was edited, or the finding removed); they are unchanged\n", r.Unmatched)
	}
	if r.NotEvaluated > 0 {
		fmt.Fprintf(w, "Note: re-anchoring stopped at its limit of %d comparisons; %d rule(s) were not "+
			"considered and are unchanged\n", MaxReanchorComparisons, r.NotEvaluated)
	}
}
