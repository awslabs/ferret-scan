// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

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
}

// LastGeneration reports what the most recent GenerateSuppressionRules call wrote: the zero report
// before the first call and after one whose save failed. Like the mutators, it is not safe for use
// concurrently with them.
func (sm *SuppressionManager) LastGeneration() GenerationReport {
	return sm.lastGeneration
}
