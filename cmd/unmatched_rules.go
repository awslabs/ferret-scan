// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// Rules that matched nothing (#885): the stderr note and stats.suppression_rules_unmatched.
//
// A rule stops matching when its finding moves, changes or is removed, and before this nothing said so.
// Measured on main @ 2fb4719 with the issue's fixture (5 rules generated on customers.txt and enabled,
// then one line inserted at the top): `active=5 suppressed=0`, exit 0, and no line on stdout or stderr
// naming a rule, through --file and --stdin alike. internal/suppressions records which rules matched
// (#918); this is the CLI half that asks it and says what it answered.

// unmatchedRulesAccount asks the suppression manager, once a run's findings have all been through
// IsSuppressed, which enabled rules matched none of them.
//
// One complication is --generate-suppressions, which rewrites rules in the run it is asked in:
//
//   - a rule it RE-ANCHORS has its finding in this run, at another line, and the manager counts it as
//     matched once generation has run (UnmatchedRules' contract);
//   - a rule it MIGRATES to the current hash formula did match a finding, through an older formula, but
//     the manager recorded the hit under the hash the rule held then, which is no longer the rule's, so
//     asked after generation it reports that rule as matching nothing.
//
// File mode generates after its findings were matched, so asking only after generation would name every
// migrated rule, and asking only before would name every re-anchored one. The account asks at both
// points and reports the rules both answers name: a rule is unmatched only if it matched nothing before
// generation rewrote it and is not re-anchored by it. Generation only appends rules and never reorders
// them, so a rule's id (or "rule #N") names the same rule in both answers. --stdin generates BEFORE it
// matches, so its ledger already holds the migrated hashes and it asks once, after.
type unmatchedRulesAccount struct {
	sm     *suppressions.SuppressionManager
	scope  suppressions.RunScope
	before *suppressions.UnmatchedReport
}

func newUnmatchedRulesAccount(sm *suppressions.SuppressionManager, scope suppressions.RunScope) *unmatchedRulesAccount {
	return &unmatchedRulesAccount{sm: sm, scope: scope}
}

// beforeGeneration records the answer as the run's matching left it. Call it after every finding has been
// through IsSuppressed and before GenerateSuppressionRules rewrites any rule.
func (a *unmatchedRulesAccount) beforeGeneration() {
	if a == nil || a.sm == nil {
		return
	}
	r := a.sm.UnmatchedRules(a.scope)
	a.before = &r
}

// report is the rules that matched no finding of the run, for the note and the stats counter.
func (a *unmatchedRulesAccount) report() suppressions.UnmatchedReport {
	if a == nil || a.sm == nil {
		return suppressions.UnmatchedReport{}
	}
	after := a.sm.UnmatchedRules(a.scope)
	if a.before == nil {
		return after
	}
	inBefore := make(map[string]bool, len(a.before.IDs))
	for _, id := range a.before.IDs {
		inBefore[id] = true
	}
	both := suppressions.UnmatchedReport{
		Partial: a.before.Partial || after.Partial,
		// Counted before generation: a rule with no metadata.filename cannot be re-anchored, and only
		// the earlier answer still credits the ones generation migrated.
		Unattributed: a.before.Unattributed,
	}
	for _, id := range after.IDs {
		if inBefore[id] {
			both.IDs = append(both.IDs, id)
		}
	}
	return both
}

// fileRunScope is --file's RunScope: the files the worker pool examined in full, and whether every check
// ran with nothing switched off.
//
// A basename leaves the scope when ANY file of that name was not fully examined (unreadable, no text,
// failed, cut short, refused at discovery): rules carry only the basename, so a rule for the copy that was
// never read would otherwise be reported as matching nothing in the copy that was. A failed worker pool
// examined nothing.
func fileRunScope(scanned []string, poolFailed bool, notExamined []unscannedEntry,
	validators map[string]detector.Validator, disabled map[string][]string) suppressions.RunScope {
	scope := suppressions.RunScope{
		AllChecks: len(validators) == len(core.CheckNames()) && !anyDisabled(disabled),
	}
	if poolFailed {
		return scope
	}
	incomplete := make(map[string]bool, len(notExamined))
	for _, e := range notExamined {
		incomplete[filepath.Base(e.Path)] = true
	}
	for _, f := range scanned {
		if !incomplete[filepath.Base(f)] {
			scope.Files = append(scope.Files, f)
		}
	}
	return scope
}

// stdinRunScope is --stdin's RunScope: the --stdin-name label, unless the scan was cut short, and whether
// every check this path can run ran with nothing switched off. METADATA, which needs a file, is not
// counted as narrowing, as the report's scope block does not count it.
func stdinRunScope(label string, incomplete bool, checksRun, notApplicable []string,
	disabled map[string][]string) suppressions.RunScope {
	scope := suppressions.RunScope{
		AllChecks: len(checksRun)+len(notApplicable) == len(core.CheckNames()) && !anyDisabled(disabled),
	}
	if !incomplete {
		scope.Files = []string{label}
	}
	return scope
}

// anyDisabled reports whether configuration switched any detection sub-type off.
func anyDisabled(disabled map[string][]string) bool {
	for _, subTypes := range disabled {
		if len(subTypes) > 0 {
			return true
		}
	}
	return false
}
