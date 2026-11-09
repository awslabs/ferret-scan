// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Rules that matched nothing (#885).
//
// A rule stops matching when its finding moves, changes or is removed, and nothing said so: on the
// issue's 39-file set, with the 473 rules generated at v2.4.0 enabled, 270 matched nothing at the
// v2.6.0 development head and stderr carried only "Suppressed 238 findings". IsSuppressed records
// which rules matched a finding (runLedger), and
// UnmatchedRules lists the enabled rules that did not, restricted to the ones the run could have
// matched, so a rule for a file the run never opened is not reported.

// runLedger records what IsSuppressed saw during one run: the rule hashes that matched a finding, and
// the finding types reported. Sets, so asking twice about one finding records it once: under
// --enable-redaction the worker pool asks before redacting and the report path asks again. Keyed by
// hash rather than by a rule's position, so a mutation that reorders the rules cannot misattribute a
// hit. Its own lock, because IsSuppressed runs on the worker pool's goroutines; after the first
// findings of a run every call finds what it would record already there and takes only the read lock.
type runLedger struct {
	mu    sync.RWMutex
	hits  map[string]struct{}
	types map[string]struct{}
}

// record notes a finding of findingType, and the rule hashes among its candidates that a live rule holds.
func (l *runLedger) record(findingType string, hits []string) {
	l.mu.RLock()
	_, known := l.types[findingType]
	for _, h := range hits {
		if _, ok := l.hits[h]; !ok {
			known = false
			break
		}
	}
	l.mu.RUnlock()
	if known {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.types == nil {
		l.types = make(map[string]struct{})
	}
	l.types[findingType] = struct{}{}
	for _, h := range hits {
		l.markHitLocked(h)
	}
}

// markHit notes that the rule holding h has a finding in this run.
func (l *runLedger) markHit(h string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.markHitLocked(h)
}

func (l *runLedger) markHitLocked(h string) {
	if l.hits == nil {
		l.hits = make(map[string]struct{})
	}
	l.hits[h] = struct{}{}
}

// RunScope is what one run examined. UnmatchedRules counts a rule only when the run could have matched
// it: a rule for a file the run never read, or of a type no check that ran produces, matched nothing
// because it could not, and reporting it would bury the rules that need attention.
type RunScope struct {
	// Files are the files whose scan completed, as paths, or the --stdin-name label (default
	// "<stdin>"). A rule belongs to the run when its metadata.filename is the basename of one of them.
	// Leave out a file that could not be read, yielded no text, or whose scan was cut short: a rule for
	// it may have matched nothing only because its finding was never looked for.
	Files []string
	// AllChecks says every check ran, with no --checks, profile or config narrowing and no disabled
	// type. Then a rule counts whatever its finding type. Otherwise a rule counts only when this run
	// reported a finding of its type, the one sign available here that a check producing it ran, and a
	// rule left out for that reason makes the report Partial.
	AllChecks bool
}

// UnmatchedReport lists the enabled rules that matched no finding of a run although the run could
// have matched them.
type UnmatchedReport struct {
	// IDs names, in file order, every enabled, applied, unexpired rule that belongs to the run's scope
	// and matched no finding. A rule with no id is named by its position, "rule #N".
	IDs []string
	// Partial says the run was narrowed (RunScope.AllChecks unset) and at least one enabled rule for
	// a scanned file was not counted, because no finding of its type was reported: whether it would
	// have matched is unknown.
	Partial bool
	// Unattributed counts the enabled, applied, unexpired rules that matched no finding and carry no
	// metadata.filename, so whether their file was scanned is unknown. They are not in IDs.
	Unattributed int
}

// Count is the number of rules the report names: the value for a "rules matched nothing" counter.
func (r UnmatchedReport) Count() int { return len(r.IDs) }

// UnmatchedRules reports the enabled rules that matched no finding in this manager's run, counting
// only those scope says the run could have matched. Call it after every finding of the run has been
// through IsSuppressed, which records the matches. A rule re-anchored by GenerateSuppressionRules counts
// as matched: its finding is in the run, at another line. Expired, disabled and refused (#866) rules
// are never counted: ExpiredSkips and the loader already report the first and last, and a disabled
// rule is a finding not yet reviewed. Safe for use concurrently with IsSuppressed.
func (sm *SuppressionManager) UnmatchedRules(scope RunScope) UnmatchedReport {
	var report UnmatchedReport
	if !sm.enabled || sm.config == nil {
		return report
	}
	scanned := make(map[string]bool, len(scope.Files))
	for _, f := range scope.Files {
		scanned[filepath.Base(f)] = true
	}
	now := time.Now()

	sm.ledger.mu.RLock()
	defer sm.ledger.mu.RUnlock()
	sm.indexMu.RLock()
	defer sm.indexMu.RUnlock()
	for i := range sm.config.Rules {
		rule := &sm.config.Rules[i]
		if !rule.Enabled || rule.NotApplied != "" || (rule.ExpiresAt != nil && now.After(*rule.ExpiresAt)) {
			continue
		}
		if _, hit := sm.ledger.hits[rule.Hash]; hit {
			continue
		}
		name := strings.TrimSpace(rule.Metadata["filename"])
		if name == "" {
			report.Unattributed++
			continue
		}
		if !scanned[name] {
			continue
		}
		if !scope.AllChecks {
			if _, reported := sm.ledger.types[strings.TrimSpace(rule.Metadata["finding_type"])]; !reported {
				report.Partial = true
				continue
			}
		}
		id := rule.ID
		if id == "" {
			id = fmt.Sprintf("rule #%d", i+1)
		}
		report.IDs = append(report.IDs, id)
	}
	return report
}

// unmatchedNoteNames is how many rule ids the note spells out before "and N more".
const unmatchedNoteNames = 10

// WriteUnmatchedRulesNote prints one line naming the rules in r, or nothing when there are none. It is
// a note, not a warning: the exit code does not change, because a rule that matched nothing hides
// nothing.
func WriteUnmatchedRulesNote(w io.Writer, r UnmatchedReport) {
	if len(r.IDs) == 0 {
		return
	}
	names := r.IDs
	more := ""
	if len(names) > unmatchedNoteNames {
		more = fmt.Sprintf(", and %d more", len(names)-unmatchedNoteNames)
		names = names[:unmatchedNoteNames]
	}
	partial := ""
	if r.Partial {
		partial = " Rules of a type this narrowed run reported no finding of were not checked."
	}
	fmt.Fprintf(w, "Note: %d enabled suppression rule(s) for files scanned in this run matched no finding "+
		"(the finding moved, changed, or was removed): %s%s. Run --generate-suppressions to re-anchor the "+
		"ones whose finding only moved.%s\n", len(r.IDs), strings.Join(names, ", "), more, partial)
}
