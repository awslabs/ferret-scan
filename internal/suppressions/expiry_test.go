// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A generated suppression rule used to expire after one week, always.
//
// That made a committed, hand-reviewed baseline inert seven days after it was generated — silently,
// because IsSuppressed passes over an expired rule with a bare `continue`. Measured on this
// repository's own .ferret-scan-suppressions.yaml: all 245 rules, 92 of them enabled: true and
// hand-reviewed, carried expires_at 2026-05-28 and had therefore been doing nothing for about four
// months, while the file's own header said contributors and CI shared it as a baseline (#696).
//
// A suppression is a decision someone made deliberately. It now lasts until someone changes it, and
// expiry is opt-in.
func TestAGeneratedRuleDoesNotExpireByDefault(t *testing.T) {
	sm := managerWithRule(t, nil)

	if len(sm.config.Rules) == 0 {
		t.Fatalf("no rule was created, so this test measures nothing")
	}
	for _, r := range sm.config.Rules {
		if r.ExpiresAt != nil {
			t.Errorf("rule %s expires at %s. A generated rule must not expire unless asked: a "+
				"default expiry turns a committed baseline into a file that stops working a week "+
				"later with nothing to show it.", r.ID, r.ExpiresAt.Format(time.RFC3339))
		}
	}
}

// TestOptingIntoAnExpiryStillWorks is the other half — removing the default must not remove the
// capability, or a team that wants suppressions to lapse loses it.
func TestOptingIntoAnExpiryStillWorks(t *testing.T) {
	const lifetime = 720 * time.Hour // 30 days
	before := time.Now()
	sm := managerWithRule(t, func(sm *SuppressionManager) { sm.SetGeneratedExpiry(lifetime) })

	if len(sm.config.Rules) == 0 {
		t.Fatalf("no rule was created")
	}
	for _, r := range sm.config.Rules {
		if r.ExpiresAt == nil {
			t.Fatalf("rule %s has no expiry despite SetGeneratedExpiry(%s)", r.ID, lifetime)
		}
		got := r.ExpiresAt.Sub(before)
		// Generous bounds: the point is that the lifetime was honoured, not its exact nanosecond.
		if got < lifetime-time.Minute || got > lifetime+time.Minute {
			t.Errorf("rule %s expires in %s, want about %s", r.ID, got, lifetime)
		}
	}

	// And zero must mean none, since that is the default path.
	sm2 := managerWithRule(t, func(sm *SuppressionManager) { sm.SetGeneratedExpiry(0) })
	for _, r := range sm2.config.Rules {
		if r.ExpiresAt != nil {
			t.Errorf("SetGeneratedExpiry(0) still produced an expiry (%s); zero must mean no expiry",
				r.ExpiresAt.Format(time.RFC3339))
		}
	}
}

// TestARuleWithNoExpiryStillSuppresses is the floor under the change.
//
// Removing the expiry would be worthless — worse, actively harmful — if a rule without one stopped
// matching. Every assertion above is about a FIELD; this one is about the behaviour that field exists
// to bound.
func TestARuleWithNoExpiryStillSuppresses(t *testing.T) {
	sm := managerWithRule(t, nil)
	// Rules are created disabled by design, so a test that forgets this passes for free.
	for i := range sm.config.Rules {
		sm.config.Rules[i].Enabled = true
	}
	sm.rebuildIndexIfNeeded(t)

	suppressed, rule := sm.IsSuppressed(expiryTestMatch())
	if !suppressed {
		t.Fatalf("a rule with no expiry did not suppress its own finding; removing the default expiry "+
			"has broken matching. Rules: %+v", sm.config.Rules)
	}
	if rule.ExpiresAt != nil {
		t.Errorf("the matching rule carries an expiry: %s", rule.ExpiresAt.Format(time.RFC3339))
	}
	if n, _ := sm.ExpiredSkips(); n != 0 {
		t.Errorf("ExpiredSkips = %d for a rule that is not expired", n)
	}
}

// TestAnExpiredRuleIsCountedAndDated is the disclosure's data source.
//
// The whole reason a lapsed baseline went unnoticed for four months is that this was not counted:
// IsSuppressed skips an expired rule and says nothing. Counted at MATCH time on purpose — "3 findings
// are in your report that your own rules were meant to suppress" is actionable, where "the file holds
// 245 expired rules" does not say whether any of them mattered.
func TestAnExpiredRuleIsCountedAndDated(t *testing.T) {
	sm := managerWithRule(t, nil)
	expired := time.Now().Add(-72 * time.Hour)
	older := time.Now().Add(-240 * time.Hour)
	for i := range sm.config.Rules {
		sm.config.Rules[i].Enabled = true
		sm.config.Rules[i].ExpiresAt = &expired
	}
	sm.rebuildIndexIfNeeded(t)

	suppressed, _ := sm.IsSuppressed(expiryTestMatch())
	if suppressed {
		t.Fatalf("an expired rule suppressed a finding; the expiry check is not running and the count " +
			"below would be meaningless")
	}
	n, oldest := sm.ExpiredSkips()
	if n != 1 {
		t.Errorf("ExpiredSkips = %d, want 1 — a rule that matched by hash but had expired must be "+
			"counted, or a baseline can stop working with nothing to show it", n)
	}
	if oldest == nil || !oldest.Equal(expired) {
		t.Errorf("oldest = %v, want %v", oldest, expired)
	}

	// A second, older expiry must move the reported date backwards, since that is the one an operator
	// needs to see ("how long has this been broken").
	sm.noteExpiredSkip(older)
	if _, o := sm.ExpiredSkips(); o == nil || !o.Equal(older) {
		t.Errorf("oldest = %v after seeing an older expiry, want %v", o, older)
	}
	if n2, _ := sm.ExpiredSkips(); n2 != 2 {
		t.Errorf("count = %d, want 2", n2)
	}
}

// TestExpiredSkipCountingIsConcurrencySafe matters because of where IsSuppressed is called from.
//
// The redaction filter runs it on worker goroutines as well as the report path, so the counter is
// atomic and the date is guarded by its OWN mutex — not indexMu, which IsSuppressed already holds
// read-locked across the match loop. Reusing indexMu would deadlock on the write lock, which is the
// kind of thing that shows up as a hung CI job rather than a failure.
func TestExpiredSkipCountingIsConcurrencySafe(t *testing.T) {
	sm := managerWithRule(t, nil)
	expired := time.Now().Add(-time.Hour)
	for i := range sm.config.Rules {
		sm.config.Rules[i].Enabled = true
		sm.config.Rules[i].ExpiresAt = &expired
	}
	sm.rebuildIndexIfNeeded(t)

	const goroutines, each = 8, 50
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// Exercises the real path: match, find the rule expired, count it.
				sm.IsSuppressed(expiryTestMatch())
				sm.ExpiredSkips()
			}
		}()
	}
	wg.Wait()

	if n, _ := sm.ExpiredSkips(); n != goroutines*each {
		t.Errorf("ExpiredSkips = %d, want %d — a lost increment means the counter is racy and the "+
			"disclosure would under-report", n, goroutines*each)
	}
}

// ---- helpers ----

// expiryTestMatch is named apart from the package's existing testMatch, which takes arguments.
func expiryTestMatch() detector.Match {
	return detector.Match{
		Type:       "SSN",
		Text:       "219-09-9998",
		Filename:   "roster.txt",
		LineNumber: 7,
		Confidence: 95,
		Validator:  "ssn",
		Context: detector.ContextInfo{
			BeforeText: "Employee SSN: ",
			AfterText:  "\n",
			FullLine:   "Employee SSN: 219-09-9998",
		},
	}
}

// managerWithRule builds a manager in a temp dir and adds one rule for expiryTestMatch().
func managerWithRule(t *testing.T, configure func(*SuppressionManager)) *SuppressionManager {
	t.Helper()
	sm := NewSuppressionManager(filepath.Join(t.TempDir(), "sup.yaml"))
	if configure != nil {
		configure(sm)
	}
	if err := sm.AddSuppression(expiryTestMatch(), "test", "unit test", nil); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	return sm
}

// rebuildIndexIfNeeded re-derives rulesByHash after a test mutates config.Rules directly.
//
// AddSuppression builds the index when it saves; poking Enabled/ExpiresAt afterwards does not. Without
// this, IsSuppressed matches nothing and every assertion about matching passes for the wrong reason.
func (sm *SuppressionManager) rebuildIndexIfNeeded(t *testing.T) {
	t.Helper()
	sm.indexMu.Lock()
	sm.rulesByHash = make(map[string][]int, len(sm.config.Rules))
	for i, r := range sm.config.Rules {
		sm.rulesByHash[r.Hash] = append(sm.rulesByHash[r.Hash], i)
	}
	sm.indexMu.Unlock()
	if len(sm.rulesByHash) == 0 {
		t.Fatalf("the rule index is empty after a rebuild; no rule can match and the test is vacuous")
	}
}
