// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestRestoringDeletedRulesRebuildsTheFile: delete rules 1 and 3 of four (what a bulk delete does),
// restore them with the positions they had, and the file is byte-identical — same ids, hashes, dates
// and expiry, in the same order.
func TestRestoringDeletedRulesRebuildsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sup.yaml")
	sm := NewSuppressionManager(path)
	at := time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)
	for line := 1; line <= 4; line++ {
		m := detector.Match{Type: "SSN", Text: "restore-value", Filename: "roster.txt", LineNumber: line, Validator: "ssn"}
		var expiry *time.Time
		if line%2 == 0 {
			expiry = &at
		}
		if err := sm.AddSuppression(m, "reviewed", "tester", expiry); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	listed := append([]SuppressionRule(nil), sm.ListSuppressions()...)

	for _, id := range []string{listed[1].ID, listed[3].ID} {
		if err := sm.RemoveSuppression(id); err != nil {
			t.Fatal(err)
		}
	}
	// Out of order on purpose: the undo sends them as the user selected them.
	restored, refused, err := sm.RestoreSuppressions([]RuleRestore{
		{Rule: listed[3], Position: 3},
		{Rule: listed[1], Position: 1},
	})
	if err != nil || restored != 2 || len(refused) != 0 {
		t.Fatalf("RestoreSuppressions = %d, %v, %v; want 2 restored", restored, refused, err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("the restored file differs from the original:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// Restoring a rule that is present again duplicates nothing.
	restored, refused, err = sm.RestoreSuppressions([]RuleRestore{{Rule: listed[0], Position: 0}, {Rule: SuppressionRule{Hash: "x"}}})
	if err != nil || restored != 0 || len(refused) != 2 {
		t.Errorf("restoring a present rule and an id-less one = %d, %v, %v; want 0 restored, 2 refused", restored, refused, err)
	}
	if n := len(sm.ListSuppressions()); n != 4 {
		t.Errorf("%d rules after refused restores, want 4", n)
	}
}
