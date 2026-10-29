// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// usAccount returns the single US_BANK_ACCOUNT finding for want on line, failing the test
// if there is not exactly one.
func usAccount(t *testing.T, line, want string) detector.Match {
	t.Helper()
	matches, err := NewValidator().ValidateContent(line, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	var found []detector.Match
	for _, m := range filterByType(matches, "US_BANK_ACCOUNT") {
		if m.Text == want {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%q: want one US_BANK_ACCOUNT %q, got %v", line, want, matchTypes(matches))
	}
	return found[0]
}

// A 12-digit cloud account id on a line that names it is capped at LOW, and the cap is
// published so the document bridge cannot lift it back (#805). On main the issue's line
// scored 85 MEDIUM, and the same line in a CSV row 100 HIGH.
func TestCloudAccountIDBesideBankingWordIsCappedAtLow(t *testing.T) {
	lines := []string{
		// The issue's reproducer.
		"Payer account 210987654321 is the AWS account id for the deposit summary.",
		// Each phrase from the issue, alone, beside a banking word that admits the run.
		"Deposit ledger, AWS account 210987654321",
		"Deposit ledger, account id 210987654321",
		"Deposit ledger, account_id 210987654321",
		"Deposit ledger, payer 210987654321",
		"Deposit ledger, management account 210987654321",
		"Deposit ledger, org id 210987654321",
		"Deposit ledger, subscription id 210987654321",
		"Deposit ledger, project number 210987654321",
		"Deposit ledger, project id 210987654321",
		"Deposit ledger, tenant 210987654321",
		// AWS product names that are banking keywords here: "transit", "savings".
		"Transit Gateway attachment in AWS account 210987654321",
		"Compute Savings Plans for payer account 210987654321",
		// Ceiling, not veto: a value that IS a bank account but is labelled this way is
		// still reported, and therefore still redacted, only at LOW.
		"Payer bank account number 210987654321 routing 021000021",
	}
	for _, line := range lines {
		m := usAccount(t, line, "210987654321")
		if m.Confidence > 55 {
			t.Errorf("%q: US_BANK_ACCOUNT at %.0f, want at most 55 (LOW)", line, m.Confidence)
		}
		ceiling, ok := m.Metadata["confidence_ceiling"].(float64)
		if !ok || ceiling != 55 {
			t.Errorf("%q: confidence_ceiling = %v, want 55.0 so the document bridge cannot lift it",
				line, m.Metadata["confidence_ceiling"])
		}
	}
}

// The issue's controls and the shapes the cap must not reach keep the confidence they had
// before #805, with no ceiling published. Passes on main too; it is the scope proof.
func TestCloudAccountCeilingLeavesOtherAccountNumbersAlone(t *testing.T) {
	tests := []struct {
		line, text string
		want       float64
	}{
		{"Account number: 210987654321 routing 021000021", "210987654321", 100},
		{"Bank account number: 210987654321", "210987654321", 100},
		{"Account number: 210987654321 at the bank", "210987654321", 100},
		{"Direct deposit to checking account 210987654321", "210987654321", 100},
		{"Routing number 021000021 account 1234567890 for payroll.", "1234567890", 100},
		// Only a 12-digit run is the cloud shape; other lengths score as before.
		{"AWS account 2109876543 deposit summary", "2109876543", 85},
		{"AWS account id 2109876543210 for the deposit summary", "2109876543210", 85},
		// The phrases need a separator between their words, like every demoting list here,
		// so a camelCase JSON key is not one. Deliberate: see cloudAccountPhrases.
		{`{"accountId": "210987654321", "note": "deposit"}`, "210987654321", 85},
	}
	for _, tt := range tests {
		m := usAccount(t, tt.line, tt.text)
		if m.Confidence != tt.want {
			t.Errorf("%q: US_BANK_ACCOUNT %q at %.0f, want %.0f", tt.line, tt.text, m.Confidence, tt.want)
		}
		if c, present := m.Metadata["confidence_ceiling"]; present {
			t.Errorf("%q: published confidence_ceiling %v, want none", tt.line, c)
		}
	}
}
