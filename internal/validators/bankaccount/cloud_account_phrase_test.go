// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// The duplicated key must be the one the document bridge reads, or the ceiling is lifted
// by the bridge's context adjustment without any test noticing.
func TestConfidenceCeilingKeyIsTheBridges(t *testing.T) {
	if confidenceCeilingKey != validators.ConfidenceCeilingKey {
		t.Fatalf("confidenceCeilingKey = %q, bridge reads %q", confidenceCeilingKey, validators.ConfidenceCeilingKey)
	}
	if cloudAccountIDCeiling >= 60 {
		t.Fatalf("cloudAccountIDCeiling = %.0f, want below the MEDIUM bar of 60", cloudAccountIDCeiling)
	}
}

func TestHasCloudAccountPhrase(t *testing.T) {
	for _, tt := range []struct {
		line string
		want bool
	}{
		{"Payer account 210987654321", true},
		{"AWS Account ID: 210987654321", true},
		{"AWS accounts 210987654321 and 109876543210", true},
		{"account-id 210987654321", true},
		{"account_id=210987654321", true},
		{"GCP project number 210987654321", true},
		{"Azure tenant 210987654321", true},
		{"Account number: 210987654321", false},
		{"bank account 210987654321", false},
		{`"accountId": "210987654321"`, false}, // demoting lists keep their separator
		{"payers 210987654321", false},
		{"lieutenant 210987654321", false},
	} {
		if got := hasCloudAccountPhrase(tt.line); got != tt.want {
			t.Errorf("hasCloudAccountPhrase(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
