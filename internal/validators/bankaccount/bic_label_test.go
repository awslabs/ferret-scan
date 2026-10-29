// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"strings"
	"testing"
)

// hasBICLabel uses the positive-keyword matcher, so the separators real files use still count
// and a label inside another word does not.
func TestHasBICLabel(t *testing.T) {
	v := NewValidator()
	for _, tt := range []struct {
		line string
		want bool
	}{
		{"SWIFT: DEUTDEFF", true},
		{"BIC/SWIFT DEUTDEFF", true},
		{"swift_code=DEUTDEFF", true},
		{"IBAN DE89 3704 0044 0532 0130 00", true},
		{"bank account DEUTDEFF", false},
		{"wire deposit DEUTDEFF", false},
		{"bicycle DEUTDEFF", false},
		{"swiftly DEUTDEFF", false},
	} {
		if got := hasBICLabel(tt.line); got != tt.want {
			t.Errorf("hasBICLabel(%q) = %v, want %v", tt.line, got, tt.want)
		}
		// Every label is also a positive keyword, so a labelled line scores as before.
		if tt.want && !v.hasBankingKeywords(tt.line) {
			t.Errorf("%q has a BIC label but no banking keyword", tt.line)
		}
	}
	for _, kw := range bicLabels {
		found := false
		for _, p := range v.positiveKeywords {
			if strings.EqualFold(p, kw) {
				found = true
			}
		}
		if !found {
			t.Errorf("BIC label %q is not a positive keyword", kw)
		}
	}
}
