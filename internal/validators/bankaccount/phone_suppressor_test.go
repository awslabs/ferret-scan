// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"strings"
	"testing"
)

// "call us" is a phone-context SUPPRESSOR here: a line that reads like a phone number stops a
// 10-digit run being reported as an account. It must keep matching only its SPACED forms.
//
// #372 added kwmatch.ContainsLabel, whose keyword spaces may match zero separators, so that a
// camelCase key like "routingNumber" counts as context. That form is opt-in for exactly this
// reason: "call us" concatenates to "callus", an ordinary English word, and measured with the
// widened matcher a "callus debridement, bank account 4432198765" line LOSES its
// US_BANK_ACCOUNT finding. A podiatry billing line is not a hypothetical, and a suppressed
// finding is never redacted, so this is a leak rather than a precision question.
//
// 147 distinct multi-word keywords reach the matcher across this tree, measured by recording
// every call. This test guards the direction that costs findings; the direction that gains
// them is guarded by the positive-gate tests.
func TestCallUsSuppressorKeepsItsSeparator(t *testing.T) {
	v := NewValidator()

	const (
		control = "bank account 1234567890"
		callus  = "callus debridement, bank account 4432198765"
		prose   = "please call us, bank account 5566778899"
	)

	report := func(line string) bool {
		t.Helper()
		ms, err := v.ValidateContent(line, "probe.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range ms {
			if strings.Contains(m.Type, "BANK_ACCOUNT") {
				return true
			}
		}
		return false
	}

	if !report(control) {
		t.Fatal("the control line reports no account, so the rest of this test is vacuous")
	}
	if !report(callus) {
		t.Error("a line mentioning a callus lost its account finding: the phone-context " +
			"suppressor matched the concatenated form of \"call us\". A suppressed finding is " +
			"never redacted, so this is a leak, not a precision question.")
	}
	if report(prose) {
		t.Error("a line with real \"call us\" prose reported an account: the phone-context " +
			"suppressor must still fire on the spaced form, or this change traded one defect " +
			"for another")
	}
}
