// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import "testing"

// Recovery codes come in sets, and the validator requires two or more grouped
// codes before it reports anything. Fixtures below always carry two — a
// single-code line reports nothing regardless of context, which is a separate
// pre-existing rule and would silently make these tests vacuous.
const (
	twoCodes   = "4RTX-9QLM-2FDW 8HKP-3VBN-6ZCA"
	twoCodesB  = "7YHN-2WSX-5TGB 9OKM-3EDC-8UJM"
	twoProduct = "XXXX-YYYY-ZZZZ AAAA-BBBB-CCCC"
)

// TestOrdinaryProseKeepsRecoveryCodes is the leak this file exists for.
//
// hasRecoveryContext vetoed the line if ANY of twenty non-recovery words appeared
// on it, anywhere. Every one of those words is ordinary next to a recovery code —
// a licence tier, a room number, an employee name, a firmware update — and because
// the veto gates the whole LINE it deleted every code on it at once. Only reported
// findings reach the redactor, so each of these lines leaked in full.
func TestOrdinaryProseKeepsRecoveryCodes(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Recovery codes " + twoCodes + " (license tier: enterprise)",
		"Backup codes " + twoCodes + " stored in room 402",
		"Recovery codes " + twoCodes + " issued to employee Chen",
		"2FA recovery codes " + twoCodes + " for the staff portal",
		"Recovery codes " + twoCodes + " -- replacement set",
		"Backup codes " + twoCodes + " after the firmware update",
		"Recovery codes " + twoCodes + " on the disk image",
		"MFA backup codes " + twoCodes + " -- see release notes",
		"Recovery codes " + twoCodes + " kept in the door safe",
		"Backup codes " + twoCodes + ", tracking ticket OPS-88",
		"Two-factor recovery codes " + twoCodes + " for the invoice system",
		"Recovery codes " + twoCodes + " -- patch window Saturday",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "runbook.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("an ordinary word elsewhere on the line deleted BOTH recovery "+
					"codes; an unreported code is never redacted: %s", line)
			}
		})
	}
}

// TestBareTopicMentionStillSuppresses is the case that refuted the first version
// of this change, and it is why the exemption is keyed on an explicit
// "recovery codes" phrase rather than on any recovery-ish word.
//
// These lines put a bare 2fa / recovery / emergency mention FIRST and the real
// label second, so a rule keyed on position alone reports product keys as
// recovery codes — exactly the false-positive class adversarial_test.go exists to
// prevent.
func TestBareTopicMentionStillSuppresses(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"2FA activated. Product keys: " + twoProduct,
		"recovery disk contains key: NKJFK-GPHP7-G8C3J RHJG7-TKMPD-JKKK2",
		"emergency replacement devices: WXYZ-1234-ABCD EFGH-5678-IJKL",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "inventory.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a bare topic mention was treated as a recovery-code label: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestLabelledNonRecoveryValuesStaySuppressed is the other precision half: when
// the non-recovery word IS the label and leads the line, it must still veto.
func TestLabelledNonRecoveryValuesStaySuppressed(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Product key " + twoCodes + " for Office 2021",
		"License key " + twoCodes + " activation",
		"Serial number " + twoCodes + " on the chassis",
		"Windows product key " + twoCodes,
		"Activation code " + twoCodes + " for the license portal",
		"Device id " + twoCodes + " registered",
		"Order " + twoCodes + " shipped",
		"Release " + twoCodes + " firmware patch",
		"Room " + twoCodes + " door code",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "assets.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a labelled non-recovery value was reported: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestControlPairs makes the recall test non-circular: for every leak case, the
// identical line WITHOUT the suppression word must already report. If the control
// reported nothing the paired case would prove nothing about the word.
func TestControlPairs(t *testing.T) {
	v := NewValidator()

	pairs := []struct{ withWord, control string }{
		{
			"Recovery codes " + twoCodes + " (license tier: enterprise)",
			"Recovery codes " + twoCodes + " in the sealed envelope",
		},
		{
			"Backup codes " + twoCodesB + " stored in room 402",
			"Backup codes " + twoCodesB + " stored in the safe",
		},
	}

	for _, p := range pairs {
		t.Run(p.control, func(t *testing.T) {
			control, err := v.ValidateContent(p.control, "runbook.txt")
			if err != nil {
				t.Fatalf("ValidateContent(control): %v", err)
			}
			if len(control) == 0 {
				t.Fatalf("the CONTROL reports nothing, so its pair proves nothing: %s", p.control)
			}
			got, err := v.ValidateContent(p.withWord, "runbook.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(got) != len(control) {
				t.Errorf("with the suppression word: %d finding(s); control: %d — the word "+
					"should not change the outcome", len(got), len(control))
			}
		})
	}
}

// TestKeywordIndex pins the offset helper, including the whole-word boundary rule
// it has to share with containsKeyword. If the two disagreed, a keyword found by
// one and missed by the other would make the positional comparison meaningless.
func TestKeywordIndex(t *testing.T) {
	cases := []struct {
		text, kw string
		want     int
	}{
		{"Recovery codes ABCD", "recovery codes", 0},
		{"see the Recovery Codes now", "recovery codes", 8},
		{"product key here", "product key", 0},
		{"no match here", "license", -1},
		{"", "license", -1},
		{"license", "license", 0},
		// Whole-word only: a keyword inside a longer word must not match.
		{"licensed software", "license", -1},
		{"unlicense", "license", -1},
		// kwmatch treats "_" as a SEPARATOR, not a word character, so a keyword
		// inside a snake_case identifier IS found — code and config are primary
		// scan targets. keywordIndex must agree, which is the whole point of
		// delegating to it.
		{"my_license_key", "license", 3},
		// Punctuation IS a boundary.
		{"(license)", "license", 1},
		{"tier:license", "license", 5},
	}

	for _, c := range cases {
		if got := keywordIndex(c.text, c.kw); got != c.want {
			t.Errorf("keywordIndex(%q, %q) = %d, want %d", c.text, c.kw, got, c.want)
		}
	}
}

// TestKeywordIndexAgreesWithContainsKeyword guards the invariant directly: the
// positional check is only sound if it finds exactly what the boolean check finds.
func TestKeywordIndexAgreesWithContainsKeyword(t *testing.T) {
	texts := []string{
		"Recovery codes ABCD-EFGH stored in room 402",
		"Product key ABCD for Office",
		"licensed software, not a license",
		"my_license_key = x",
		"2FA activated. Product keys: XXXX",
		"",
	}
	keywords := []string{
		"license", "product key", "room", "recovery codes", "2fa", "serial",
	}

	for _, text := range texts {
		for _, kw := range keywords {
			has := containsKeyword(text, kw)
			idx := keywordIndex(text, kw)
			if has != (idx >= 0) {
				t.Errorf("disagreement on (%q, %q): containsKeyword=%v keywordIndex=%d",
					text, kw, has, idx)
			}
		}
	}
}
