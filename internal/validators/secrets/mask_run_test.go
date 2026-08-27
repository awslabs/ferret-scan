// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// TestAMaskRunIsNotASecret is the detection half of #522.
//
// A run of asterisks is this tool's OWN output. Re-scanning a redacted file is a normal thing to do —
// it is how you verify a redaction — and reporting the mask as `API_KEY_OR_SECRET` at MEDIUM 75 then
// drove `format_preserving` to replace it with a run of asterisks of the same length, so the
// "redacted" copy came back byte-identical to its input with `Success` true at rc 0 and an audit log
// whose `original_file_hash` and `redacted_file_hash` were EQUAL.
func TestAMaskRunIsNotASecret(t *testing.T) {
	for _, n := range []int{8, 16, 20, 40, 64} {
		v := strings.Repeat("*", n)
		if plausibleUnquotedSecret(v) {
			t.Errorf("a run of %d asterisks was accepted as a plausible secret", n)
		}
	}
}

// TestARealSecretIsStillAccepted is the control that keeps the suppressor from being a coverage loss.
//
// Measured across 1,069 real text files, this change removed exactly TWO findings — both provably
// mask runs (`2fa secret: ****...` and `AWS_SECRET_ACCESS_KEY=****...`) — and gained none. These are
// the shapes that must survive for that to stay true.
func TestARealSecretIsStillAccepted(t *testing.T) {
	for _, v := range []string{
		"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", // AWS-secret shaped
		"ghp_16CharsOfTokenAndMore12345",         // provider token shaped
		"correcthorsebatterystaple",              // long all-lowercase passphrase
		"S3cr3t-Value_With.Symbols!",             // mixed
	} {
		if !plausibleUnquotedSecret(v) {
			t.Errorf("a real secret shape was rejected: %q", v)
		}
	}
}

// TestAValueMerelyCONTAININGMaskCharactersIsStillASecret is the narrowness assertion.
//
// The rule is ENTIRELY mask characters, not "contains one". A credential with asterisks in it is a
// credential, and rejecting it would trade a false positive for a real miss — the wrong direction for
// a suppressor. This shape reports at HIGH 100 end to end.
func TestAValueMerelyCONTAININGMaskCharactersIsStillASecret(t *testing.T) {
	for _, v := range []string{
		"abc**defGHIjklMNOpqrs123456789",
		"**leadingMask1234567890abc",
		"trailingMask1234567890abc**",
	} {
		if !plausibleUnquotedSecret(v) {
			t.Errorf("a real secret containing mask characters was rejected: %q", v)
		}
	}
}

// TestIsAllMaskCharacters pins the helper, including the cases where getting it wrong would widen the
// suppressor into real values.
func TestIsAllMaskCharacters(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"", false}, // an empty value is not a mask run; it is nothing
		{"*", true},
		{strings.Repeat("*", 40), true},
		{"***a***", false},                     // one real character means it is not a mask
		{strings.Repeat("X", 40), false},       // NOT widened to other characters -- see the helper's comment
		{strings.Repeat("#", 40), false},       //
		{"••••", false},                        // a bullet is not this tool's mask byte either
		{strings.Repeat("*", 39) + "0", false}, // a single surviving digit, as a partial mask leaves
	} {
		if got := isAllMaskCharacters(tc.in); got != tc.want {
			t.Errorf("isAllMaskCharacters(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestScanningRedactedOutputReportsNoSecret drives the PUBLIC entry point, which is the gap between
// "the decision function rejects it" and "the tool does not report it".
//
// The content is exactly what this tool writes when it redacts an env file. Verifying a redaction by
// re-scanning its output is the workflow that surfaced #522, so this is the shape a user actually hits.
//
// The mask case and the real-secret control are DELIBERATELY separate calls. Putting a real secret in
// the same content displaces the mask finding — the validator reported exactly one
// API_KEY_OR_SECRET for the whole file, the real one — so a combined fixture could never show the mask
// being reported and the test passed against the unfixed code. Splitting them makes both halves live.
func TestScanningRedactedOutputReportsNoSecret(t *testing.T) {
	t.Run("masked output reports no secret", func(t *testing.T) {
		content := strings.Join([]string{
			"AWS_ACCESS_KEY_ID=" + strings.Repeat("*", 20),
			"AWS_SECRET_ACCESS_KEY=" + strings.Repeat("*", 40),
		}, "\n")

		matches, err := NewValidator().ValidateContent(content, "redacted.env")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range matches {
			if isAllMaskCharacters(m.Text) {
				t.Errorf("a mask run was reported as %s at line %d confidence %.0f — this is the "+
					"tool's own output being re-detected as a credential (#522)",
					m.Type, m.LineNumber, m.Confidence)
			}
		}
	})

	t.Run("a real secret in the same shape is still reported", func(t *testing.T) {
		realKey := "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
		content := "AWS_SECRET_ACCESS_KEY=" + realKey

		matches, err := NewValidator().ValidateContent(content, "real.env")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("the real secret was not reported at all; the suppressor has cost coverage on " +
				"exactly the shape it was scoped to leave alone")
		}
	})
}

// TestTheSuppressorIsValueIntrinsicAndCannotHideASecret records why this is a veto rather than a
// confidence ceiling, unlike unlabelledHexIdentifierCap in the same file.
//
// That one is a ceiling because a NEGATIVE LIST OF FIELD NAMES would let an author suppress a real
// secret by relabelling it — attacker-controlled suppression. This rule reads only the value's own
// bytes, so the analogous attack requires replacing the secret with asterisks, which destroys it. The
// test states the property: adding any label around a real secret cannot make it unreportable.
func TestTheSuppressorIsValueIntrinsicAndCannotHideASecret(t *testing.T) {
	real := "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
	if !plausibleUnquotedSecret(real) {
		t.Fatal("the control secret is not accepted, so this test proves nothing")
	}
	// There is no label to add: the function takes the VALUE. The only way to reach the rejection is
	// to replace the value with mask characters, which is not suppression of a secret but removal of
	// one.
	if plausibleUnquotedSecret(strings.Repeat("*", len(real))) {
		t.Error("a fully masked value of the same length was accepted")
	}
}
