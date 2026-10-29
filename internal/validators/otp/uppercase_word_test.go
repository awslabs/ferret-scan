// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"math/rand"
	"strings"
	"testing"
)

// #800 dropped a digit-free candidate shaped like an English word from the lowercase base32 pass
// only. The uppercase pass matches A-Z directly and emitted without the test, so the same word in
// capitals was still an OTP_SECRET (#838). The secrets below are generated at run time from fixed
// seeds and never written down, so no committed file carries a secret-shaped value.

func TestUppercaseEnglishWordIsNotAnOTPSecret(t *testing.T) {
	cases := []struct{ name, line string }{
		{"issue line 1, 85 MEDIUM before", "otp_secret = RESPONSIBILITIES"},
		{"issue line 2, 95 HIGH before", "mfa_totp_secret = RESPONSIBILITIES"},
		// The #800 words, in capitals, on the lines #800 measured them on.
		{"#800 line 1 in capitals",
			"Shared RESPONSIBILITIES: the customer enables MFA and rotates the multi-factor secret on schedule."},
		{"#800 line 2 in capitals", "Teams are OPERATIONALIZING MFA enforcement across every account."},
		{"compound noun in capitals",
			"The MFA policy covers INTELLECTUALPROPERTY repositories and their secret stores."},
		{"run-together words in capitals", "mfa CONFIGURATIONSVALIDATORS run before the two-factor rollout"},
		{"y spelled as a vowel, in capitals",
			"Two-factor setup is CRYPTOGRAPHICALLY enforced by the authenticator app."},
		// An all-caps line, as a console banner or a log export writes it.
		{"an all-caps sentence", "TOTP SECRET KEY: ADMINISTRATIVELY DISABLED FOR THIS ACCOUNT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.line, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(%q): %v", tc.line, err)
			}
			for _, m := range matches {
				t.Errorf("reported %s %q at %.0f on %q: an English word in capitals is not a base32 secret",
					m.Type, m.Text, m.Confidence, tc.line)
			}
		})
	}
}

// The control the issue asks for: a real secret on the issue's own lines reports exactly what it
// did before, in capitals and in lowercase. A 32-character secret holding a digit is never tested
// for word shape, so 55 base +10 for its length plus the line context: otp and secret on the first
// line (+30), mfa, totp and secret on the second (+45, capped at +40, clamped to 100).
func TestSecretOnTheIssueLinesKeepsItsConfidence(t *testing.T) {
	lower := lowercaseSecret(rand.New(rand.NewSource(838)), 32)
	for _, secret := range []string{strings.ToUpper(lower), lower} {
		cases := []struct {
			line string
			want float64
		}{
			{"otp_secret = " + secret, 95},
			{"mfa_totp_secret = " + secret, 100},
		}
		for _, tc := range cases {
			got, found := topConfidence(t, tc.line, secret)
			if !found {
				t.Fatalf("the generated secret was not reported on %q", tc.line)
			}
			if got != tc.want {
				t.Errorf("the generated secret scored %.0f on %q, want %.0f as before #838", got, tc.line, tc.want)
			}
		}
	}
}

// Both passes now ask the same question of the same letters, so a digit-free value is reported in
// capitals exactly when it is reported in lowercase, at the same confidence. On main the capitals
// were reported every time, word-shaped or not. The share still reported is the cost bound: about
// four in five digit-free random 16-character secrets, as in the lowercase pass.
func TestUppercaseAndLowercasePassesAgreeOnDigitFreeValues(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(8381))
	tried, reported := 0, 0
	b := make([]byte, 16)
	for i := 0; i < 2000; i++ {
		for j := range b {
			b[j] = byte('A' + rng.Intn(26))
		}
		upper := string(b)
		if v.isLikelyWord(upper) {
			continue // the passes treat a patterned value differently by design: dropped vs -50
		}
		lower := strings.ToLower(upper)
		up, uok := topConfidence(t, otpLine(upper), upper)
		lo, lok := topConfidence(t, otpLine(lower), lower)
		if uok != lok || up != lo {
			t.Fatalf("uppercase %q reported=%v at %.0f, lowercase reported=%v at %.0f", upper, uok, up, lok, lo)
		}
		tried++
		if uok {
			reported++
		}
	}
	share := float64(reported) / float64(tried)
	t.Logf("%d of %d digit-free random 16-character secrets reported in both cases (%.1f%%)",
		reported, tried, 100*share)
	if share < 0.7 {
		t.Errorf("only %.1f%% of digit-free random secrets were reported; the word test should cost "+
			"about a fifth of them, not all", 100*share)
	}
}

// The boundary values of TestLowercaseWordShapeBoundaries, in capitals, land on the same side of
// each bound. On main every one of these is reported at 95 or 100.
func TestUppercaseWordShapeBoundaries(t *testing.T) {
	cases := []struct {
		name, value string
		reported    bool
	}{
		{"vowel share exactly 1/4 with a 4-consonant run: word-shaped", "TRNKALPSVEMDWHOU", false},
		{"vowel share exactly 3/5: word-shaped", "KAUTOIREMUONASEILUAP", false},
		{"vowel share 3/16, under the 1/4 floor", "TRNKALPSVEMDWHOQ", true},
		{"vowel share 13/20, over the 3/5 ceiling", "KAUTOIREOUONASEILUAP", true},
		{"a run of five consonants", "TRNKQALPSEMDWHOU", true},
		{"one digit exempts the value from the word test", "KAUTOIREMU7ONASEILUAP", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, found := topConfidence(t, otpLine(tc.value), tc.value)
			if found != tc.reported {
				t.Errorf("%q reported=%v, want %v", tc.value, found, tc.reported)
			}
		})
	}
}
