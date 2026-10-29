// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"math/rand"
	"strings"
	"testing"
)

// The lowercase base32 pass uppercases a candidate and admits it on isValidBase32, and every
// letter is in the base32 alphabet, so a lowercase English word of 16+ letters on a line that
// names MFA was reported as an OTP secret (#800). Measured on main before the fix, on the
// issue's two lines: "responsibilities" 95 HIGH, "operationalizing" 70 MEDIUM.
//
// The secrets below are generated at run time from fixed seeds and never written down, so no
// committed file carries a secret-shaped value.

const base32Lower = "abcdefghijklmnopqrstuvwxyz234567"

// otpLine puts value on a line with strong OTP context (totp, secret, authenticator: +40).
func otpLine(value string) string {
	return "totp secret " + value + " for the authenticator app"
}

// lowercaseSecret returns n characters drawn uniformly from the lowercase base32 alphabet,
// redrawn until it holds at least one digit 2-7: the shape #800 must leave alone.
func lowercaseSecret(rng *rand.Rand, n int) string {
	b := make([]byte, n)
	for {
		for i := range b {
			b[i] = base32Lower[rng.Intn(len(base32Lower))]
		}
		if strings.ContainsAny(string(b), "234567") {
			return string(b)
		}
	}
}

func TestLowercaseEnglishWordIsNotAnOTPSecret(t *testing.T) {
	cases := []struct{ name, line string }{
		{"issue line 1, 95 HIGH before",
			"Shared responsibilities: the customer enables MFA and rotates the multi-factor secret on schedule."},
		{"issue line 2, 70 MEDIUM before",
			"Teams are operationalizing MFA enforcement across every account."},
		{"compound noun, 90 HIGH before",
			"The MFA policy covers intellectualproperty repositories and their secret stores."},
		{"run-together words, 90 HIGH before",
			"mfa configurationsvalidators run before the two-factor rollout"},
		// With 'y' counted as a consonant this word's vowel share is 4/17, under the 1/4 floor.
		{"y spelled as a vowel, 85 MEDIUM before",
			"Two-factor setup is cryptographically enforced by the authenticator app."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.line, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(%q): %v", tc.line, err)
			}
			for _, m := range matches {
				t.Errorf("reported %s %q at %.0f on %q: a lowercase English word is not a base32 secret",
					m.Type, m.Text, m.Confidence, tc.line)
			}
		})
	}
}

// The issue's acceptance check: a lowercase 32-character secret with a digit, written on the same
// two lines, reports exactly what it did before the fix. 55 base, +10 for 32+ characters, plus the
// line context: mfa, multi-factor and secret on the first line (capped at +40, clamped to 100), mfa
// alone on the second (+15).
func TestLowercaseSecretOnTheIssueLinesKeepsItsConfidence(t *testing.T) {
	secret := lowercaseSecret(rand.New(rand.NewSource(800)), 32)
	cases := []struct {
		name, line string
		want       float64
	}{
		{"issue line 1",
			"Shared responsibilities: the customer enables MFA and rotates the multi-factor secret " +
				secret + " on schedule.", 100},
		{"issue line 2",
			"Teams are operationalizing MFA enforcement across every account: " + secret, 80},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := topConfidence(t, tc.line, secret)
			if !found {
				t.Fatalf("the generated secret was not reported on %q", tc.line)
			}
			if got != tc.want {
				t.Errorf("the generated secret scored %.0f on %q, want %.0f as before #800", got, tc.line, tc.want)
			}
		})
	}
}

// The uppercase pass does not use the word test, so a lowercase secret holding a digit must score
// exactly what its uppercase form scores, at every length the pattern admits.
func TestLowercaseSecretScoresLikeItsUppercaseForm(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(8001))
	for i := 0; i < 500; i++ {
		lower := lowercaseSecret(rng, 16+rng.Intn(49))
		upper := strings.ToUpper(lower)
		if v.isLikelyWord(upper) {
			continue // the passes treat a patterned value differently by design: dropped vs -50
		}
		lo, lok := topConfidence(t, otpLine(lower), lower)
		up, uok := topConfidence(t, otpLine(upper), upper)
		if !lok || !uok || lo != up {
			t.Fatalf("lowercase %q reported=%v at %.0f, uppercase reported=%v at %.0f", lower, lok, lo, uok, up)
		}
	}
}

// The veto is a letter-shape test, not a digit requirement. A digit-free random secret is still
// reported unless its letters happen to be shaped like English, which measured about a fifth of
// them at 16 characters; requiring a digit would drop every one.
func TestDigitFreeRandomLowercaseSecretIsUsuallyStillReported(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(8002))
	tried, reported := 0, 0
	b := make([]byte, 16)
	for i := 0; i < 2000; i++ {
		for j := range b {
			b[j] = byte('a' + rng.Intn(26))
		}
		s := string(b)
		if v.isLikelyWord(strings.ToUpper(s)) {
			continue
		}
		tried++
		if _, found := topConfidence(t, otpLine(s), s); found {
			reported++
		}
	}
	share := float64(reported) / float64(tried)
	t.Logf("%d of %d digit-free random 16-character lowercase secrets reported (%.1f%%)", reported, tried, 100*share)
	if share < 0.7 {
		t.Errorf("only %.1f%% of digit-free random lowercase secrets were reported; the word test "+
			"should cost about a fifth of them, not all", 100*share)
	}
}

// Values that sit exactly on the bounds. The two that are dropped are not English: they are the
// rule's edges, the rare digit-free random secret the cost in isLowercaseWordShape counts. On main
// every one of these is reported at 95 or 100.
func TestLowercaseWordShapeBoundaries(t *testing.T) {
	cases := []struct {
		name, value string
		reported    bool
	}{
		{"vowel share exactly 1/4 with a 4-consonant run: word-shaped", "trnkalpsvemdwhou", false},
		{"vowel share exactly 3/5: word-shaped", "kautoiremuonaseiluap", false},
		{"vowel share 3/16, under the 1/4 floor", "trnkalpsvemdwhoq", true},
		{"vowel share 13/20, over the 3/5 ceiling", "kautoireouonaseiluap", true},
		{"a run of five consonants", "trnkqalpsemdwhou", true},
		// The 3/5 value above with a digit added: its letters alone are still word-shaped.
		{"one digit exempts the value from the word test", "kautoiremu7onaseiluap", true},
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
