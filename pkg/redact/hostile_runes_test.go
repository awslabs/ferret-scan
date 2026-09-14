// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// lengthChangingLowerRunes is the COMPLETE set of runes for which
// strings.ToLower changes the byte length, obtained by enumerating the whole
// code point space rather than by picking characters that look suspicious.
//
// Twenty-five shrink and two grow. The direction decides the failure mode: a
// shrinking rune makes an offset run past the end of the folded copy, which
// panics; a growing one makes it land mid-value, which produces a wrong answer
// with no panic and therefore no signal at all.
var lengthChangingLowerRunes = []rune{
	// shrink
	0x0130, 0x1E9E, 0x2126, 0x212A, 0x212B, 0x2C62, 0x2C64, 0x2C6D, 0x2C6E,
	0x2C6F, 0x2C70, 0x2C7E, 0x2C7F, 0xA78D, 0xA7AA, 0xA7AB, 0xA7AC, 0xA7AD,
	0xA7AE, 0xA7B0, 0xA7B1, 0xA7B2, 0xA7C5, 0xA7CB, 0xA7DC,
	// grow
	0x023A, 0x023E,
}

// TestNoValidatorIsDisabledByALengthChangingRune is the cross-validator guard
// for #656: content the caller does not control must never be able to switch a
// validator off.
//
// The bug it pins: several validators built a case-folded copy of each line and
// then indexed it with offsets taken from the ORIGINAL line. Because Unicode
// case mapping is not length-preserving — U+212A KELVIN SIGN folds from 3 bytes
// to 1 — a line carrying a run of such characters made every subsequent offset
// overshoot, the validator panicked, and the panic was recovered into ZERO
// findings for the WHOLE FILE at exit 0. Only reported findings reach the
// redactor, so that is a redaction bypass triggered by one character class.
//
// Written against EVERY advertised check rather than the two that were known to
// be affected, deliberately. The two were found by probing, and probing
// under-reports: whether a given payload overshoots depends on exact byte
// offsets, so a validator can carry the same defect and look clean against one
// fixture. This test is the standing check that the next validator to acquire
// the pattern is caught by CI rather than by someone pasting Kelvin signs into a
// document.
//
// The threshold matters and is why the payload is long. With n shrinking runes
// the keyword starts 3n bytes in while the folded copy is only n bytes longer
// than its prefix, so the overshoot needs roughly n >= 9 before it reaches past
// the end. A one-character fixture indexes safely and proves nothing.
func TestNoValidatorIsDisabledByALengthChangingRune(t *testing.T) {
	names := redact.ValidCheckNames()
	if len(names) == 0 {
		t.Fatal("ValidCheckNames() is empty, so this test cannot detect anything")
	}

	for _, name := range names {
		input, ok := checkFixtures[name]
		if !ok {
			// TestValidCheckNames_AllDetectAndRedact already fails loudly on a
			// missing fixture; not duplicating that failure here.
			continue
		}

		t.Run(name, func(t *testing.T) {
			redactOnce := func(text string) (string, int) {
				engine, err := redact.NewEngine(redact.EngineOptions{
					Checks:   []string{name},
					Strategy: redact.Simple,
				})
				if err != nil {
					t.Fatalf("NewEngine(Checks=[%q]) failed: %v", name, err)
				}
				defer func() { _ = engine.Close() }()
				res, err := engine.Redact(context.Background(), redact.Request{Text: text})
				if err != nil {
					t.Fatalf("Redact failed: %v", err)
				}
				return res.Redacted, len(res.Findings())
			}

			// The control is what makes every assertion below non-vacuous: if the
			// fixture produced no findings to begin with, "no findings were lost"
			// would be trivially true for every payload.
			_, base := redactOnce(input)
			if base == 0 {
				t.Fatalf("control produced 0 findings, so this test cannot detect a loss")
			}

			for _, r := range lengthChangingLowerRunes {
				if !utf8.ValidRune(r) {
					t.Fatalf("U+%04X is not a valid rune — the table is corrupt", r)
				}
				// 40, not 12. The overshoot is a THRESHOLD and it differs per validator:
				// measured, VIN needs >= 8 shrinking runes before its offsets run past the
				// end, and bankaccount needs >= 28. A 12-rune payload caught VIN and MISSED
				// bankaccount -- verified by mutation, so this guard would have caught one of
				// the two known instances and read as a pass. 40 clears both with margin.
				pad := strings.Repeat(string(r), 40)
				// Three arrangements, because which one overshoots depends on byte
				// offsets: hostile run before the value, on its own line before it,
				// and after it.
				payloads := map[string]string{
					"prefixing the value": pad + " " + input,
					"on a preceding line": input + "\n" + pad + " " + input,
					"following the value": input + " " + pad,
				}
				for shape, text := range payloads {
					redacted, got := redactOnce(text)
					// A COUNT comparison, which is what this asserted when it shipped
					// with #658, is too weak: it cannot see a confidence demotion (still
					// one finding) or a finding GAINED, and both remaining instances of
					// the class were exactly those shapes. The authoritative oracle is
					// now TestOutputDoesNotDependOnLengthChangingRunes in pkg/scan, which
					// diffs the full signature including numeric confidence against a
					// byte-length-identical control. This test keeps the count check
					// because it covers something that one does not — the REDACTION path
					// and the resulting bytes — and a drop here is the leak itself.
					if got < base {
						t.Errorf("U+%04X %s: findings dropped %d -> %d. A validator that "+
							"panics on attacker-supplied text reports a clean scan of a file "+
							"it abandoned, and the value stays in the cleartext of the "+
							"redacted output.", r, shape, base, got)
						continue
					}
					// The sink half: whatever the fixture's sensitive value is, it must
					// not survive into the redacted text just because a hostile rune
					// shares the line.
					if v := sensitiveSubstring(input); v != "" && strings.Contains(redacted, v) {
						t.Errorf("U+%04X %s: %q survived into the redacted output",
							r, shape, v)
					}
				}
			}
		})
	}
}

// sensitiveSubstring returns the token from a fixture that must never appear in
// redacted output, or "" when the fixture has no single distinguishing token.
//
// A helper rather than a second fixture map: the values are already in
// checkFixtures, and a duplicate table would be one more thing to keep in step.
func sensitiveSubstring(fixture string) string {
	// Whitespace only. Splitting on "." as well shredded 172.217.14.206 into four
	// short pieces and silently returned "", which made the sink assertion skip
	// IP_ADDRESS while the test still read as passing -- the exact shape of
	// vacuity this file is about.
	best := ""
	for _, tok := range strings.Fields(fixture) {
		// Trim surrounding prose punctuation, then drop any "NAME=" / "label:"
		// prefix so the token is the VALUE and not the assignment. The redacted
		// output legitimately keeps the key, so comparing the whole assignment
		// would never match and the assertion would be dead.
		tok = strings.Trim(tok, `.,;:"'()[]`)
		if i := strings.LastIndexAny(tok, "=:"); i >= 0 && i+1 < len(tok) {
			tok = tok[i+1:]
		}
		if !strings.ContainsAny(tok, "0123456789") {
			continue
		}
		if len(tok) > len(best) {
			best = tok
		}
	}
	if len(best) < 6 {
		return ""
	}
	return best
}

// TestSensitiveSubstringPicksTheIdentifier keeps the helper above honest: if it
// silently returned "" for everything, the sink assertion in the test would
// never run and the test would look like it was checking twice as much as it was.
func TestSensitiveSubstringPicksTheIdentifier(t *testing.T) {
	// Measured against the real fixtures, not predicted. The first draft of this
	// table guessed, and the guess was wrong for IP_ADDRESS in a way that made the
	// sink assertion skip that check while the test still passed.
	want := map[string]string{
		"BANK_ACCOUNT":    "1234567890",
		"CLOUD_RESOURCES": "acme-prod-customer-exports-2024",
		"CREDIT_CARD":     "4111-1111-1111-1111",
		"DATE_OF_BIRTH":   "03/14/1985",
		"DRIVERS_LICENSE": "I1234567",
		"IP_ADDRESS":      "172.217.14.206",
		"MEDICAL_ID":      "1EG4-TE5-MK73",
		"PASSPORT":        "C87654321",
		"PHONE":           "555-0142",
		"SECRETS":         "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"SSN":             "219-09-9999",
		"VIN":             "1HGBH41JXMN109186",
	}
	for check, w := range want {
		fixture, ok := checkFixtures[check]
		if !ok {
			t.Errorf("%s has no fixture", check)
			continue
		}
		if got := sensitiveSubstring(fixture); got != w {
			t.Errorf("sensitiveSubstring(%s fixture) = %q, want %q", check, got, w)
		}
	}
	// And it must decline rather than guess on prose.
	if got := sensitiveSubstring("CONFIDENTIAL AND PROPRIETARY - Trade Secret"); got != "" {
		t.Errorf("sensitiveSubstring(prose) = %q, want \"\"", got)
	}
	// Guard against the helper degenerating: at least half the fixtures must
	// yield a token, or the sink assertion is mostly not running.
	withToken := 0
	for _, f := range checkFixtures {
		if sensitiveSubstring(f) != "" {
			withToken++
		}
	}
	// Measured at 12 of 17. Asserting the exact number rather than a fraction: if
	// the helper degrades, the count drops and this says so, instead of the sink
	// assertion quietly covering fewer checks each time a fixture is reworded.
	// EMAIL, INTELLECTUAL_PROPERTY, OTP, PERSON_NAME and PHYSICAL_ADDRESS
	// correctly yield "" (no single digit-bearing token) and rest on the
	// finding-count assertion alone.
	if withToken != 12 {
		t.Errorf("%d of %d fixtures yield a sensitive token, want 12 — the sink assertion's "+
			"coverage moved, so either a fixture changed or the helper regressed",
			withToken, len(checkFixtures))
	}
}
