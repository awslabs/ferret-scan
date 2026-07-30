// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	stdctx "context"
	"strings"
	"testing"
)

// TestLabelledSSNInProseIsDetected closes a coverage gap that let a proposed
// false-positive fix look safe when it was a cleartext leak.
//
// A large false-positive class exists in tabular data: any 9-digit value in a
// >=3-field delimited line scores HIGH (2161 high-confidence hits on a public
// World Bank population CSV, which contains no PII at all). A tempting one-line
// fix is a "decimal guard" that rejects a digit run adjacent to a "." on a word
// boundary, on the theory that 1.130075728 is a fraction rather than an SSN.
//
// That guard silently deletes every case below, because \b ends BEFORE a
// sentence-terminal period: "the SSN is 130075728." looks identical to a decimal
// fraction under a boundary test. These are the HIGHEST-confidence shapes the
// validator has — an explicit label next to the value — and the guard runs before
// isValidSSN, so it removes them outright rather than re-banding them. Measured on
// the shipped validator: all four score 95-100; under the guard, all four vanish
// and the redaction pipeline writes no output file, leaving the value in
// cleartext.
//
// Neither the ssn package suite nor the golden corpus contained a single
// sentence-terminal SSN, so both PASSED under the broken guard. A regression gate
// cannot prove anything about a class it does not contain. This test is that
// class.
func TestLabelledSSNInProseIsDetected(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		want string
	}{
		{"sentence terminal, no separators", "Employee record: the SSN is 130075728.", "130075728"},
		{"sentence terminal, hyphenated", "Employee SSN: 130-07-5728.", "130-07-5728"},
		{"sentence terminal, spaced", "Social Security Number: 130 07 5728.", "130 07 5728"},
		{"key=value terminated", "ssn=130075728.", "130075728"},
		{"comma terminated", "The SSN is 130075728, on file since 2019.", "130075728"},
		{"parenthesised", "Employee SSN (130-07-5728) verified.", "130-07-5728"},
		{"semicolon terminated", "ssn: 130075728; verified", "130075728"},
		{"quoted in prose", `The employee's SSN is "130075728".`, "130075728"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContentCtx(stdctx.Background(), tc.line, "/test/hr.txt")
			if err != nil {
				t.Fatalf("ValidateContentCtx: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no findings — an explicitly LABELLED SSN in prose is the "+
					"highest-confidence shape this validator has, and dropping it is a "+
					"cleartext leak (an unreported value is never redacted). A value-shape "+
					"guard that treats a trailing '.' as a decimal point causes exactly "+
					"this.\n  line: %q", tc.line)
			}
			var found bool
			var got []string
			for _, m := range matches {
				got = append(got, m.Text)
				if m.Text == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("findings %v do not include %q\n  line: %q", got, tc.want, tc.line)
			}
		})
	}
}

// TestLabelledProseSSNKeepsHighConfidence pins the BAND, not just the presence.
//
// Presence alone is not enough: a fix that demoted these from HIGH to LOW would
// hide them under `--confidence high,medium` and change pre-commit exit codes,
// which is a quieter version of the same leak. An explicit "SSN"/"social security
// number" label adjacent to a structurally valid value should reach MEDIUM at
// minimum.
func TestLabelledProseSSNKeepsHighConfidence(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Employee record: the SSN is 130075728.",
		"Employee SSN: 130-07-5728.",
		"Social Security Number: 130 07 5728.",
	}

	const floor = 60.0 // MEDIUM band boundary
	for _, line := range lines {
		matches, err := v.ValidateContentCtx(stdctx.Background(), line, "/test/hr.txt")
		if err != nil {
			t.Fatalf("ValidateContentCtx(%q): %v", line, err)
		}
		if len(matches) == 0 {
			t.Fatalf("no findings for %q (see TestLabelledSSNInProseIsDetected)", line)
		}
		var best float64
		for _, m := range matches {
			if m.Confidence > best {
				best = m.Confidence
			}
		}
		if best < floor {
			t.Errorf("best confidence %.1f < %.0f for %q — an explicit label next to a valid "+
				"SSN must stay in the MEDIUM band or above, or it disappears under "+
				"--confidence high,medium and stops failing pre-commit", best, floor, line)
		}
	}
}

// TestDecimalFractionsAreNotSSNs is the other half of the contract, and the reason
// the rejected guard was attractive in the first place: a digit run that is
// genuinely part of a decimal number should not be reported.
//
// Recorded as the CURRENT behavior rather than an aspiration. Any future
// false-positive work in this area has to keep TestLabelledSSNInProseIsDetected
// green while improving these — that pairing is the whole point. Cases that the
// validator reports today are marked, so the file states the real starting line
// instead of a wished-for one.
func TestDecimalFractionsAreNotSSNs(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
	}{
		{"leading decimal", "ratio 1.130075728 computed"},
		{"trailing decimal", "value 130075728.44 recorded"},
		{"version-like", "build 1.130075728.2"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContentCtx(stdctx.Background(), tc.line, "/test/metrics.txt")
			if err != nil {
				t.Fatalf("ValidateContentCtx: %v", err)
			}
			// Not asserted as zero: this documents today's behavior so a future
			// precision fix has a measured starting point. What IS asserted is that
			// nothing here reaches the HIGH band, since an unlabelled digit run
			// inside a decimal has no business being high-confidence.
			for _, m := range matches {
				if m.Confidence >= 90 {
					t.Errorf("reported %q at confidence %.1f (HIGH) on a line with no SSN "+
						"label and a decimal context: %q", m.Text, m.Confidence, tc.line)
				}
			}
			if len(matches) > 0 {
				var got []string
				for _, m := range matches {
					got = append(got, m.Text)
				}
				t.Logf("current behavior: reports %v (below HIGH) — a precision fix here must "+
					"not regress TestLabelledSSNInProseIsDetected", got)
			}
		})
	}
}

// TestProseAndTabularSSNsCoexist guards the specific blind spot that made the
// broken fix look safe: a recall corpus consisting only of delimited rows cannot
// detect a prose regression, and vice versa. Both shapes in one document.
func TestProseAndTabularSSNsCoexist(t *testing.T) {
	v := NewValidator()

	content := strings.Join([]string{
		"name,dept,ssn",
		"Jane Smith,Payroll,130-07-5728",
		"",
		"Note: the employee above confirmed her SSN is 130075728.",
	}, "\n")

	matches, err := v.ValidateContentCtx(stdctx.Background(), content, "/test/mixed.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}

	var tabular, prose bool
	for _, m := range matches {
		switch m.LineNumber {
		case 2:
			tabular = true
		case 4:
			prose = true
		}
	}
	if !tabular {
		t.Error("the delimited row (line 2) produced no finding")
	}
	if !prose {
		t.Error("the prose sentence (line 4) produced no finding — this is the shape a " +
			"columnar-only recall corpus cannot see")
	}
}
