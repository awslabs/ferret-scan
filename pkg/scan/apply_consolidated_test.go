// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"strings"
	"testing"
)

// #631: RedactText returned a string byte-identical to its input while reporting Count=1, for any
// finding whose reported Text is a rendered SUMMARY rather than a document span.
//
// Measured on the parent commit with the plainest possible call — ScanText(ctx, text, TextOptions{})
// and no config at all:
//
//	INTELLECTUAL_PROPERTY conf=98, reported Text ending "[+17 more matches on line]"
//	simple / format_preserving / synthetic: Count=1, output == input, 6 values in cleartext
//
// The safety net was already on the path and could not fire: plaintext.RedactString calls
// redactors.RestoreBoundedMatchText, whose gate needs Context.FullLine AND
// Metadata[MatchTextTruncatedKey], and apply.go carried neither.

// boundedConsolidationText is one long line holding six copyright notices, which is what makes the
// intellectual-property validator consolidate them and BOUND the reported text.
//
// Six rather than two: the bounding only kicks in past a threshold of matches on the line, and a
// fixture that does not trip it would test the ordinary locatable path while appearing to cover this.
const boundedConsolidationText = "Slide footer: " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. " +
	"Copyright (c) 2026 Acme Corporation. All Rights Reserved. ACME CONFIDENTIAL AND PROPRIETARY. "

func TestRedactTextMasksABoundedConsolidatedFinding(t *testing.T) {
	res, err := ScanText(context.Background(), boundedConsolidationText, TextOptions{})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}

	// Non-vacuity, and it is the whole basis of the test: the fixture must produce a finding whose
	// reported Text does NOT occur in the input. If a future change makes the text locatable, this
	// test would pass through the ordinary path and prove nothing about #631.
	var bounded bool
	for _, f := range res.Findings {
		if f.Text != "" && !strings.Contains(boundedConsolidationText, f.Text) {
			bounded = true
			t.Logf("bounded finding: %s conf=%.0f text=%q", f.Type, f.Confidence, f.Text)
		}
	}
	if !bounded {
		t.Fatalf("no finding has a reported Text absent from the input, so this fixture no longer "+
			"exercises the bounded-consolidation case. %d findings; re-derive the fixture rather than "+
			"deleting the test", len(res.Findings))
	}

	for _, tc := range []struct {
		name     string
		strategy RedactStrategy
	}{
		{"simple", StrategySimple},
		{"format_preserving", StrategyFormatPreserving},
		{"synthetic", StrategySynthetic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RedactText(boundedConsolidationText, res.Findings, tc.strategy)
			if err != nil {
				t.Fatalf("RedactText: %v", err)
			}
			if out.Text == boundedConsolidationText {
				t.Errorf("output is byte-identical to the input while Count=%d — this is #631: the "+
					"value is in cleartext and the caller was told it was redacted", out.Count)
			}
			if n := strings.Count(out.Text, "Acme Corporation"); n != 0 {
				t.Errorf("%d occurrences of the value survive redaction (input had 6)", n)
			}
		})
	}
}

// TestRedactTextCountIsReplacementsNotFindings pins the accounting.
//
// Count was len(matches) — the findings handed in — which made it an attestation the function could
// not support: a match the redactor cannot locate hits `continue` before its mapping is recorded, so a
// value left in cleartext was still counted as redacted. It is now len(mappings).
func TestRedactTextCountIsReplacementsNotFindings(t *testing.T) {
	const text = "Card 4111 1111 1111 1111 on file.\n"

	res, err := ScanText(context.Background(), text, TextOptions{Checks: []string{"CREDIT_CARD"}})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}

	// A finding that cannot possibly be located, appended to whatever the scan really found. The
	// redactor must skip it and must NOT count it.
	unlocatable := Finding{
		Type:       "SSN",
		Validator:  "ssn",
		Confidence: 90,
		LineNumber: 1,
		Text:       "000-00-0000 this string is not in the document",
	}
	findings := append([]Finding{}, res.Findings...)
	findings = append(findings, unlocatable)

	out, err := RedactText(text, findings, StrategySimple)
	if err != nil {
		t.Fatalf("RedactText: %v", err)
	}
	if out.Count >= len(findings) {
		t.Errorf("Count = %d for %d findings, one of which cannot be located anywhere in the input. "+
			"Counting it attests to a redaction that did not happen, which is what let a cleartext "+
			"value read as handled", out.Count, len(findings))
	}
	// And the locatable one must still be redacted, or the count is low for the wrong reason.
	if strings.Contains(out.Text, "4111 1111 1111 1111") {
		t.Errorf("the locatable value was not redacted either, so the lower Count is not evidence of "+
			"correct accounting: %q", out.Text)
	}
}

// TestDerivedTruncationFlagCannotMisfireOnALocatableFinding is the must-NOT-fire half.
//
// The truncation flag is derived from two observable facts rather than plumbed through, so the risk is
// that it fires for an ordinary finding and masks its whole LINE instead of just the value — masking
// more than asked is data loss, even though it is not a leak.
func TestDerivedTruncationFlagCannotMisfireOnALocatableFinding(t *testing.T) {
	const text = "Employee SSN: 536-90-4271 in the HR record for the payroll team.\n"

	res, err := ScanText(context.Background(), text, TextOptions{Checks: []string{"SSN"}})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("no SSN finding, so this test cannot observe the locatable path")
	}
	// Non-vacuity: the reported text must really be locatable, or this is the bounded case again.
	if !strings.Contains(text, res.Findings[0].Text) {
		t.Fatalf("the reported text %q is not in the input, so this is not the locatable case",
			res.Findings[0].Text)
	}

	out, err := RedactText(text, res.Findings, StrategySimple)
	if err != nil {
		t.Fatalf("RedactText: %v", err)
	}
	if strings.Contains(out.Text, "536-90-4271") {
		t.Errorf("the value survived redaction: %q", out.Text)
	}
	// The surrounding prose must survive: if the derived flag misfired, RestoreBoundedMatchText would
	// have replaced Text with the whole trimmed line and the redactor would have masked all of it.
	for _, keep := range []string{"Employee SSN:", "in the HR record", "payroll team"} {
		if !strings.Contains(out.Text, keep) {
			t.Errorf("redaction removed %q, which is not the reported value — the derived truncation "+
				"flag misfired on a locatable finding and masked the whole line: %q", keep, out.Text)
		}
	}
}
