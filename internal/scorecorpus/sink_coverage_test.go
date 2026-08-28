// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"strings"
	"testing"
)

// #315: four cases — c04_tsv, c45_tsv_no_header, s09_html_table, s11_sql_insert — carried
// Redactable: false and were skipped by the sink gate, on the basis that .tsv, .html and .sql had
// no registered redactor. That stopped being true: PR #359 (2a0e96c) made GetRedactorForFile fall
// back to the same preprocessors.LooksLikeText sniff the router uses to admit a file, so scan
// admission and redact admission now agree by construction.
//
// So the exclusion was hiding four cases from the leak gate for a reason that no longer held —
// which is the worse direction of the two: a case outside the gate cannot fail it.
//
// This test is what stops that recurring. The Redactable field is deliberately kept (ODF still has
// no redactor, #514), but its false branch is now a deliberate act rather than a default: marking a
// case unredactable removes it from the leak gate, and that has to be visible.
func TestTheSinkGateCoversEveryLabelledCase(t *testing.T) {
	var skipped []string
	var labelled int
	for _, c := range GatedCases() {
		if len(c.Labels) == 0 {
			continue
		}
		labelled++
		if !c.Redactable {
			skipped = append(skipped, c.Name)
		}
	}

	// Non-vacuity: if GatedCases ever returns nothing, an empty skip list means nothing.
	if labelled < 100 {
		t.Fatalf("only %d labelled cases; this test asserts a property OVER the corpus and "+
			"would be near-vacuous", labelled)
	}

	if len(skipped) != 0 {
		t.Errorf("%d of %d labelled cases are excluded from the redaction sink gate:\n  %s\n\n"+
			"A case outside the gate cannot fail it. If a file type genuinely has no redactor "+
			"(ODF, #514, is the real remaining one) then say so here with the reason — but four "+
			"cases sat outside this gate because .tsv/.html/.sql once had no redactor, and they "+
			"stayed there for the whole time after #359 gave them one (#315).",
			len(skipped), labelled, strings.Join(skipped, "\n  "))
	}
}
