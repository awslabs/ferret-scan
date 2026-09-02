// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactverify"
)

// The predicate and the enforcer must be evaluated over the SAME match set.
//
// redactText narrows `matches` through ExpandClusterMatches -> RestoreBoundedMatchText ->
// ResolveOverlaps before applying positional replacements, and that narrowing is right for positions:
// ResolveOverlaps drops a match fully contained in a wider surviving one, because the wider span's
// replacement covers the contained value at that reported position.
//
// It is wrong for the completeness invariant. Every OTHER copy of the contained value survives, and if
// the sweep is handed the post-narrowing set it never learns the value exists. The floor, meanwhile,
// judges the full reported list — so it refuses a file the sweep believed it had cleaned.
//
// Measured on a 480-file corpus: this single asymmetry was the sole cause of 3 of the 4 files that
// refused and of 13 of the 14 residual values, including OTP secrets and recovery codes.
func TestSweepIsGivenTheSameMatchSetTheFloorVerifies(t *testing.T) {
	// The condition that actually reproduces the defect: the value's ONLY reported occurrence is
	// CONTAINED in a wider reported match, and the value also appears somewhere that is NOT reported at
	// all.
	//
	// ResolveOverlaps drops the contained PERSON_NAME, which is right for positions — the wider span's
	// replacement covers that copy. The unreported copy on line 2 is then reachable ONLY by the sweep,
	// and only if the sweep is handed the match set BEFORE the narrowing. Given the post-narrowing set
	// it never learns the value exists, and the floor — which judges the full reported list — refuses
	// the file.
	//
	// An earlier version of this test also reported line 2's name as its own match. ResolveOverlaps kept
	// that one (different FullLine, so it is not contained), the positional pass redacted it, and the
	// test passed with the sweep fed either set. A mutation swapping the sets survived, which is what
	// exposed it. The copy has to be UNREPORTED.
	const wider = "Copyright (c) 2019 W3C and Jeff Carpenter"
	const line2 = "reviewed by Jeff Carpenter"
	content := wider + "\n" + line2 + "\n"

	matches := []detector.Match{
		{Text: wider, Type: "INTELLECTUAL_PROPERTY", LineNumber: 1, Confidence: 70,
			Context: detector.ContextInfo{FullLine: wider}},
		{Text: "Jeff Carpenter", Type: "PERSON_NAME", LineNumber: 1, Confidence: 95,
			Context: detector.ContextInfo{FullLine: wider}},
	}

	// Non-vacuity 1: the narrowing must actually drop the contained match.
	if got := len(redactors.ResolveOverlaps(matches)); got == len(matches) {
		t.Fatalf("fixture bug: ResolveOverlaps kept all %d matches, so the contained-match case is not "+
			"covered and this test would pass on the unfixed code", got)
	}
	// Non-vacuity 2: the unreported copy must be present to begin with.
	if !strings.Contains(content, line2) {
		t.Fatal("fixture bug: the unreported copy is absent")
	}

	pr := NewPlainTextRedactor(nil, nil)
	pr.SetPositionCorrelationEnabled(false)
	out, _, err := pr.RedactString(content, matches, redactors.ParseRedactionStrategy("format_preserving"))
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}

	if strings.Contains(out, "Jeff Carpenter") {
		t.Errorf("a reported PERSON_NAME survives at an unreported position:\n%s\n"+
			"ResolveOverlaps dropped the only match carrying that value, so unless the sweep is given "+
			"the pre-narrowing set it never sees the value and the floor refuses the whole file.", out)
	}
	if r := redactverify.ResidualTypes([]byte(out), matches); len(r) > 0 {
		t.Errorf("the floor would refuse this output, reporting %v", r)
	}
}
