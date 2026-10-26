// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestCorpusHoldsEveryOverlapShape is the guard #773 asked for: the corpus must keep holding at least
// one same-line IDENTICAL, PARTIAL and CONTAINED overlap group on the text path, or the redaction
// snapshots stop locking the overlap rule without anything failing.
//
// That is not hypothetical. creditcard_phone_overlap was written to lock containment, and it quietly
// stopped holding any overlap when the PHONE validator stopped firing inside the card: its snapshot kept
// passing because there was nothing left for it to test. The groups are derived from what the real scan
// reports, through the same redactors.ResolveOverlaps every writer uses, so a validator change that makes
// a case stop overlapping fails here instead of going unnoticed.
func TestCorpusHoldsEveryOverlapShape(t *testing.T) {
	found := map[redactors.GroupKind][]string{}
	for _, c := range Cases {
		matches, _ := scanCase(t, c)
		for _, g := range redactors.ResolveOverlaps(matches) {
			if g.IsGroup() {
				found[g.Kind] = append(found[g.Kind], c.Name)
			}
		}
	}
	for _, kind := range []redactors.GroupKind{redactors.GroupIdentical, redactors.GroupPartial, redactors.GroupContained} {
		cases := found[kind]
		if len(cases) == 0 {
			t.Errorf("no corpus case holds a same-line %s overlap group any more; the redaction snapshots no longer "+
				"lock how that shape is rendered (#773). Add or repair a case so one does.", kind)
			continue
		}
		sort.Strings(cases)
		t.Logf("%s groups: %d, in %s", kind, len(cases), strings.Join(dedupe(cases), ", "))
	}
	// The dedicated case must hold all three itself, so the shapes cannot drift apart across cases.
	for _, kind := range []redactors.GroupKind{redactors.GroupIdentical, redactors.GroupPartial, redactors.GroupContained} {
		held := false
		for _, name := range found[kind] {
			held = held || name == "overlap_groups_render_once"
		}
		if !held {
			t.Errorf("overlap_groups_render_once no longer holds the %s shape", kind)
		}
	}
}

func dedupe(sorted []string) []string {
	var out []string
	for _, s := range sorted {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
