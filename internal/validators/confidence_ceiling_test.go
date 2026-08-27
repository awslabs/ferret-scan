// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"sort"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
)

// A validator can declare a hard ceiling on a finding's confidence, and the bridge
// must honour it after every adjustment that raises confidence.
//
// The mechanism exists because confidence is raised in three places AFTER a validator
// returns — a document-context adjustment on each path, and a cross-path correlation
// boost — so a validator that clamps its own return value cannot make the bound stick.
// Measured: a value the secrets validator scored 55 was reported at 80 in a real
// document once +20 context and +5 correlation had been applied.
//
// It is generic on purpose. Any validator with a value-intrinsic reason to say "no
// amount of surrounding context should promote this" can set the key; the bridge needs
// no knowledge of which validator or which shape.

func TestClampToCeilingHonoursADeclaredCeiling(t *testing.T) {
	m := detector.Match{
		Confidence: 80,
		Metadata:   map[string]any{ConfidenceCeilingKey: 55.0},
	}
	clampToCeiling(&m)

	if m.Confidence != 55 {
		t.Errorf("Confidence = %v, want 55.\nA declared ceiling must survive the "+
			"document-context and cross-path boosts, which is the whole reason the clamp "+
			"lives in the bridge rather than in the validator.", m.Confidence)
	}
}

func TestClampToCeilingLeavesLowerConfidenceAlone(t *testing.T) {
	m := detector.Match{
		Confidence: 40,
		Metadata:   map[string]any{ConfidenceCeilingKey: 55.0},
	}
	clampToCeiling(&m)

	if m.Confidence != 40 {
		t.Errorf("Confidence = %v, want 40 unchanged: a ceiling is an upper bound, "+
			"not a target to raise toward", m.Confidence)
	}
}

// TestClampToCeilingIgnoresMalformedCeilings is the safety floor. A ceiling that is
// absent, the wrong type, or non-positive must be ignored rather than treated as zero:
// clamping to 0 would erase a finding's confidence and, depending on the band filter,
// remove it from the report entirely — which per the sink rule means it stops being
// redacted.
func TestClampToCeilingIgnoresMalformedCeilings(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
	}{
		{"nil metadata", nil},
		{"key absent", map[string]any{"other": 1.0}},
		{"wrong type int", map[string]any{ConfidenceCeilingKey: 55}},
		{"wrong type string", map[string]any{ConfidenceCeilingKey: "55"}},
		{"zero", map[string]any{ConfidenceCeilingKey: 0.0}},
		{"negative", map[string]any{ConfidenceCeilingKey: -10.0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := detector.Match{Confidence: 90, Metadata: tc.meta}
			clampToCeiling(&m)
			if m.Confidence != 90 {
				t.Errorf("Confidence = %v, want 90 unchanged. A malformed ceiling must be "+
					"ignored; clamping to 0 would erase the finding's confidence and could "+
					"drop it from the report, which stops it being redacted.", m.Confidence)
			}
		})
	}
}

// TestCeilingKeyMatchesTheSecretsValidator guards the one duplicated literal. The
// bridge declares the key rather than importing it from a validator package, so the
// dependency points one way; this test is what keeps the two spellings from drifting
// apart silently, which would turn every ceiling into a no-op.
func TestCeilingKeyMatchesTheSecretsValidator(t *testing.T) {
	if ConfidenceCeilingKey != secrets.ConfidenceCeilingKey {
		t.Errorf("ceiling key drift: bridge has %q, secrets validator has %q.\n"+
			"The literal is duplicated to keep the bridge from depending on a validator "+
			"package. If they diverge, every declared ceiling is silently ignored and the "+
			"findings it protects go back to being promoted by document context.",
			ConfidenceCeilingKey, secrets.ConfidenceCeilingKey)
	}
}

// TestTheIPAddressValidatorsCeilingReachesTheBridge closes the loop for #513.
//
// The ipaddress validator caps a context-free dotted quad at 75 because a software version
// is structurally identical to a routable address. That cap was applied to a local variable
// and nowhere else, so the document-context adjustment undid it: measured on ten real .odt
// documents carrying a byte-identical LibreOffice generator string, eight reported HIGH 95
// and two MEDIUM 75, the difference being body text the match has nothing to do with.
//
// This drives the validator for real rather than comparing two constants, so it fails both
// if the key drifts and if the validator stops publishing it. TestCeilingKeyMatchesThe-
// SecretsValidator cannot cover ipaddress, whose key is unexported.
func TestTheIPAddressValidatorsCeilingReachesTheBridge(t *testing.T) {
	matches, err := ipaddress.NewValidator().ValidateContent(
		"Application: LibreOffice/24.8.4.2$MacOSX_AARCH64", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1 for the generator string", len(matches))
	}

	m := matches[0]
	if _, ok := m.Metadata[ConfidenceCeilingKey]; !ok {
		t.Fatalf("the capped match carries no %q the bridge can read.\nIts metadata keys: %v\n"+
			"If the validator spells the key differently the ceiling is silently ignored and "+
			"the version goes back to being promoted to HIGH by document context (#513).",
			ConfidenceCeilingKey, metadataKeys(m.Metadata))
	}

	// Now do what the bridge does: add the document-level adjustment, then clamp.
	// +20 is the adjustment measured on the real .odt documents.
	before := m.Confidence
	m.Confidence += 20
	clampToCeiling(&m)

	if m.Confidence != before {
		t.Errorf("after a +20 document adjustment and the clamp, confidence = %v, want %v.\n"+
			"This is the exact sequence that reported a LibreOffice version string at HIGH 95.",
			m.Confidence, before)
	}
	if m.Confidence >= 90 {
		t.Errorf("confidence = %v, which is HIGH; a value the validator declared ambiguous "+
			"must not reach HIGH on document-level evidence", m.Confidence)
	}
}

func metadataKeys(meta map[string]any) []string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
