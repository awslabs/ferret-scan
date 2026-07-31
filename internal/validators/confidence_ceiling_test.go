// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
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
