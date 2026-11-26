// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

const seedRepeats = 20

// seedText uses the SSN fixture the other engine tests use.
const seedText = "Employee SSN: 219-09-9999\n"

func seedEngine(t *testing.T, seed []byte) *redact.Engine {
	t.Helper()
	e, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"SSN"}, Strategy: redact.Synthetic})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if seed != nil {
		redact.SeedSyntheticScopeForTest(e, seed)
	}
	return e
}

func redactN(t *testing.T, e *redact.Engine, n int) []string {
	t.Helper()
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		res, err := e.Redact(context.Background(), redact.Request{Text: seedText})
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if strings.Contains(res.Redacted, "219-09-9999") {
			t.Fatalf("request %d left the SSN in clear: %q", i, res.Redacted)
		}
		out = append(out, res.Redacted)
	}
	return out
}

// A seeded Engine is repeatable: 20 requests are byte-identical, and a second Engine with the same
// seed gives the same bytes. A different seed differs.
func TestSeededEngineSyntheticIsRepeatable(t *testing.T) {
	got := redactN(t, seedEngine(t, []byte("engine-seed")), seedRepeats)
	for i, g := range got {
		if g != got[0] {
			t.Fatalf("request %d = %q, request 0 = %q", i, g, got[0])
		}
	}
	if again := redactN(t, seedEngine(t, []byte("engine-seed")), 1)[0]; again != got[0] {
		t.Fatalf("a second Engine with the same seed gave %q, want %q", again, got[0])
	}
	if other := redactN(t, seedEngine(t, []byte("another-seed")), 1)[0]; other == got[0] {
		t.Fatalf("a different seed gave the same output %q", other)
	}
}

// Without the hook the default stays random: one SSN across requests gets at least two replacements.
func TestUnseededEngineSyntheticStaysRandom(t *testing.T) {
	distinct := map[string]bool{}
	for _, g := range redactN(t, seedEngine(t, nil), seedRepeats) {
		distinct[g] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("%d requests gave %d distinct replacement(s); the default must not be a constant", seedRepeats, len(distinct))
	}
	t.Logf("%d requests, %d distinct replacements", seedRepeats, len(distinct))
}

// The seed touches only synthetic: simple and format_preserving do not draw from the scope.
func TestSeededEngineLeavesOtherStrategiesAlone(t *testing.T) {
	for _, s := range []redact.Strategy{redact.Simple, redact.FormatPreserving} {
		plain, _ := redact.NewEngine(redact.EngineOptions{Checks: []string{"SSN"}, Strategy: s})
		seeded, _ := redact.NewEngine(redact.EngineOptions{Checks: []string{"SSN"}, Strategy: s})
		redact.SeedSyntheticScopeForTest(seeded, []byte("x"))
		a, err1 := plain.Redact(context.Background(), redact.Request{Text: seedText})
		b, err2 := seeded.Redact(context.Background(), redact.Request{Text: seedText})
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		if s == redact.Simple && a.Redacted != b.Redacted {
			t.Fatalf("strategy %v: seeded %q != plain %q", s, b.Redacted, a.Redacted)
		}
		if strings.Contains(b.Redacted, "219-09-9999") {
			t.Fatalf("strategy %v left the SSN in clear", s)
		}
	}
}
