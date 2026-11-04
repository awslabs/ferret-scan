// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The rendering tests below ask about one value's shape, so each call is its own invocation: a fresh
// synthetic scope, which simple and format_preserving never read. Consistency ACROSS calls is what
// scope_test.go is about.

func gen(t testing.TB, v, typ string, st redactors.RedactionStrategy) string {
	t.Helper()
	s, err := Generate(v, typ, st, redactors.NewSyntheticScope())
	if err != nil {
		t.Fatalf("Generate(%q, %s, %s): %v", v, typ, st, err)
	}
	return s
}

func rend(t testing.TB, v, typ string, st redactors.RedactionStrategy) Rendering {
	t.Helper()
	r, err := Render(v, typ, st, redactors.NewSyntheticScope())
	if err != nil {
		t.Fatalf("Render(%q, %s, %s): %v", v, typ, st, err)
	}
	return r
}

func rendGroup(t testing.TB, g redactors.OverlapGroup, ms []detector.Match, st redactors.RedactionStrategy) Rendering {
	t.Helper()
	r, err := RenderGroup(g, ms, st, redactors.NewSyntheticScope())
	if err != nil {
		t.Fatalf("RenderGroup(%s): %v", st, err)
	}
	return r
}
