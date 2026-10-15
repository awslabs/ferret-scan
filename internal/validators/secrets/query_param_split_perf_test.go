// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// queryParamLine is one URL whose query string holds k token parameters.
func queryParamLine(k int) string {
	parts := make([]string, k)
	for i := range parts {
		parts[i] = fmt.Sprintf("token=Ab%05dCdEfGh%05d", i, i)
	}
	return "https://h.example/cb?" + strings.Join(parts, "&")
}

// Splitting a query string into its parameters must cost one pass over the line. Resuming the
// unquoted pattern after each `&` re-ran its greedy value to the end of the line every time:
// 1.1s / 4.3s / 16.9s at 2,000 / 4,000 / 8,000 parameters, against 0.1s / 0.2s / 0.5s for one pass.
func TestQueryParamSplitIsLinear(t *testing.T) {
	if raceEnabled {
		t.Skip("complexity guard runs without -race (CI's complexity step): -race compresses the ratio " +
			"and costs ~50s here")
	}
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}
	v := NewValidator()
	const k = 1000
	base, big := queryParamLine(k), queryParamLine(4*k)
	var nBase, nBig int
	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { nBase = len(v.findKeywordSecrets(base)) },
		func() { nBig = len(v.findKeywordSecrets(big)) })
	if err != nil {
		t.Fatalf("measuring: %v", err)
	}
	// Non-vacuity: each parameter is its own candidate, or the ratio times nothing.
	if nBase != k || nBig != 4*k {
		t.Fatalf("got %d and %d candidates, want %d and %d", nBase, nBig, k, 4*k)
	}
	t.Logf("4x parameters cost %s", g)
	if _, ok := g.Ticks(); !ok {
		t.Logf("growth ratio NOT asserted — %s", g.ResolutionNote())
		return
	}
	perfguard.ReportMargin(t, "secrets query-string split", g, 8.0, perfguard.StayBelow)
	if g.Ratio > 8.0 {
		t.Errorf("4x query parameters cost %s — linear is ~4x and quadratic ~16x", g)
	}
}
