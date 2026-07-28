// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// fingerprint renders a match set into a stable, order-independent string so two
// runs can be compared by content regardless of the order the slice happens to
// be in. It sorts, so it cannot itself hide an ordering difference — that is the
// job of the caller, which compares raw slices too.
func fingerprint(matches []detector.Match) string {
	rows := make([]string, len(matches))
	for i, m := range matches {
		rows[i] = fmt.Sprintf("%s|%d|%.2f|%s", m.Type, m.LineNumber, m.Confidence, m.Text)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// TestSocialMedia_ClusteringIsDeterministic is the regression test for the plain-
// .html nondeterminism: the same content produced 14–21 findings across runs of
// one binary.
//
// Root cause was map iteration order leaking into an order-sensitive stage.
// processLineForAllPatterns discovered matches by ranging over the compiledPatterns
// map, and processLineMatchesWithClustering flattened the line-keyed map with a
// bare range; the resulting slice was a random permutation. The clustering that
// consumes it is greedy first-wins (identifyProfileClusters seeds on slice
// position), and areMatchesRelated is symmetric but NOT transitive, so a different
// seed order produced a different partition and collapsed a different number of
// rows into SOCIAL_MEDIA_CLUSTER findings.
//
// The content below is built to exercise exactly that: many handles that pass the
// proximity gate and are pairwise-but-not-transitively related, so the number of
// clusters is sensitive to seed order on the unfixed code.
func TestSocialMedia_ClusteringIsDeterministic(t *testing.T) {
	v := newConfiguredValidator()

	var b strings.Builder
	// Interleave several platforms and overlapping usernames across adjacent
	// lines so the ±16-line proximity window links many of them and the greedy
	// partition is order-sensitive.
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "Contact https://twitter.com/user%d and @user%d today\n", i%7, i%5)
		fmt.Fprintf(&b, "Also see https://github.com/user%d and https://facebook.com/user%d.page\n", i%5, i%7)
		fmt.Fprintf(&b, "Profile https://linkedin.com/in/user%d plus https://instagram.com/user%d\n", i%7, i%5)
	}
	content := b.String()

	first, err := v.ValidateContent(content, "determinism-fixture.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	want := fingerprint(first)

	// Many iterations: map order is randomized per-run within a process, so
	// repeated calls sample different permutations. On the unfixed code the count
	// and partition drift within a few dozen calls.
	const iterations = 200
	for i := 0; i < iterations; i++ {
		got, err := v.ValidateContent(content, "determinism-fixture.txt")
		if err != nil {
			t.Fatalf("ValidateContent (iter %d): %v", i, err)
		}
		if len(got) != len(first) {
			t.Fatalf("iter %d: finding COUNT changed: got %d, first run %d "+
				"(clustering partition is nondeterministic)", i, len(got), len(first))
		}
		if fp := fingerprint(got); fp != want {
			t.Fatalf("iter %d: finding SET changed across runs of the same binary:\n--- first ---\n%s\n--- iter %d ---\n%s",
				i, want, i, fp)
		}
	}
}

// TestSocialMedia_PerLineMatchOrderIsStable pins the narrower half of the fix:
// processLineForAllPatterns must return a line's matches in a fixed order
// regardless of the compiledPatterns map iteration order, because that order is
// what seeds the clustering. A single line carrying several distinct platform
// handles is enough to exercise it.
func TestSocialMedia_PerLineMatchOrderIsStable(t *testing.T) {
	v := newConfiguredValidator()

	// One line, many platforms, so the only ordering input is the pattern-map
	// iteration order.
	content := "links: https://twitter.com/alice https://github.com/alice " +
		"https://facebook.com/alice.page https://instagram.com/alice https://linkedin.com/in/alice"

	first, err := v.ValidateContent(content, "single-line.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	// Compare the RAW slice order (not a sorted fingerprint) across runs.
	rawOrder := func(ms []detector.Match) string {
		parts := make([]string, len(ms))
		for i, m := range ms {
			parts[i] = m.Type + ":" + m.Text
		}
		return strings.Join(parts, ",")
	}
	want := rawOrder(first)

	for i := 0; i < 200; i++ {
		got, err := v.ValidateContent(content, "single-line.txt")
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		if o := rawOrder(got); o != want {
			t.Fatalf("iter %d: per-line match ORDER changed across runs:\n want: %s\n got:  %s", i, want, o)
		}
	}
}
