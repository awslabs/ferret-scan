// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// THE POPULATION A GUARD MEASURES IS PART OF WHAT IT ASSERTS.
//
// internal/validators/finding_retention_test.go already bounds a finding's metadata key count
// against the Go map bucket cliff. It drives retentionProbeValidator, which emits exactly ONE
// metadata key, and its own comment says the synthetic validator is deliberate: "so the budgets
// below measure the RETENTION mechanism and not that validator's own vocabulary, which changes for
// unrelated reasons."
//
// That reasoning is right for the byte budgets and fatal for the cliff, because THE CLIFF IS
// VOCABULARY. A guard on the key count, driven by a fixture that pins the key count, bounds the one
// property its fixture was chosen to exclude.
//
// Measured over this corpus with the real validator set: every one of the 108 findings carries
// 9 to 31 metadata keys. Not one is at 8. So the cliff the other guard exists to keep the tool
// below was crossed before it was written, by every finding, and it passes.
//
// This census is the same question asked of the real population. It is a COUNT and a KEY LIST, both
// exact integers and strings, so it is identical on every platform and in every mode -- the argument
// the other guard makes for using a count rather than a byte figure, applied to a population that
// can actually move it. Any new metadata key, from a validator or from the document bridge, changes
// this file and has to be justified in review with the band it lands in.
//
// See #621. The byte consequences are computed and LOGGED below but deliberately kept out of the
// golden and out of every assertion: they come from the allocator, and this repo has been burned
// repeatedly by thresholds calibrated on one machine (#509, #546).

// metadataCliffProbeReps is high enough that a band jump (+329 B at the smallest) is orders of
// magnitude clear of MemStats noise, and low enough to stay well under a second.
const metadataCliffProbeReps = 8000

// metadataCliffProbeSamples is 3 and the statistic is the MINIMUM, not the mean.
//
// This is not a style choice. At one sample the probe reported a phantom band boundary at 2 keys --
// a map[string]any is the same size at 1 and 2 keys -- because the first size measured absorbs the
// allocations of the loop's own warm-up. Noise in a heap measurement is one-sided: it can only make
// a size look BIGGER, never smaller. So the minimum across samples is the allocation floor, which is
// the quantity a band boundary is a property of, and it is the same statistic internal/perfguard
// already uses for its growth ratios.
const metadataCliffProbeSamples = 3

// firstMetadataCliff is the key count at which a map[string]any first allocates a second bucket
// group. internal/validators/finding_retention_test.go hardcodes this as
// metadataBucketCapacity = 8 ("Not a tuning knob. It is a property of the runtime's map
// implementation"), which is true and is exactly why it needs checking: Go 1.24 replaced the map
// implementation wholesale with Swiss tables, and a constant describing runtime internals goes
// silently wrong across such a change rather than loudly.
const firstMetadataCliff = 9

// measureMapBandBoundaries returns the key counts at which a map[string]any grows, measured on the
// running toolchain.
func measureMapBandBoundaries(t *testing.T, maxKeys int) (boundaries []int, sizeAt []float64) {
	t.Helper()

	sizeAt = make([]float64, maxKeys+1)
	names := make([]string, maxKeys)
	for i := range names {
		names[i] = fmt.Sprintf("metadata_key_name_%02d", i)
	}

	sample := func(k int) float64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		hold := make([]map[string]any, metadataCliffProbeReps)
		for r := range hold {
			m := make(map[string]any)
			for i := 0; i < k; i++ {
				m[names[i]] = "a-twenty-five-byte-value!"
			}
			hold[r] = m
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		per := float64(after.HeapAlloc-before.HeapAlloc) / float64(metadataCliffProbeReps)
		runtime.KeepAlive(hold)
		return per
	}

	// Warm up before the first measured size, so the size measured first is not the one that pays
	// for the probe's own allocations.
	sample(1)

	for k := 1; k <= maxKeys; k++ {
		low := sample(k)
		for s := 1; s < metadataCliffProbeSamples; s++ {
			if p := sample(k); p < low {
				low = p
			}
		}
		sizeAt[k] = low
	}

	// A band jump is at least +329 B measured; 100 B is far above run-to-run spread and far below
	// the smallest real jump, so it separates them without being tuned to either.
	const jumpFloor = 100
	for k := 2; k <= maxKeys; k++ {
		if sizeAt[k]-sizeAt[k-1] > jumpFloor {
			boundaries = append(boundaries, k)
		}
	}
	return boundaries, sizeAt
}

// TestMetadataKeyCensusOverTheRealValidatorSet locks the per-type metadata vocabulary of every
// finding the real validators produce over the corpus.
func TestMetadataKeyCensusOverTheRealValidatorSet(t *testing.T) {
	if testing.Short() {
		t.Skip("scans the whole corpus and probes map growth on the running toolchain; skipped in -short")
	}

	const maxProbedKeys = 34
	boundaries, sizeAt := measureMapBandBoundaries(t, maxProbedKeys)
	t.Logf("map[string]any growth on %s: bands begin at key counts %v", runtime.Version(), boundaries)

	// Non-vacuity for the probe half. If the measurement found no jumps -- a build with a different
	// allocator, a maxKeys too small, a GC that did not settle -- every byte figure below would read
	// as identical and the log would say the population costs nothing extra.
	if len(boundaries) < 2 {
		t.Fatalf("found %d map growth boundaries in 1..%d (%v); expected at least 2, so the byte "+
			"figures logged below would be meaningless", len(boundaries), maxProbedKeys, boundaries)
	}
	if boundaries[0] != firstMetadataCliff {
		t.Errorf("a map[string]any first grows at %d keys on %s, but this repo hardcodes the cliff at "+
			"%d -- internal/validators/finding_retention_test.go's metadataBucketCapacity = %d and its "+
			"failure text quote a +342 B/finding cost derived from it. The runtime's map "+
			"implementation has changed under those numbers (Go 1.24 already replaced it once with "+
			"Swiss tables); re-measure before trusting any byte figure in that file. Measured bands: %v",
			boundaries[0], runtime.Version(), firstMetadataCliff, firstMetadataCliff-1, boundaries)
	}

	bytesFor := func(n int) float64 {
		if n <= 0 {
			return 0
		}
		if n > maxProbedKeys {
			return sizeAt[maxProbedKeys]
		}
		return sizeAt[n]
	}
	bandOf := func(n int) int {
		b := 0
		for _, edge := range boundaries {
			if n >= edge {
				b++
			}
		}
		return b
	}

	type census struct {
		widest int
		keys   []string
		n      int
	}
	byType := map[string]*census{}
	hist := map[int]int{}
	totalFindings, withMetadata, overFirstCliff := 0, 0, 0
	var totalBytes float64

	for _, c := range Cases {
		matches, _ := scanCase(t, c)
		for _, m := range matches {
			totalFindings++
			n := len(m.Metadata)
			if n == 0 {
				continue
			}
			withMetadata++
			hist[n]++
			totalBytes += bytesFor(n)
			if n >= firstMetadataCliff {
				overFirstCliff++
			}
			cur := byType[m.Type]
			if cur == nil {
				cur = &census{}
				byType[m.Type] = cur
			}
			cur.n++
			if n > cur.widest {
				keys := make([]string, 0, n)
				for k := range m.Metadata {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				cur.widest, cur.keys = n, keys
			}
		}
	}

	// Non-vacuity for the population half, three ways. A corpus that produced nothing, findings with
	// no metadata at all, or a single type would each satisfy a snapshot comparison trivially -- and
	// the golden would then lock in the emptiness rather than the vocabulary.
	if totalFindings == 0 {
		t.Fatal("the corpus produced no findings at all, so this census would lock an empty file")
	}
	if withMetadata == 0 {
		t.Fatalf("none of the %d findings carried ANY metadata, so this census cannot see the "+
			"vocabulary it exists to bound", totalFindings)
	}
	if len(byType) < 10 {
		t.Fatalf("only %d finding types carried metadata; the corpus covers far more than that, so "+
			"the validator set under test is not the real one", len(byType))
	}

	t.Logf("population: %d findings, %d carrying metadata, across %d types",
		totalFindings, withMetadata, len(byType))
	t.Logf("%d of %d findings (%.1f%%) already sit at or past the first cliff of %d keys; "+
		"metadata maps cost %.0f B/finding on average here",
		overFirstCliff, withMetadata, 100*float64(overFirstCliff)/float64(withMetadata),
		firstMetadataCliff, totalBytes/float64(withMetadata))

	names := make([]string, 0, len(byType))
	for name := range byType {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	b.WriteString("# Metadata key census: the widest finding of each type, over the real validator set.\n")
	b.WriteString("# Regenerate with UPDATE_GOLDEN=1. A changed count is a per-finding memory change:\n")
	b.WriteString("# see the band boundaries logged by TestMetadataKeyCensusOverTheRealValidatorSet and #621.\n")
	b.WriteString("# Counts and key names only -- no byte figures, which are allocator-dependent.\n")
	for _, name := range names {
		c := byType[name]
		fmt.Fprintf(&b, "%s\tkeys=%d\tband=%d\n", name, c.widest, bandOf(c.widest))
		for _, k := range c.keys {
			fmt.Fprintf(&b, "\t%s\n", k)
		}
	}
	b.WriteString("# histogram of key counts across all findings carrying metadata\n")
	counts := make([]int, 0, len(hist))
	for n := range hist {
		counts = append(counts, n)
	}
	sort.Ints(counts)
	for _, n := range counts {
		fmt.Fprintf(&b, "# %d keys: %d findings (band %d)\n", n, hist[n], bandOf(n))
	}

	checkGolden(t, "metadata-key-census.txt", b.String())
}
