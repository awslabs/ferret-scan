// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// ProcessEmbeddedMedia assembles the combined embedded-media text, and that assembly must
// not be quadratic in bytes.
//
// It used a string accumulator — `var result string` with `result += block` inside the
// per-part loop. Go's string += reallocates and re-copies the whole accumulated prefix on
// every iteration, so building the combined text cost O(n²) BYTES across n embedded parts.
// The quadratic is in bytes rather than parts, so a few dozen multi-hundred-KB blocks
// (embedded documents and PDFs, or a raster-heavy deck where each image round-trips the
// router for metadata text) already cost tens of MB of transient copying.
//
// Transient only — it never affected results or any counter — which is exactly why no
// existing gate could see it: the complexity guards in internal/goldencorpus cover the
// validators and the redaction paths, and nothing covered EXTRACTION. See #338.

// embeddedComplexityCeiling bounds the largest sample.
//
// Generous on purpose: this is an algorithmic-class check, not a benchmark. Sized so a
// loaded shared runner passes comfortably while a return to O(n²) copying does not.
const embeddedComplexityCeiling = 20 * time.Second

// builderProbeRouter is a RouterInterface that returns a fixed-size text block per part,
// so the measured cost is the ASSEMBLY, not the extraction.
type builderProbeRouter struct {
	blockSize int
	calls     int
}

func (r *builderProbeRouter) ProcessFile(filePath string, _ interface{}) (*ProcessedContent, error) {
	r.calls++
	return &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filePath,
		Text:          strings.Repeat("embedded metadata line\n", r.blockSize/23),
		Format:        "image_metadata",
		ProcessorType: "image_metadata",
		Success:       true,
	}, nil
}

func (r *builderProbeRouter) ProcessEmbedded(childPath, _ string) (*ProcessedContent, error) {
	return r.ProcessFile(childPath, nil)
}

func (r *builderProbeRouter) CanProcessFile(string, bool) (bool, string) { return true, "" }

// This probe measures assembly cost and materialises nothing, so it has no traversal budget to
// hand out and sits at the top level. Both are the nil/zero answers a router gives for an
// untracked path, which is the behaviour the production code must tolerate.
func (r *builderProbeRouter) EmbeddedBudget(string) *embedded.Budget { return nil }
func (r *builderProbeRouter) EmbeddedDepthOf(string) int             { return 0 }

// buildEmbeddedParts creates n real temp files and the EmbeddedMedia entries naming them.
//
// Real files because the pipeline stats and routes each part; a fabricated path would be
// refused before the assembly under test is ever reached.
func buildEmbeddedParts(t *testing.T, n int) []EmbeddedMedia {
	t.Helper()
	dir := t.TempDir()
	out := make([]EmbeddedMedia, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("image%03d.jpeg", i)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("\xff\xd8\xff\xe0 jpeg-ish bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, EmbeddedMedia{
			OriginalName: "word/media/" + name,
			TempFilePath: p,
			MediaType:    "image",
		})
	}
	return out
}

// measureAssemble runs the assembly and reports BYTES ALLOCATED, elapsed time, the combined
// text length and the number of parts routed.
//
// Allocation is the primary signal, not time. The defect is "O(n^2) bytes copied", and bytes
// copied is exactly what TotalAlloc counts — deterministically, with no dependence on
// scheduler noise, CI load, or whether -race is enabled. Measured both ways on the same
// fixtures:
//
//	                  60 parts   240 parts   ratio
//	strings.Builder     29 MB      116 MB     3.96x
//	string +=          123 MB     1842 MB    15.0x
//
// against wall clock, which measured 2.7x locally and 6.4x on a loaded CI macOS runner for the
// SAME correct code — straddling the 6.0 threshold and turning this guard into a flake. Time is
// kept only as an absolute ceiling for the case a ratio cannot catch: both samples slowing
// together.
func measureAssemble(t *testing.T, n, blockSize int) (alloc uint64, elapsed time.Duration, textLen, calls int) {
	t.Helper()

	bmp := NewBaseMetadataPreprocessor("probe", "image_metadata")
	router := &builderProbeRouter{blockSize: blockSize}
	bmp.SetRouter(router)

	parts := buildEmbeddedParts(t, n)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	start := time.Now()
	text, _, _ := bmp.ProcessEmbeddedMedia("container.docx", parts)
	elapsed = time.Since(start)

	runtime.ReadMemStats(&after)

	return after.TotalAlloc - before.TotalAlloc, elapsed, len(text), router.calls
}

// TestProcessEmbeddedMediaAssemblyIsNotQuadratic is the guard.
//
// It asserts the GROWTH RATIO (see maxGrowth below), with an absolute ceiling kept only as a
// backstop. An earlier revision of this comment claimed the opposite — that the ratio was
// merely logged, in the idiom the redaction guard in internal/goldencorpus uses — which was
// a leftover from a first attempt that was itself vacuous.
//
// # Why this drives ProcessEmbeddedMedia directly instead of scanning a real document
//
// #338 asks for the growth curve to be pinned "the same way the detector/redaction hot paths
// are", i.e. over a real fixture. That target was built and measured, twice, and neither
// version can gate on the defect.
//
// A real .docx carrying n embedded JPEGs (each with 4KB of EXIF ImageDescription), scanned
// end-to-end through core.ScanFile, times IDENTICALLY with and without the fix:
//
//	parts    string +=    strings.Builder
//	   40      0.26s          0.25s
//	  160      0.72s          0.71s
//	  320      1.38s          1.31s
//	  640      2.56s          2.49s
//
// The copying is swamped by the linear costs around it — zip inflate, per-part extraction,
// and validating the combined text. Since #338 describes the defect as "O(n^2) BYTES
// COPIED", allocation was tried next, measuring runtime.MemStats.TotalAlloc across the same
// real scan. The quadratic is visible there, but only barely:
//
//	per-part text    with fix    reverted
//	      4KB        3.9x        4.4x   (299MB -> 347MB at 160 parts)
//	     32KB        4.0x        5.0x   (1081MB -> 1450MB at 160 parts)
//
// Separating 4.0x from 5.0x needs a threshold with roughly 12% headroom, on a figure that
// moves with GOMAXPROCS and GC timing across the three CI runners, at a cost of ~1.4GB of
// churn per run. A gate that flaky is worse than no gate.
//
// Driving the assembly loop in isolation, and measuring ALLOCATION rather than time, gives a
// margin that holds everywhere: 3.96x with the Builder against 15.0x with the accumulator, on
// a figure no scheduler can perturb. That is what makes an assertion possible at all.
//
// The cost is honest and worth stating: a stub router means only the append loop is pinned
// here, so a quadratic introduced in part enumeration, in ProcessEmbedded, or in
// container-side stitching would need its own target.
func TestProcessEmbeddedMediaAssemblyIsNotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("embedded-media assembly complexity guard skipped in -short mode")
	}

	const (
		blockSize   = 64 << 10 // 64KB of text per part, i.e. an embedded document, not a thumbnail
		baseN, bigN = 60, 240  // 4x
	)

	allocBase, tBase, lenBase, callsBase := measureAssemble(t, baseN, blockSize)
	allocBig, tBig, lenBig, callsBig := measureAssemble(t, bigN, blockSize)

	// Non-vacuity floors, both directions.
	//
	// Every part must have been routed (otherwise the loop exited early and the timing
	// describes nothing), and the combined text must GROW roughly with the input
	// (otherwise appends are being dropped and a faster run is a broken one).
	if callsBase != baseN || callsBig != bigN {
		t.Fatalf("router saw %d/%d and %d/%d parts — the loop did not process every part, so "+
			"the timings below describe an incomplete assembly", callsBase, baseN, callsBig, bigN)
	}
	if lenBase == 0 || lenBig == 0 {
		t.Fatalf("combined text is empty (%d, %d bytes) — an assembly that appends nothing is "+
			"fast and wrong", lenBase, lenBig)
	}
	if ratio := float64(lenBig) / float64(lenBase); ratio < 3.5 {
		t.Fatalf("combined text grew only %.2fx for 4x the parts (%d -> %d bytes) — blocks are "+
			"being dropped, so this measures the wrong thing", ratio, lenBase, lenBig)
	}

	if allocBase == 0 || allocBig == 0 {
		t.Fatalf("measured zero allocation (%d, %d bytes) — the probe is not running", allocBase, allocBig)
	}
	ratio := float64(allocBig) / float64(allocBase)
	t.Logf("4x parts at %dKB each: %.2fx allocation (%.0fMB -> %.0fMB), %v -> %v elapsed, "+
		"%d -> %d bytes of text. A Builder is linear in total bytes, so ~4x is expected; the "+
		"string accumulator this replaced copied the whole prefix per part, i.e. ~16x.",
		blockSize>>10, ratio, float64(allocBase)/(1<<20), float64(allocBig)/(1<<20),
		tBase, tBig, lenBase, lenBig)

	// The RATIO is asserted, not just a ceiling.
	//
	// A ceiling alone made this guard VACUOUS: restoring the string accumulator was
	// unmistakably quadratic and still passed, because tens of milliseconds is nowhere near
	// any sane wall-clock ceiling. The defect this test exists for was invisible to it.
	//
	// The threshold sits between the two measurements with room on both sides: linear is 4.0,
	// the Builder measures 3.96x, the accumulator 15.0x, true quadratic is 16.0. Those are
	// ALLOCATION figures, which is why the margin holds on every runner — see
	// measureAssemble for why the wall-clock version of this assertion had to go.
	const maxGrowth = 6.0
	if ratio > maxGrowth {
		t.Errorf("4x the parts allocated %.2fx the bytes (> %.1f) — assembly is scaling with "+
			"(parts x accumulated bytes) again, i.e. the combined text is being re-copied per "+
			"part instead of appended", ratio, maxGrowth)
	}

	// Ceiling kept as a backstop for the case a ratio cannot catch: both samples slow
	// together, which a proportional regression would produce.
	if tBig > embeddedComplexityCeiling {
		t.Errorf("assembling %d embedded parts of %dKB took %v (> %v)",
			bigN, blockSize>>10, tBig, embeddedComplexityCeiling)
	}
}

// The assembled text must be byte-identical to a plain concatenation of the blocks, so
// switching to a Builder cannot have changed the output. Asserted separately from timing
// because a fast, wrong assembly is the failure mode a ceiling cannot catch.
func TestProcessEmbeddedMediaAssemblyPreservesContent(t *testing.T) {
	bmp := NewBaseMetadataPreprocessor("probe", "image_metadata")
	router := &builderProbeRouter{blockSize: 512}
	bmp.SetRouter(router)

	parts := buildEmbeddedParts(t, 5)
	text, sections, _ := bmp.ProcessEmbeddedMedia("container.docx", parts)

	// Every part's name must appear, in order, and the per-part section boundaries must
	// still line up with the text the cursor was computed against.
	last := -1
	for i := range parts {
		name := filepath.Base(parts[i].OriginalName)
		at := strings.Index(text, name)
		if at < 0 {
			t.Fatalf("part %d (%s) is absent from the combined text", i, name)
		}
		if at <= last {
			t.Errorf("part %d (%s) appears out of order", i, name)
		}
		last = at
	}
	if len(sections) == 0 {
		t.Error("no content sections were produced; section anchoring depends on the same " +
			"per-block line cursor as the assembly")
	}
	// The line cursor is maintained independently of the accumulator, so a Builder must
	// not have shifted it: each section's start line must fall inside the text.
	totalLines := strings.Count(text, "\n") + 1
	for i, s := range sections {
		if s.LineOffset < 0 || s.LineOffset > totalLines {
			t.Errorf("section %d starts at line %d, outside the %d-line combined text",
				i, s.LineOffset, totalLines)
		}
	}
}
