// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// #467 asked for "a regression guard measuring RSS (or live heap) against finding count, with a
// findings floor so it cannot pass on an empty scan". This is it, and writing it first was
// deliberate: the issue lists four candidate fixes and none of them is verifiable without a number
// to move.
//
// WHAT THE MEASUREMENT SAYS, AND WHERE IT CORRECTS THE ISSUE.
//
// #467 reports "~4.4-5.1 KB per finding" of RETENTION and treats that as what drives peak RSS.
// Measured end to end at HEAD -- a heap profile taken inside cmd/main.go at the point where
// allMatches is fully populated, findings-dense fixture, --checks email --confidence all --limit 0:
//
//	findings   peak RSS    live heap at the retention point   TOTAL allocated
//	 4,000      71 MB       3,765 B/finding                   24,725 B/finding
//	16,000     207 MB       2,111 B/finding                   24,842 B/finding
//	32,000     367 MB       2,056 B/finding                   24,772 B/finding
//
// Retention is ~2.1 KB per finding, not 4.4-5.1 KB. The term that actually sets peak RSS is CHURN:
// a near-constant 24.8 KB ALLOCATED per finding, twelve times what stays live. At 32,000 findings
// the runtime held HeapSys=389 MB with HeapIdle=320 MB -- 82% of the heap was idle spans the
// collector had not returned to the OS. So a fix aimed only at retention can remove at most a
// twelfth of the peak. That is worth knowing before choosing between #467's four directions, and it
// is why this guard measures live heap per LAYER rather than one end-to-end RSS number: RSS is
// dominated by a term none of the four directions touch.
//
// Per-layer retention, through this bridge, three runs each, spread under 2%:
//
//	the findings themselves (this bridge)         634 - 669 B/finding
//	the formatter's confidence-filtered copy      275 -  294 B/finding   <- #467 contributor 1
//	the JSON representation built on top of it    496 -  502 B/finding
//
// So #467's "second full struct copy" is 278 B/finding: 13% of end-to-end retention and 2.8% of
// peak RSS. Real, but a twentieth of what the issue's headline implies, and the JSON representation
// beside it is 1.8x LARGER. Both are live at once, alongside the originals -- four representations,
// not two.
//
// WHY RSS IS NOT THE ASSERTION. Peak RSS on this workload is a function of GOGC, of how promptly
// the runtime returns spans, and of the OS. Live heap after an explicit GC reproduced to within 2%
// across runs here, and the repo has already been burned twice by wall-clock and RSS ceilings that
// flaked on a runner nobody had measured (#509, #546). A deterministic statistic that covers the
// layers is worth more than a noisy one that covers the total.

// WHAT MUTATIONS THIS CATCHES. Five, each verified to be a real assertion failure rather than a
// build error -- the first attempt at two of them read as CAUGHT when they had simply failed to
// compile:
//
//	a 1KB document-level value added to every finding's metadata    bridge budget, 2007 B/f
//	the filter copy carrying its own 512-byte string                filter budget, 938 B/f
//	ContextInsights emptied of semantic categories                  the no-context branch check
//	a metadata value whose length scales with the finding count      bridge budget
//	a Text that grows with the finding count, staying UNDER budget   the GROWTH check, 1.61x
//
// The last one exists because the other four all tripped a BUDGET, which would have left the growth
// check unexercised decoration. Calibrated so both sizes stay under 1200 B/f (695 and 1118) and only
// the ratio fires -- an assertion arm no mutation can reach is not a guard.

// retentionProbeValidator emits one finding per line carrying an '@', shaped the way a real
// validator's findings are: a value lifted from the line, a context window, and a metadata map.
//
// A synthetic validator rather than the real email one so the budgets below measure the RETENTION
// mechanism and not that validator's own vocabulary, which changes for unrelated reasons.
type retentionProbeValidator struct{}

func (retentionProbeValidator) ValidateContent(content, path string) ([]detector.Match, error) {
	var out []detector.Match
	off, line := 0, 1
	for {
		nl := strings.IndexByte(content[off:], '\n')
		if nl < 0 {
			break
		}
		text := content[off : off+nl]
		if at := strings.IndexByte(text, '@'); at >= 0 {
			start, end := at-5, at+20
			if start < 0 {
				start = 0
			}
			if end > len(text) {
				end = len(text)
			}
			out = append(out, detector.Match{
				Text:       text[start:end],
				Type:       "EMAIL",
				Confidence: 90,
				LineNumber: line,
				Filename:   path,
				Validator:  "retention-probe",
				Context:    detector.LineContext(text, start, end),
				Metadata:   map[string]any{"validation_checks": []string{"syntax", "tld"}},
			})
		}
		off += nl + 1
		line++
	}
	return out, nil
}

func (retentionProbeValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 90, nil
}

func (retentionProbeValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }

// Budgets, in bytes of live heap per finding. Each sits roughly 1.8x-2x above the measured value:
// loose enough not to flake on a platform whose allocator rounds differently, tight enough that
// adding one more document-level value to every finding's metadata trips it.
//
// Deliberately THREE budgets rather than one total. A single number goes vacuous the moment one
// layer shrinks and another grows by the same amount, and these three layers are changed by
// different people for different reasons.
const (
	bridgeRetentionBudget    = 1200 // vs 634-669 measured
	filterCopyBudget         = 600  // vs 275-294 measured
	jsonRepresentationBudget = 1000 // vs 496-502 measured
)

// retentionFindingsFloor is #467's "findings floor so it cannot pass on an empty scan". Every
// assertion here divides by the finding count, so a scan that produced nothing would divide by zero
// or, worse, produce a tiny quotient and pass.
const retentionFindingsFloor = 1000

func TestFindingRetentionPerFindingStaysBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("retention guard allocates ~2MB of fixture and runs the document bridge; skipped in -short")
	}

	// Two sizes, 16x apart, because the question is not only "how big" but "does the per-finding
	// cost GROW" -- retention that is superlinear in finding count is the failure #337 originally
	// reported and a single size cannot see it.
	small := measureRetention(t, 2000)
	large := measureRetention(t, 32000)

	for _, m := range []retentionMeasurement{small, large} {
		if m.findings < retentionFindingsFloor {
			t.Fatalf("%d findings is under the %d floor: the measurement below would be dividing by "+
				"a count too small to mean anything, and the budgets would pass on a broken probe",
				m.findings, retentionFindingsFloor)
		}
		// The bridge only writes its document-level metadata when insights carry semantic
		// categories. If that ever empties, the cheap branch runs, every budget below drops, and
		// the guard passes while measuring code #467 is not about. Asserted, not merely logged.
		if m.semanticCategories == 0 {
			t.Fatalf("ContextInsights carried no semantic categories, so the bridge took its "+
				"no-context branch and never wrote the per-finding document metadata this guard "+
				"exists to bound (%d findings)", m.findings)
		}
		t.Logf("%6d findings: bridge=%4.0f B/f  filter copy=%4.0f B/f  json=%4.0f B/f  "+
			"(churn %5.0f B/f, %d semantic categories)",
			m.findings, m.bridgePerFinding, m.filterPerFinding, m.jsonPerFinding,
			m.churnPerFinding, m.semanticCategories)

		if m.bridgePerFinding > bridgeRetentionBudget {
			t.Errorf("%d findings retain %.0f B each through the document bridge, over the %d B "+
				"budget. Something now holds a per-finding copy of something document-level — the "+
				"metadata written at dual_path_bridge.go's context block is the usual cause, and "+
				"four of those values (context_domain, context_doctype, context_confidence, "+
				"semantic_context) are identical for every finding in a file. See #467.",
				m.findings, m.bridgePerFinding, bridgeRetentionBudget)
		}
		if m.filterPerFinding > filterCopyBudget {
			t.Errorf("the confidence-filtered copy costs %.0f B per finding, over the %d B budget. "+
				"FilterMatchesByConfidence builds a second slice and both are live at once (#467 "+
				"contributor 1); if this grew, it is now copying more than the struct header.",
				m.filterPerFinding, filterCopyBudget)
		}
		if m.jsonPerFinding > jsonRepresentationBudget {
			t.Errorf("the JSON representation costs %.0f B per finding, over the %d B budget. This "+
				"is a THIRD live representation beside the originals and the filtered copy.",
				m.jsonPerFinding, jsonRepresentationBudget)
		}
	}

	// The growth check. Measured 634 -> 669 B/finding across a 16x step, so 1.06x; 1.5x leaves room
	// for allocator rounding at different sizes without admitting a genuine superlinearity.
	const maxPerFindingGrowth = 1.5
	if got := large.bridgePerFinding / small.bridgePerFinding; got > maxPerFindingGrowth {
		t.Errorf("per-finding retention GREW %.2fx over a 16x step in finding count (%.0f B/f at "+
			"%d findings, %.0f B/f at %d) — retention is superlinear in finding count, which is the "+
			"shape #337 reported. A per-finding budget alone cannot see this.",
			got, small.bridgePerFinding, small.findings, large.bridgePerFinding, large.findings)
	}
}

type retentionMeasurement struct {
	findings                                                            int
	bridgePerFinding, filterPerFinding, jsonPerFinding, churnPerFinding float64
	semanticCategories                                                  int
}

// measureRetention runs the document bridge over a findings-dense fixture and reports live heap per
// finding at each layer, holding every representation alive across the reads.
func measureRetention(t *testing.T, lines int) retentionMeasurement {
	t.Helper()

	var sb strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&sb, "contact user%d@example%d.com for account %d in the billing department\n", i, i%97, i)
	}
	content := sb.String()

	bridge := NewDocumentValidatorBridge()
	bridge.RegisterValidator("retention-probe", retentionProbeValidator{})

	// The insights matter: the bridge only writes its document-level metadata when it HAS context,
	// so a zero-value ContextInsights would measure the cheap branch and the budgets would be
	// meaningless. semanticCategories is reported so a future change that empties it is visible.
	insights := context.NewContextAnalyzer().AnalyzeContext(content, "retention-probe.txt")

	var before, afterCall, afterGC runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	matches, err := bridge.ProcessDocumentContentCtx(stdctx.Background(), content, "retention-probe.txt", insights)
	if err != nil {
		t.Fatalf("bridge returned %v", err)
	}
	runtime.ReadMemStats(&afterCall)
	runtime.GC()
	runtime.ReadMemStats(&afterGC)

	if len(matches) == 0 {
		t.Fatalf("the probe produced no findings from %d lines: every quotient below would be "+
			"undefined", lines)
	}
	n := float64(len(matches))

	options := formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	}

	var beforeFilter, afterFilter, afterJSON runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&beforeFilter)
	filtered := shared.FilterMatchesByConfidence(matches, options)
	runtime.GC()
	runtime.ReadMemStats(&afterFilter)
	jsonRep := shared.ConvertMatchesToJSONFormat(filtered, nil, options)
	runtime.GC()
	runtime.ReadMemStats(&afterJSON)

	if len(filtered) != len(matches) {
		t.Fatalf("the confidence filter dropped %d of %d findings, so the filter-copy budget is "+
			"being charged for a smaller set than it is divided by",
			len(matches)-len(filtered), len(matches))
	}
	if len(jsonRep.Results) == 0 {
		t.Fatalf("the JSON representation is empty: its budget would pass on nothing")
	}

	m := retentionMeasurement{
		findings:           len(matches),
		bridgePerFinding:   float64(afterGC.HeapAlloc-before.HeapAlloc) / n,
		filterPerFinding:   float64(afterFilter.HeapAlloc-beforeFilter.HeapAlloc) / n,
		jsonPerFinding:     float64(afterJSON.HeapAlloc-afterFilter.HeapAlloc) / n,
		churnPerFinding:    float64(afterCall.TotalAlloc-before.TotalAlloc) / n,
		semanticCategories: len(insights.SemanticContext),
	}

	// Everything must still be reachable, or the GC above would have collected what is being
	// measured and every number would read near zero.
	runtime.KeepAlive(matches)
	runtime.KeepAlive(filtered)
	runtime.KeepAlive(jsonRep)
	return m
}
