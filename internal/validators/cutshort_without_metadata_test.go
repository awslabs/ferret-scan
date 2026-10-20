// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"bytes"
	stdctx "context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// These tests pin #771: a cut-short on a metadata-capable file scanned WITHOUT METADATA lost every
// finding and the disclosure, at exit 0. The router gives such a file a metadata item, the
// metadata path failed for want of a validator, a cut-short made the document path fail too, and
// the both-paths-failed branch returned nil with the cut-short formatted away by %v.
//
// processed() in execguard_e2e_test.go is plaintext only, and plaintext routes no metadata item,
// so every cut-short test in this package ran down the one shape that never reached the defect.
// officeProcessed is the shape that does.

// officeProcessed is what the office preprocessor hands the bridge for a .docx: nMetadata declared
// metadata sections, then a body section.
func officeProcessed(nMetadata int) *preprocessors.ProcessedContent {
	pc := &preprocessors.ProcessedContent{
		Text:          "DocumentType: Word Document\n\nbody text",
		OriginalPath:  "report.docx",
		Filename:      "report.docx",
		ProcessorType: "office",
		Success:       true,
	}
	for i := 0; i < nMetadata; i++ {
		pc.Sections = append(pc.Sections, preprocessors.ContentSection{
			Name:       "office_metadata",
			Kind:       preprocessors.SectionKindMetadata,
			Text:       fmt.Sprintf("DocumentType: Word Document %d", i),
			SourceFile: "report.docx",
		})
	}
	pc.Sections = append(pc.Sections, preprocessors.ContentSection{Name: "body", Text: "body text", SourceFile: "report.docx"})
	return pc
}

// cutShortSentinels returns the errors execguard.IsCoverageCutShort tests for, read out of the
// predicate's SOURCE rather than listed here. A list in this file would be a second enumeration of
// the family, which is the drift IsCoverageCutShort exists to end (its doc comment counts four);
// deriving it means a sentinel added to the predicate lands in the table below on its own, and the
// table fails until it can produce that sentinel.
func cutShortSentinels(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "execguard", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no execguard sources found (err=%v)", err)
	}
	fset := token.NewFileSet()
	var found bool
	var out []string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "IsCoverageCutShort" {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 2 {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Is" {
					if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "errors" {
						out = append(out, types.ExprString(call.Args[1]))
					}
				}
				return true
			})
		}
	}
	if !found || len(out) == 0 {
		t.Fatalf("could not read the sentinels out of execguard.IsCoverageCutShort (found func: %v, "+
			"errors.Is calls: %d). The table below is derived from that function; if it moved or "+
			"stopped using errors.Is, update cutShortSentinels rather than hardcoding a list.", found, len(out))
	}
	sort.Strings(out)
	return out
}

// errDocValidator returns err, with no matches, for every input.
type errDocValidator struct{ err error }

func (errDocValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (errDocValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (errDocValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (v errDocValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, v.err
}

// cutShortProducer is a document validator "X" whose dispatch ends in one sentinel, plus the
// budgets that make it fire.
type cutShortProducer struct {
	sentinel error
	x        detector.Validator
	budgets  map[string]execguard.ValidatorBudget
}

// cutShortProducers maps each sentinel, spelled as IsCoverageCutShort spells it, to a way of
// producing it. Where the engine has a real mechanism the producer uses it (a per-validator time
// budget, a match cap, a panic); a validator that declines its input returns the sentinel itself,
// which is what cloudresources does.
var cutShortProducers = map[string]cutShortProducer{
	"context.DeadlineExceeded": {stdctx.DeadlineExceeded, budgetBlockValidator{},
		map[string]execguard.ValidatorBudget{"X": {TimeLimit: 20 * time.Millisecond}}},
	"context.Canceled": {stdctx.Canceled, errDocValidator{err: stdctx.Canceled}, nil},
	"ErrMatchBudgetExceeded": {execguard.ErrMatchBudgetExceeded, nMatchDocValidator{n: 50},
		map[string]execguard.ValidatorBudget{"X": {MatchLimit: 5}}},
	"ErrContentTooLarge": {execguard.ErrContentTooLarge,
		errDocValidator{err: fmt.Errorf("%w: test fixture", execguard.ErrContentTooLarge)}, nil},
	"ErrValidatorPanicked": {execguard.ErrValidatorPanicked, panicDocValidator{}, nil},
}

// metaItemStub stands in for the METADATA validator: one METATYPE match per item, a call counter,
// and optionally a sleep on the first call or a panic.
type metaItemStub struct {
	calls      *atomic.Int32
	firstSleep time.Duration
	panics     bool
	err        error
	emit       int // matches per item; 0 means 1
}

func (metaItemStub) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (metaItemStub) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (metaItemStub) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (m metaItemStub) ValidateContent(content, path string) ([]detector.Match, error) {
	n := int32(1)
	if m.calls != nil {
		n = m.calls.Add(1)
	}
	if m.panics {
		panic("boom in metadata validator")
	}
	if m.err != nil {
		return nil, m.err
	}
	if n == 1 && m.firstSleep > 0 {
		time.Sleep(m.firstSleep)
	}
	emit := m.emit
	if emit <= 0 {
		emit = 1
	}
	out := make([]detector.Match, 0, emit)
	for i := 0; i < emit; i++ {
		out = append(out, detector.Match{Type: "METATYPE", Text: content, Validator: "metadata", Filename: path})
	}
	return out, nil
}

func countType(matches []detector.Match, typ string) int {
	n := 0
	for _, m := range matches {
		if m.Type == typ {
			n++
		}
	}
	return n
}

// TestCutShortKeepsFindingsWithOrWithoutMetadata is the issue's table: every cut-short sentinel,
// with METADATA selected and not, on a plaintext file and on a .docx. In every cell the healthy
// validator's finding must survive and the cut-short must be returned so the file is reported
// incomplete. Before the fix the four .docx-without-METADATA cells per sentinel returned no
// findings and a nil error, the only cells of the table that did.
func TestCutShortKeepsFindingsWithOrWithoutMetadata(t *testing.T) {
	sentinels := cutShortSentinels(t)
	for _, s := range sentinels {
		if _, ok := cutShortProducers[s]; !ok {
			t.Errorf("execguard.IsCoverageCutShort tests %s, which this table has no producer for. "+
				"Add one to cutShortProducers: a new member of the family is exactly what this "+
				"table exists to cover on a metadata-capable file.", s)
		}
	}
	for name := range cutShortProducers {
		if !containsString(sentinels, name) {
			t.Errorf("cutShortProducers has %s, which execguard.IsCoverageCutShort no longer tests; "+
				"remove the producer so the table stays derived from the predicate", name)
		}
	}

	contents := []struct {
		name string
		pc   func() *preprocessors.ProcessedContent
	}{
		{"plaintext", func() *preprocessors.ProcessedContent { return processed("content") }},
		{"report.docx", func() *preprocessors.ProcessedContent { return officeProcessed(1) }},
	}
	for _, s := range sentinels {
		p, ok := cutShortProducers[s]
		if !ok {
			continue
		}
		for _, metadata := range []bool{false, true} {
			for _, c := range contents {
				label := fmt.Sprintf("%s/METADATA=%v/%s", s, metadata, c.name)
				t.Run(label, func(t *testing.T) {
					validators := map[string]detector.Validator{"X": p.x, "OK": &okDocValidator{}}
					if metadata {
						validators["METADATA"] = metaItemStub{}
					}
					ctx := execguard.WithBudgets(stdctx.Background(), p.budgets)
					matches, err := buildWrapper(t, validators).ValidateProcessedContentCtx(ctx, c.pc())

					if got := countType(matches, "OKTYPE"); got != 1 {
						t.Errorf("the healthy validator's finding count is %d, want 1 (err=%v): a cut-short "+
							"in one validator discarded another validator's finding", got, err)
					}
					if !execguard.IsCoverageCutShort(err) {
						t.Errorf("IsCoverageCutShort(%v) = false: the cut-short was not returned, so the "+
							"file is reported fully examined (exit 0 under --fail-on-incomplete)", err)
					}
					if !errors.Is(err, p.sentinel) {
						t.Errorf("errors.Is(err, %v) = false for %v", p.sentinel, err)
					}
				})
			}
		}
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// lockedBuffer is a bytes.Buffer safe for concurrent writers.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestUnselectedMetadataIsANoOp pins Resolution item 1 at both of its sites: the metadata bridge
// with no validator returns (nil, nil) like a document bridge with no validators, and the dual
// path does not run the metadata goroutine at all, so a document-path cut-short on a .docx is a
// single-path failure: no metadata_path_error, no dual_path_fallback, no legacy re-run.
func TestUnselectedMetadataIsANoOp(t *testing.T) {
	t.Run("bridge", func(t *testing.T) {
		matches, err := NewMetadataValidatorBridge().ProcessMetadataContentCtx(stdctx.Background(),
			nil, context.ContextInsights{})
		if err != nil || matches != nil {
			t.Fatalf("ProcessMetadataContentCtx with no validator = (%v, %v), want (nil, nil): METADATA "+
				"not being selected is not a failure", matches, err)
		}
	})

	t.Run("dual path", func(t *testing.T) {
		// The observer is written from every validator goroutine, so the log needs a writer that
		// is safe for concurrent use; the CLI's is os.Stderr.
		var log lockedBuffer
		debugObs := observability.NewDebugObserver(&log)
		observer := debugObs.StandardObserver
		observer.DebugObserver = debugObs
		d := NewDetector(observer)
		if err := d.SetupValidators(map[string]detector.Validator{"X": panicDocValidator{}, "OK": &okDocValidator{}}); err != nil {
			t.Fatal(err)
		}

		matches, err := d.ValidateProcessedContentCtx(stdctx.Background(), officeProcessed(1))
		if got := countType(matches, "OKTYPE"); got != 1 || !errors.Is(err, execguard.ErrValidatorPanicked) {
			t.Errorf("got %d OKTYPE, err=%v; want 1 and ErrValidatorPanicked", got, err)
		}
		for _, rec := range []string{"metadata_path_error", "dual_path_fallback", "Using legacy content aggregation", "legacy_document_error"} {
			if strings.Contains(log.String(), rec) {
				t.Errorf("--debug shows %q for a .docx scanned without METADATA. An unselected check must "+
					"not fail, and a cut-short must not send the file through the legacy re-run.", rec)
			}
		}
	})

	t.Run("no cut-short is unchanged", func(t *testing.T) {
		matches, err := buildWrapper(t, map[string]detector.Validator{"OK": &okDocValidator{}}).
			ValidateProcessedContentCtx(stdctx.Background(), officeProcessed(2))
		if err != nil || len(matches) != 1 || matches[0].Type != "OKTYPE" {
			t.Fatalf("a .docx with no cut-short returned (%v, %v), want one OKTYPE match and nil", matches, err)
		}
	})
}

// TestMetadataPanicIsDisclosed: with METADATA selected, a panic in the metadata validator was
// recovered, logged and dropped, so the file reported a complete scan (#771 root cause 4). It must
// reach the incomplete-coverage channel, keep the document path's finding, and name the check.
func TestMetadataPanicIsDisclosed(t *testing.T) {
	matches, err := buildWrapper(t, map[string]detector.Validator{
		"OK":       &okDocValidator{},
		"METADATA": metaItemStub{panics: true},
	}).ValidateProcessedContentCtx(stdctx.Background(), officeProcessed(1))

	if got := countType(matches, "OKTYPE"); got != 1 {
		t.Errorf("document finding count %d, want 1", got)
	}
	if !errors.Is(err, execguard.ErrValidatorPanicked) {
		t.Fatalf("err = %v, want ErrValidatorPanicked: the METADATA validator abandoned the file's "+
			"metadata and the scan reported it complete", err)
	}
	if !strings.Contains(err.Error(), `"METADATA"`) {
		t.Errorf("err = %q, want it to name the check METADATA (the dispatch name), not the Go type", err)
	}
}

// TestParentDeadlineMidMetadataKeepsPartials: the scan's own deadline fires while the document path
// is stalled. If the metadata path has finished, only one path failed and that already worked. If
// the metadata path is still on an item, both paths fail, and the both-failed branch returned nil
// and an error errors.Is could not see through, dropping the document path's finding.
func TestParentDeadlineMidMetadataKeepsPartials(t *testing.T) {
	for _, sleep := range []time.Duration{0, 300 * time.Millisecond} {
		t.Run("metadata item sleep "+sleep.String(), func(t *testing.T) {
			stall := &stallingDocValidator{release: make(chan struct{}), started: make(chan struct{}, 1)}
			defer close(stall.release)
			w := buildWrapper(t, map[string]detector.Validator{
				"STALL":    stall,
				"OK":       &okDocValidator{},
				"METADATA": metaItemStub{firstSleep: sleep},
			})
			ctx, cancel := stdctx.WithTimeout(stdctx.Background(), 150*time.Millisecond)
			defer cancel()

			matches, err := w.ValidateProcessedContentCtx(ctx, officeProcessed(2))
			if got := countType(matches, "OKTYPE"); got != 1 {
				t.Errorf("document finding count %d, want 1 (err=%v): the deadline dropped a finding a "+
					"validator had already returned", got, err)
			}
			if !errors.Is(err, stdctx.DeadlineExceeded) {
				t.Errorf("errors.Is(err, context.DeadlineExceeded) = false for %v", err)
			}
		})
	}
}

// TestMetadataBudgetIsHonoured: --validator-budget METADATA=<d> was accepted and did nothing,
// because budgets were looked up only in execguard.ValidateContent and the metadata loop dispatched
// through SafeRun under the Go type name (#771 root cause 5). Its time budget is one deadline for
// the loop, checked before each item; its match budget caps the union of items.
func TestMetadataBudgetIsHonoured(t *testing.T) {
	scan := func(t *testing.T, stub metaItemStub, items int, budget execguard.ValidatorBudget) ([]detector.Match, error) {
		t.Helper()
		ctx := execguard.WithBudgets(stdctx.Background(), map[string]execguard.ValidatorBudget{"METADATA": budget})
		return buildWrapper(t, map[string]detector.Validator{"OK": &okDocValidator{}, "METADATA": stub}).
			ValidateProcessedContentCtx(ctx, officeProcessed(items))
	}

	// No subtest here relies on a 1ns budget being expired at the first check. That
	// holds on a nanosecond clock (Linux, macOS) and not on Windows, whose clock ticks
	// at 0.5-15.6 ms: context.WithTimeout then arms a timer instead of cancelling, and
	// a stub item finishes before it fires. The budget/sleep pairs below leave two
	// orders of magnitude between the budget and the work on every platform.

	t.Run("fires during the last item: the item finishes, its finding is kept, the overrun is reported", func(t *testing.T) {
		var calls atomic.Int32
		matches, err := scan(t, metaItemStub{calls: &calls, firstSleep: 400 * time.Millisecond}, 1,
			execguard.ValidatorBudget{TimeLimit: 50 * time.Millisecond})
		if !errors.Is(err, stdctx.DeadlineExceeded) {
			t.Errorf("err = %v, want DeadlineExceeded: a budget the only item overran has no next item to "+
				"stop, so it must be reported after the loop or METADATA=<d> is silently ignored on every "+
				"single-item file", err)
		}
		if n := calls.Load(); n != 1 {
			t.Errorf("metadata validator ran %d times, want 1", n)
		}
		if got := countType(matches, "METATYPE"); got != 1 {
			t.Errorf("metadata finding count %d, want 1: the overrun discloses, it does not discard", got)
		}
		if got := countType(matches, "OKTYPE"); got != 1 {
			t.Errorf("document finding count %d, want 1", got)
		}
	})

	t.Run("fires during an item: that item finishes, the next does not start", func(t *testing.T) {
		var calls atomic.Int32
		matches, err := scan(t, metaItemStub{calls: &calls, firstSleep: 400 * time.Millisecond}, 3,
			execguard.ValidatorBudget{TimeLimit: 100 * time.Millisecond})
		if !errors.Is(err, stdctx.DeadlineExceeded) {
			t.Errorf("err = %v, want DeadlineExceeded", err)
		}
		if n := calls.Load(); n != 1 {
			t.Errorf("metadata validator ran %d times, want 1: the budget is checked between items, so "+
				"the item in flight finishes and no later item starts", n)
		}
		if got := countType(matches, "METATYPE"); got != 1 {
			t.Errorf("metadata finding count %d, want 1: the item that finished keeps its finding", got)
		}
	})

	t.Run("match budget caps the union of items", func(t *testing.T) {
		matches, err := scan(t, metaItemStub{}, 3, execguard.ValidatorBudget{MatchLimit: 1})
		if !errors.Is(err, execguard.ErrMatchBudgetExceeded) {
			t.Errorf("err = %v, want ErrMatchBudgetExceeded", err)
		}
		if got := countType(matches, "METATYPE"); got != 1 {
			t.Errorf("metadata finding count %d, want 1 (MatchLimit)", got)
		}
	})

	t.Run("a generous budget changes nothing", func(t *testing.T) {
		matches, err := scan(t, metaItemStub{}, 3, execguard.ValidatorBudget{TimeLimit: time.Hour, MatchLimit: 100})
		if err != nil || countType(matches, "METATYPE") != 3 || countType(matches, "OKTYPE") != 1 {
			t.Errorf("got %d METATYPE, %d OKTYPE, err=%v; want 3, 1, nil",
				countType(matches, "METATYPE"), countType(matches, "OKTYPE"), err)
		}
	})
}

// TestLegacyFallbackKeepsCutShortPartials: the legacy aggregation is still reachable (a routing
// failure falls back to it). It dropped the document path's matches on any error and returned nil
// unconditionally, so a fallback run that was itself cut short reported a complete scan.
func TestLegacyFallbackKeepsCutShortPartials(t *testing.T) {
	legacy := func(t *testing.T, validators map[string]detector.Validator, ctx stdctx.Context,
		pc *preprocessors.ProcessedContent) ([]detector.Match, error) {
		t.Helper()
		return buildWrapper(t, validators).bridge.processContentLegacy(ctx, pc, context.ContextInsights{})
	}
	bg := stdctx.Background()

	t.Run("document path cut short", func(t *testing.T) {
		matches, err := legacy(t, map[string]detector.Validator{"X": panicDocValidator{}, "OK": &okDocValidator{}},
			bg, officeProcessed(1))
		if got := countType(matches, "OKTYPE"); got != 1 {
			t.Errorf("document finding count %d, want 1", got)
		}
		if !errors.Is(err, execguard.ErrValidatorPanicked) {
			t.Errorf("err = %v, want ErrValidatorPanicked", err)
		}
	})

	t.Run("metadata unit panics", func(t *testing.T) {
		matches, err := legacy(t, map[string]detector.Validator{"OK": &okDocValidator{}, "METADATA": metaItemStub{panics: true}},
			bg, officeProcessed(1))
		if got := countType(matches, "OKTYPE"); got != 1 {
			t.Errorf("document finding count %d, want 1", got)
		}
		if !errors.Is(err, execguard.ErrValidatorPanicked) || !strings.Contains(err.Error(), `"METADATA"`) {
			t.Errorf("err = %v, want ErrValidatorPanicked naming METADATA", err)
		}
	})

	t.Run("METADATA budget reaches the legacy dispatch", func(t *testing.T) {
		// A match budget rather than a time budget: it needs no clock, so it proves the
		// lookup name on every platform (a 1ns budget is not reliably expired on Windows).
		ctx := execguard.WithBudgets(bg, map[string]execguard.ValidatorBudget{"METADATA": {MatchLimit: 1}})
		matches, err := legacy(t, map[string]detector.Validator{"OK": &okDocValidator{}, "METADATA": metaItemStub{emit: 2}},
			ctx, officeProcessed(1))
		if !errors.Is(err, execguard.ErrMatchBudgetExceeded) {
			t.Errorf("err = %v, want ErrMatchBudgetExceeded: the legacy metadata dispatch must look the budget "+
				"up under METADATA", err)
		}
		// officeProcessed(1) has two non-empty sections, so the legacy path dispatches two
		// units; ValidateContent caps each at MatchLimit and keeps the capped slice.
		if got := countType(matches, "METATYPE"); got != 2 {
			t.Errorf("metadata finding count %d, want 2 (one per unit): a capped unit keeps what it returned", got)
		}
	})

	t.Run("an ordinary error stays log-only", func(t *testing.T) {
		matches, err := legacy(t, map[string]detector.Validator{
			"OK":       &okDocValidator{},
			"METADATA": metaItemStub{err: errors.New("ordinary validator error")},
		}, bg, officeProcessed(1))
		if err != nil || countType(matches, "OKTYPE") != 1 {
			t.Errorf("got (%d OKTYPE, %v), want (1, nil): an ordinary error does not make the result "+
				"partial, and returning it would make the caller drop every finding", countType(matches, "OKTYPE"), err)
		}
	})
}
