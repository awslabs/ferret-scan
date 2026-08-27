// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// budgetProbe records the traversal budget the router hands it for each file it processes.
//
// A probe rather than a direct call to budgetOf, because the whole point of #474 is that the
// budget reaches the code that MATERIALISES bytes — a preprocessor, mid-Process. Asserting on
// the map from outside would pass on a router that stores budgets nobody can reach.
type budgetProbe struct {
	seen map[string]*embedded.Budget
	// depths records what EmbeddedDepthOf reported, so the pre-materialisation guard can be
	// tested on the value it actually branches on.
	depths map[string]int
	router *FileRouter
}

func (p *budgetProbe) CanProcess(string) bool { return true }

func (p *budgetProbe) Process(filePath string) (*preprocessors.ProcessedContent, error) {
	if p.seen == nil {
		p.seen = map[string]*embedded.Budget{}
		p.depths = map[string]int{}
	}
	p.seen[filePath] = p.router.EmbeddedBudget(filePath)
	p.depths[filePath] = p.router.EmbeddedDepthOf(filePath)
	return &preprocessors.ProcessedContent{
		OriginalPath: filePath, Filename: filePath,
		Text: "probe", Format: "text", ProcessorType: "probe", Success: true,
	}, nil
}

func (p *budgetProbe) GetName() string                    { return "budget_probe" }
func (p *budgetProbe) GetSupportedExtensions() []string   { return []string{".probe"} }
func (p *budgetProbe) SetObserver(observability.Observer) {}

func newProbedRouter(t *testing.T) (*FileRouter, *budgetProbe) {
	t.Helper()
	fr := NewFileRouter(false)
	probe := &budgetProbe{router: fr}
	fr.RegisterPreprocessor("budget_probe", func(map[string]interface{}) preprocessors.Preprocessor {
		return probe
	})
	fr.InitializePreprocessors(map[string]interface{}{})
	return fr, probe
}

func writeProbeFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("probe content"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestTopLevelFileGetsABudgetAndReleasesIt is the lifecycle half of #474.
//
// The budget has to exist WHILE the file is processed — that is when bytes are materialised — and
// be gone afterwards. A budget that outlived its file would make the SECOND file in a directory
// scan inherit an exhausted allowance and report clean, turning a resource fix into a silent
// detection loss, which is strictly worse than the bug being fixed.
func TestTopLevelFileGetsABudgetAndReleasesIt(t *testing.T) {
	fr, probe := newProbedRouter(t)
	path := writeProbeFile(t, "top.probe")

	if _, err := fr.ProcessFile(path, nil); err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	during, ok := probe.seen[path]
	if !ok {
		t.Fatal("the probe never ran, so this test measures nothing")
	}
	if during == nil {
		t.Fatal("a top-level file was processed with NO traversal budget; every embedded part it " +
			"materialises would then draw an unbounded fresh allowance (#474)")
	}
	if during.Remaining() != embedded.BudgetBytes {
		t.Errorf("a fresh traversal budget has %d bytes remaining, want the full %d",
			during.Remaining(), embedded.BudgetBytes)
	}

	if fr.hasBudgetEntry(path) {
		t.Error("the budget survived the file that owned it; the next file to be scanned would " +
			"inherit whatever this one spent")
	}
}

// TestSecondFileStartsWithAFullBudget is the consequence the release exists for, asserted on
// behaviour rather than on the map.
//
// Two files scanned in sequence must each get their own full allowance. This is the assertion that
// would fail if the budget were a package-level counter — the design the fix deliberately avoids,
// because a shared counter also makes coverage depend on worker interleaving.
func TestSecondFileStartsWithAFullBudget(t *testing.T) {
	fr, probe := newProbedRouter(t)
	first := writeProbeFile(t, "first.probe")
	second := writeProbeFile(t, "second.probe")

	if _, err := fr.ProcessFile(first, nil); err != nil {
		t.Fatalf("ProcessFile(first): %v", err)
	}
	// Spend the first file's entire allowance, as a decompression bomb would.
	if b := probe.seen[first]; b != nil {
		b.Reserve(embedded.BudgetBytes)
	}

	if _, err := fr.ProcessFile(second, nil); err != nil {
		t.Fatalf("ProcessFile(second): %v", err)
	}

	b2 := probe.seen[second]
	if b2 == nil {
		t.Fatal("the second file got no budget at all")
	}
	if b2 == probe.seen[first] {
		t.Fatal("both files share ONE budget object; a bomb in the first file would silence the second")
	}
	if b2.Remaining() != embedded.BudgetBytes {
		t.Errorf("the second file started with %d bytes, want the full %d — it inherited the "+
			"first file's spending", b2.Remaining(), embedded.BudgetBytes)
	}
}

// TestChildInheritsTheParentBudgetRatherThanAFreshOne is the core of #474.
//
// This is the assertion that fails on the unfixed code: every container drew its own fresh
// 200MB allowance, so the aggregate scaled with CONTAINER COUNT. Measured on a real
// LibreOffice .docx before the fix, a 367KB file with 64 embedded children took 130 grants and
// wrote 11,531MB to temp — a 32,947x write amplification at exit 0 with nothing on stderr.
func TestChildInheritsTheParentBudgetRatherThanAFreshOne(t *testing.T) {
	fr, probe := newProbedRouter(t)
	parent := writeProbeFile(t, "parent.probe")
	child := writeProbeFile(t, "child.probe")

	// Establish the parent as a top-level file with its own budget, the way processFileInternal
	// does, then spend part of it so inheritance is distinguishable from a fresh grant.
	parentBudget := embedded.NewBudget()
	parentBudget.Reserve(1024)
	fr.setBudget(parent, parentBudget)
	defer fr.clearBudget(parent)

	if _, err := fr.ProcessEmbedded(child, parent); err != nil {
		t.Fatalf("ProcessEmbedded: %v", err)
	}

	got := probe.seen[child]
	if got == nil {
		t.Fatal("the child was processed with no budget; it would materialise parts unbounded")
	}
	if got != parentBudget {
		t.Fatalf("the child got a DIFFERENT budget object from its parent — this is the #474 "+
			"amplification: remaining=%d vs parent's %d", got.Remaining(), parentBudget.Remaining())
	}
	if got.Remaining() != embedded.BudgetBytes-1024 {
		t.Errorf("the child's budget has %d bytes remaining, want %d: it must carry what the "+
			"parent already spent", got.Remaining(), embedded.BudgetBytes-1024)
	}
}

// TestChildDoesNotManufactureABudgetWhenTheParentHasNone pins the degradation path.
//
// A caller that reaches ProcessEmbedded with an untracked parent — a test, or any future entry
// point — must leave the child WITHOUT a traversal budget rather than granting a fresh one.
// Granting one is precisely the per-container amplification being removed, and it would reappear
// here as the one code path that still does it.
func TestChildDoesNotManufactureABudgetWhenTheParentHasNone(t *testing.T) {
	fr, probe := newProbedRouter(t)
	child := writeProbeFile(t, "orphan.probe")

	if _, err := fr.ProcessEmbedded(child, "/not/a/tracked/parent"); err != nil {
		t.Fatalf("ProcessEmbedded: %v", err)
	}

	if got := probe.seen[child]; got != nil {
		t.Errorf("an untracked parent's child was given a fresh %d-byte budget; that is the "+
			"per-container grant #474 removes", got.Remaining())
	}
}

// TestChildEntryIsReleasedAfterProcessing: the map tracks in-flight files only, exactly as the
// depth map does, so a deep or wide traversal cannot leave entries behind.
func TestChildEntryIsReleasedAfterProcessing(t *testing.T) {
	fr, _ := newProbedRouter(t)
	parent := writeProbeFile(t, "p.probe")
	child := writeProbeFile(t, "c.probe")

	fr.setBudget(parent, embedded.NewBudget())
	defer fr.clearBudget(parent)

	if _, err := fr.ProcessEmbedded(child, parent); err != nil {
		t.Fatalf("ProcessEmbedded: %v", err)
	}
	if fr.hasBudgetEntry(child) {
		t.Error("the child's entry outlived its processing; a wide traversal would accumulate one " +
			"entry per part for the lifetime of the scan")
	}
}

// TestEmbeddedDepthOfReportsWhatTheGuardBranchesOn.
//
// The Office preprocessor consults this BEFORE materialising parts, because MaxEmbeddedDepth is
// enforced in ProcessEmbedded — after every part has already been inflated and written to a temp
// file and then thrown away. If this reported 0 for a nested child the guard would never fire and
// the deepest level's bytes would still be written for nothing.
func TestEmbeddedDepthOfReportsWhatTheGuardBranchesOn(t *testing.T) {
	fr, probe := newProbedRouter(t)
	parent := writeProbeFile(t, "d1.probe")
	child := writeProbeFile(t, "d2.probe")

	if got := fr.EmbeddedDepthOf(parent); got != 0 {
		t.Errorf("EmbeddedDepthOf(top level) = %d, want 0", got)
	}

	fr.setDepth(parent, 1)
	defer fr.clearDepth(parent)
	if _, err := fr.ProcessEmbedded(child, parent); err != nil {
		t.Fatalf("ProcessEmbedded: %v", err)
	}
	if got := probe.depths[child]; got != 2 {
		t.Errorf("a child of a depth-1 parent saw depth %d, want 2", got)
	}
}
