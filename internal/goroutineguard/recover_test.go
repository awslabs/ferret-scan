// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package goroutineguard holds one test: every goroutine started in this module's
// scan path must recover, or be listed here with a reason.
//
// It is a package rather than a file inside an existing one because the check walks
// the whole module and belongs to none of the packages it inspects.
package goroutineguard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Why this is a gate and not a review habit.
//
// A Go panic does not cross a goroutine boundary. So `defer recover()` in a function
// protects that function and NOT the goroutines it starts, and the failure mode when it
// is missing is the worst one available: the process dies mid-run, every file after the
// current one goes unscanned, and there is no report at all — strictly worse than a
// disclosed refusal, because a refusal at least produces output.
//
// That asymmetry is easy to get wrong precisely because the parent looks protected.
// `ExtractText` in the PDF text extractor had a recover in its own defer and started
// per-page goroutines with none; the recover's existence was evidence the library panics,
// and the children it spawned were the unprotected ones (#665).
//
// Audited at the time this was written: 14 goroutines in non-test code, of which 4 ran
// third-party parsers over untrusted file bytes with no recover anywhere above them.
// All four now recover. The rest are listed below with the reason each is safe.

// exempt maps "<file>::<enclosing function>" to the reason a goroutine there needs no
// recover of its own.
//
// Keyed on the enclosing FUNCTION rather than a line number so the entry survives edits
// above it. A file+function key can cover several goroutines in the same function, which
// is deliberate: they are reviewed together.
//
// Adding an entry is a claim that has to be true. "It probably won't panic" is not a
// reason — the two categories below are.
var exempt = map[string]string{
	// (a) The body does no work that can panic: channel close, WaitGroup wait.
	"internal/parallel/parallel_processor.go::ProcessFilesWithProgress": "" +
		"closes a channel and calls workerPool.Submit; the submit path is itself guarded and " +
		"neither operation runs file content",

	// (b) Everything the body calls recovers internally, at a documented chokepoint.
	//
	// RunValidators dispatches through the validator's ValidateProcessedContentCtx, which
	// reaches execguard.SafeRun — the per-validator chokepoint that recovers and, since
	// #658, reports the panic as coverage cut short. validator_runner.go:104-107 states
	// this. Verified end-to-end in #656: a panicking validator produces
	// `validator "X" panicked` in the SARIF notifications and exit 3 under
	// --fail-on-incomplete, rather than killing the process.
	"internal/parallel/validator_runner.go::RunValidators": "" +
		"dispatches through execguard.SafeRun, which recovers per validator and reports the " +
		"panic as coverage cut short (#658); the remaining goroutines here only close " +
		"channels and wait on the WaitGroup",

	"internal/validators/dual_path_bridge.go::processDualPath": "" +
		"calls ProcessDocumentContentCtx / ProcessMetadataContentCtx, both of which fan out " +
		"through execguard.ValidateContent",
	"internal/validators/dual_path_bridge.go::ProcessDocumentContentCtx": "" +
		"the per-validator goroutine calls execguard.ValidateContent directly; the other " +
		"closes a channel after wg.Wait",
}

var goFuncRe = regexp.MustCompile(`\bgo\s+func\s*\(`)
var funcDeclRe = regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)

// TestEveryGoroutineRecovers walks the module's non-test Go source and requires each
// `go func` body to contain a recover(), unless its file+function is exempt above.
func TestEveryGoroutineRecovers(t *testing.T) {
	root := moduleRoot(t)

	type site struct {
		file, fn string
		line     int
		hasRec   bool
	}
	var sites []site

	for _, dir := range []string{"internal", "pkg", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			lines := strings.Split(string(raw), "\n")
			fn := "?"
			for i, l := range lines {
				if m := funcDeclRe.FindStringSubmatch(l); m != nil {
					fn = m[1]
				}
				if !goFuncRe.MatchString(l) {
					continue
				}
				sites = append(sites, site{rel, fn, i + 1, bodyHasRecover(lines, i)})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", dir, err)
		}
	}

	// Non-vacuity: if the walk finds nothing, the test asserts nothing. The count is
	// deliberately a floor and not an equality — a new goroutine should fail this test on
	// its recover, not on a count nobody remembered to bump.
	if len(sites) < 10 {
		t.Fatalf("found only %d `go func` sites; the walk is broken, so this gate would pass "+
			"no matter what the code did", len(sites))
	}
	t.Logf("audited %d goroutine sites in non-test code", len(sites))

	var unprotected []string
	used := map[string]bool{}
	for _, s := range sites {
		key := s.file + "::" + s.fn
		if s.hasRec {
			continue
		}
		if reason, ok := exempt[key]; ok {
			used[key] = true
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempt with an empty reason; an exemption without a reason is "+
					"indistinguishable from an oversight", key)
			}
			continue
		}
		unprotected = append(unprotected, fmt.Sprintf("%s:%d (func %s)", s.file, s.line, s.fn))
	}

	if len(unprotected) > 0 {
		sort.Strings(unprotected)
		t.Errorf("%d goroutine(s) neither recover nor are exempt:\n  %s\n\n"+
			"A Go panic does not cross a goroutine boundary, so a recover in the calling "+
			"function does NOT protect this body. An unrecovered panic here kills the whole "+
			"process: the run stops mid-scan, every remaining file goes unscanned, and no "+
			"report is produced at all.\n\n"+
			"Either add `defer func() { if r := recover(); r != nil { ... } }()` that reports the "+
			"failure through the channel this goroutine already writes to — so it becomes a "+
			"disclosed per-unit failure rather than a process death — or add a file::function "+
			"entry to `exempt` in this file stating why it cannot panic.",
			len(unprotected), strings.Join(unprotected, "\n  "))
	}

	// A stale exemption is its own bug: it says a hazard was reviewed when the code it
	// referred to is gone, and the next reader trusts it.
	for key := range exempt {
		if !used[key] {
			t.Errorf("exempt entry %q matched no unprotected goroutine — it is stale, or the "+
				"goroutine now has its own recover and the entry should be deleted", key)
		}
	}
}

// bodyHasRecover reports whether the goroutine literal starting at lines[i] contains a
// recover() call IN CODE, tracking brace depth to find the body's end.
//
// Comments are stripped first, and that is not a detail. The first version of this
// function tested the raw line, so a goroutine whose comment merely MENTIONED recover()
// satisfied the gate — and the very first fix this gate was written to protect carries
// exactly such a comment ("The recover() in ExtractText's own defer cannot see this"). The
// gate passed with the real recover deleted, which is a guard that cannot fail: any author
// explaining why a recover is needed would have exempted themselves from having one.
//
// Caught by mutation, and only because the mutation was verified to have landed (the
// recover() count in the file dropped from 3 to 2) before the gate was run. A mutation
// that silently does not apply reads exactly like a gate that works.
func bodyHasRecover(lines []string, i int) bool {
	depth, started, inBlock := 0, false, false
	for j := i; j < len(lines) && j < i+250; j++ {
		code, blk := stripComments(lines[j], inBlock)
		inBlock = blk
		depth += strings.Count(code, "{") - strings.Count(code, "}")
		if strings.Contains(code, "{") {
			started = true
		}
		if strings.Contains(code, "recover()") {
			return true
		}
		if started && depth <= 0 {
			return false
		}
	}
	return false
}

// stripComments removes // and /* */ comment text from one line, returning the code and
// whether a block comment is still open. Brace counting also has to use the stripped
// line: a brace inside a comment would otherwise shift the body boundary.
//
// Deliberately not a full Go lexer — it does not understand braces or comment markers
// inside string literals. That is acceptable here because a false "no recover" only
// produces a demand for an exemption entry, never a silent pass, and TestStripComments
// pins the cases that matter.
func stripComments(line string, inBlock bool) (string, bool) {
	var b strings.Builder
	for k := 0; k < len(line); k++ {
		if inBlock {
			if k+1 < len(line) && line[k] == '*' && line[k+1] == '/' {
				inBlock = false
				k++
			}
			continue
		}
		if k+1 < len(line) && line[k] == '/' && line[k+1] == '/' {
			break
		}
		if k+1 < len(line) && line[k] == '/' && line[k+1] == '*' {
			inBlock = true
			k++
			continue
		}
		b.WriteByte(line[k])
	}
	return b.String(), inBlock
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}

// TestStripComments pins the comment stripper, because the gate above is only as good as
// this function: a stripper that let comment text through is what made the first version
// of the gate unable to fail.
func TestStripComments(t *testing.T) {
	cases := []struct {
		in       string
		inBlock  bool
		wantCode string
		wantOpen bool
	}{
		{`if r := recover(); r != nil {`, false, `if r := recover(); r != nil {`, false},
		{`// the recover() in the parent cannot see this`, false, ``, false},
		{`x := 1 // recover() mentioned in a trailing comment`, false, `x := 1 `, false},
		{`/* recover() */ y := 2`, false, ` y := 2`, false},
		{`/* start of a block`, false, ``, true},
		{`still inside, recover() here does not count`, true, ``, true},
		{`end of block */ z := recover()`, true, ` z := recover()`, false},
		// Braces inside a comment must not move the body boundary.
		{`// } this brace is not real`, false, ``, false},
	}
	for _, c := range cases {
		got, open := stripComments(c.in, c.inBlock)
		if got != c.wantCode || open != c.wantOpen {
			t.Errorf("stripComments(%q, %v) = (%q, %v), want (%q, %v)",
				c.in, c.inBlock, got, open, c.wantCode, c.wantOpen)
		}
	}
}
