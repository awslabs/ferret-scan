// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The strategy gate (#863): a redactor's GetSupportedStrategies is enforced, so a strategy it does
// not declare is refused instead of being rendered as some other strategy under the requested name.

// declaredStub declares exactly the strategies it is given and records whether it was asked to
// redact, so a test can tell a refusal at the gate from a redaction that happened to fail.
type declaredStub struct {
	declared []RedactionStrategy
	called   bool
}

func (s *declaredStub) GetName() string                             { return "declared_stub" }
func (s *declaredStub) GetSupportedTypes() []string                 { return []string{".jpg"} }
func (s *declaredStub) GetSupportedStrategies() []RedactionStrategy { return s.declared }
func (s *declaredStub) GetComponentName() string                    { return "declared_stub" }
func (s *declaredStub) RedactDocument(_, outputPath string, _ []detector.Match, _ RedactionStrategy) (*RedactionResult, error) {
	s.called = true
	if err := os.WriteFile(outputPath, []byte(stubRedactedOutput), 0o600); err != nil {
		return nil, err
	}
	return &RedactionResult{Success: true, RedactedFilePath: outputPath}, nil
}

func fpOnly() *declaredStub {
	return &declaredStub{declared: []RedactionStrategy{RedactionFormatPreserving}}
}

func TestCheckStrategyRefusesOnlyAnUndeclaredStrategyWithSomethingToRedact(t *testing.T) {
	r := fpOnly()

	err := CheckStrategy(r, RedactionSimple, sampleMatches())
	if !errors.Is(err, ErrStrategyNotSupported) {
		t.Fatalf("CheckStrategy(simple) on a format_preserving-only redactor = %v, want ErrStrategyNotSupported", err)
	}
	for _, want := range []string{"declared_stub", "format_preserving", "simple"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q; the operator needs the strategy, the redactor "+
				"and what it does support to choose again", err, want)
		}
	}
	if err := CheckStrategy(r, RedactionFormatPreserving, sampleMatches()); err != nil {
		t.Errorf("a declared strategy was refused: %v", err)
	}
	// Nothing to render means no strategy is applied: a clean or fully suppressed file is never
	// reported as unredacted.
	if err := CheckStrategy(r, RedactionSimple, nil); err != nil {
		t.Errorf("a dispatch with no matches was refused: %v", err)
	}
}

func TestRedactorForRefusesAnUndeclaredStrategy(t *testing.T) {
	rm := newTestManager(t)
	stub := fpOnly()
	if err := rm.RegisterRedactor(stub); err != nil {
		t.Fatal(err)
	}

	if _, err := rm.RedactorFor("photo.jpg", RedactionSimple, sampleMatches()); !errors.Is(err, ErrStrategyNotSupported) {
		t.Fatalf("RedactorFor(simple) = %v, want ErrStrategyNotSupported", err)
	}
	got, err := rm.RedactorFor("photo.jpg", RedactionFormatPreserving, sampleMatches())
	if err != nil || got != Redactor(stub) {
		t.Fatalf("RedactorFor(format_preserving) = %v, %v; want the registered redactor", got, err)
	}
	if got, err := rm.RedactorFor("photo.jpg", RedactionSimple, nil); err != nil || got != Redactor(stub) {
		t.Fatalf("RedactorFor(simple, no matches) = %v, %v; want the registered redactor", got, err)
	}
	// A selection failure keeps its own meaning, so a caller can still tell "no redactor for this
	// type" from "this type cannot take this strategy".
	if _, err := rm.RedactorFor("report.pdf", RedactionSimple, sampleMatches()); err == nil || errors.Is(err, ErrStrategyNotSupported) {
		t.Fatalf("RedactorFor on an unregistered type = %v; want GetRedactorForFile's error, not a strategy refusal", err)
	}
}

// TestRedactEmbeddedRefusesAnUndeclaredStrategy is the embedded dispatch site: a part whose redactor
// does not declare the strategy is refused before it is redacted, and the refusal is not mistaken
// for "no redactor handles this type".
func TestRedactEmbeddedRefusesAnUndeclaredStrategy(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	rm := newTestManager(t)
	stub := fpOnly()
	if err := rm.RegisterRedactor(stub); err != nil {
		t.Fatal(err)
	}
	req := EmbeddedRedactionRequest{
		ParentPath: "parent.docx",
		PartName:   "word/media/image1.jpg",
		Content:    []byte("x"),
		Matches:    sampleMatches(),
		Strategy:   RedactionSimple,
	}

	_, err := rm.RedactEmbedded(req)
	if !errors.Is(err, ErrStrategyNotSupported) {
		t.Fatalf("RedactEmbedded(simple) = %v, want ErrStrategyNotSupported", err)
	}
	if errors.Is(err, ErrNoEmbeddedRedactor) {
		t.Errorf("the refusal reads as \"no redactor handles this embedded file type\", but the type has one")
	}
	if !strings.Contains(err.Error(), "image1.jpg") {
		t.Errorf("refusal %q does not name the part", err)
	}
	if stub.called {
		t.Error("the part was redacted under a strategy its redactor does not declare")
	}

	req.Strategy = RedactionFormatPreserving
	if _, err := rm.RedactEmbedded(req); err != nil || !stub.called {
		t.Fatalf("RedactEmbedded(format_preserving) = %v (redactor called: %v); a declared strategy must dispatch",
			err, stub.called)
	}
}

// TestNoDispatchBypassesTheStrategyGate keeps GetSupportedStrategies enforced: a production use of
// GetRedactorForFile hands a file to a redactor without asking whether it declares the strategy,
// which is how synthetic was written as a mask at exit 0. Every non-test Go file in the module is
// parsed, and every reference counts -- a call, or the method taken as a value and called later;
// RedactorFor itself is the one sanctioned user. There is no allowlist: the worker pool, the last
// production caller, dispatches through RedactorFor since #863.
func TestNoDispatchBypassesTheStrategyGate(t *testing.T) {
	root := moduleRoot(t)
	found := map[string]int{}
	gate := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, isSel := n.(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "GetRedactorForFile" {
					return true
				}
				if ok && fn.Name.Name == "RedactorFor" && rel == "internal/redactors/capability.go" {
					gate++
				} else {
					found[rel]++
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if gate != 1 {
		t.Fatalf("RedactorFor uses GetRedactorForFile %d times, want 1: the guard is not looking at the gate", gate)
	}
	for file, n := range found {
		t.Errorf("%s uses GetRedactorForFile %d time(s). Dispatch through RedactionManager.RedactorFor so "+
			"the redactor's declared strategies are enforced (#863)", file, n)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}
