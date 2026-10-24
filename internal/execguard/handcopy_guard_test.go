// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package execguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The cut-short family is enumerated ONCE, in IsCoverageCutShort. These tests are the guard that
// keeps it that way (#770, item 12).
//
// The family has been hand-copied before, and a hand copy fails silently: a member missing from
// one copy means its outcome is treated as success at that site. #424 introduced
// IsCoverageCutShort to replace the copies, and two survived it: the dual-path bridge's
// keepMatches, which tested ErrMatchBudgetExceeded alone and so dropped every partial a deadline
// or a size cap left behind, and core.ScanContent's chain, which omitted ErrValidatorPanicked. Both
// were found by measurement, not by review.
//
// The rule: outside internal/execguard, no non-test file in internal/, cmd/ or pkg/ calls
// errors.Is with a member of the family. A site that needs to know whether coverage was cut short
// calls IsCoverageCutShort. The one shape the rule allows is a switch that only picks WORDING once
// IsCoverageCutShort has matched (see allowedWordingSwitch); none exists today.

// moduleRoot is the repository root, two directories above this package.
const moduleRoot = "../.."

// sentinel is one member of the family, by import path and name.
type sentinel struct{ pkg, name string }

func (s sentinel) String() string { return s.pkg + "." + s.name }

// handCopy is one errors.Is call that names a member outside execguard.
type handCopy struct {
	pos  string
	expr string
}

// familyFromSource reads the family out of IsCoverageCutShort's own source: the second argument of
// every errors.Is call in its body, resolved through that file's imports. Derived, not listed, so a
// member added to the predicate is guarded from that commit on.
func familyFromSource(t *testing.T) map[sentinel]bool {
	t.Helper()
	modPath := modulePath(t)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[sentinel]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		imports := importTable(file)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name.Name != "IsCoverageCutShort" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isErrorsIs(call, imports) {
					return true
				}
				switch arg := call.Args[1].(type) {
				case *ast.Ident: // a sentinel of this package
					out[sentinel{modPath + "/internal/execguard", arg.Name}] = true
				case *ast.SelectorExpr:
					if x, ok := arg.X.(*ast.Ident); ok {
						out[sentinel{imports[x.Name], arg.Sel.Name}] = true
					}
				}
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("read no members out of IsCoverageCutShort; if it moved or stopped using errors.Is, " +
			"update familyFromSource rather than listing the family here")
	}
	return out
}

// TestNoHandCopiesOfTheCutShortFamily fails on every errors.Is(x, S), S a member of the family,
// in a non-test file under internal/, cmd/ or pkg/ outside internal/execguard.
func TestNoHandCopiesOfTheCutShortFamily(t *testing.T) {
	family := familyFromSource(t)
	if len(family) < 5 {
		t.Fatalf("IsCoverageCutShort names %d members (%v); the guard expected at least the five it was written against", len(family), family)
	}

	var found []handCopy
	files := 0
	for _, dir := range []string{"internal", "cmd", "pkg"} {
		root := filepath.Join(moduleRoot, dir)
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				switch info.Name() {
				case "testdata", "vendor", "node_modules":
					return filepath.SkipDir
				}
				if filepath.Clean(path) == filepath.Join(moduleRoot, "internal", "execguard") {
					return filepath.SkipDir // the family's owner
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			files++
			found = append(found, handCopiesIn(t, path, family)...)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if files < 100 {
		t.Fatalf("walked only %d source files; the guard is not looking where the code is", files)
	}
	if len(found) > 0 {
		var b strings.Builder
		for _, h := range found {
			b.WriteString("\n  " + h.pos + ": " + h.expr)
		}
		t.Errorf("%d errors.Is test(s) name a member of the cut-short family outside internal/execguard:%s\n"+
			"Call execguard.IsCoverageCutShort instead. A hand copy goes stale the first time the family "+
			"changes, and a member it misses is silently treated as success (#770). If a switch only picks "+
			"wording after IsCoverageCutShort has matched, nest it under that check (allowedWordingSwitch).",
			len(found), b.String())
	}
}

// handCopiesIn parses one file and returns its errors.Is calls on family members, minus those inside
// an allowed wording switch.
func handCopiesIn(t *testing.T, path string, family map[sentinel]bool) []handCopy {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return findHandCopies(fset, file, family, modulePath(t)+"/"+filepath.ToSlash(relDir(path)))
}

// findHandCopies is the guard's logic, separate from the walk so it can be tested on synthetic
// sources. pkgPath is the import path of the file's own package, for an unqualified sentinel.
func findHandCopies(fset *token.FileSet, file *ast.File, family map[sentinel]bool, pkgPath string) []handCopy {
	imports := importTable(file)
	var out []handCopy
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		call, ok := n.(*ast.CallExpr)
		if !ok || !isErrorsIs(call, imports) {
			return true
		}
		var s sentinel
		switch arg := call.Args[1].(type) {
		case *ast.Ident:
			s = sentinel{pkgPath, arg.Name}
		case *ast.SelectorExpr:
			x, ok := arg.X.(*ast.Ident)
			if !ok {
				return true
			}
			s = sentinel{imports[x.Name], arg.Sel.Name}
		default:
			return true
		}
		if family[s] && !allowedWordingSwitch(stack, imports) {
			out = append(out, handCopy{pos: fset.Position(call.Pos()).String(), expr: s.String()})
		}
		return true
	})
	return out
}

// allowedWordingSwitch reports whether the call sits in a case of a switch statement that is itself
// inside the body of an if whose condition calls IsCoverageCutShort: the one shape that asks WHICH
// guard fired, for a message, after the predicate has already decided that one did.
func allowedWordingSwitch(stack []ast.Node, imports map[string]string) bool {
	inCase := false
	for i := len(stack) - 1; i >= 0; i-- {
		switch n := stack[i].(type) {
		case *ast.CaseClause:
			inCase = true
		case *ast.IfStmt:
			if !inCase {
				return false
			}
			// The switch must be in the if's BODY, not its condition or else branch.
			if i+1 < len(stack) && stack[i+1] == n.Body && callsIsCoverageCutShort(n.Cond) {
				return true
			}
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		}
	}
	return false
}

func callsIsCoverageCutShort(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			switch f := call.Fun.(type) {
			case *ast.SelectorExpr:
				found = found || f.Sel.Name == "IsCoverageCutShort"
			case *ast.Ident:
				found = found || f.Name == "IsCoverageCutShort"
			}
		}
		return !found
	})
	return found
}

func isErrorsIs(call *ast.CallExpr, imports map[string]string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Is" || len(call.Args) != 2 {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && imports[x.Name] == "errors"
}

// importTable maps each name a file can use for an import to the import path: the alias when there
// is one (dual_path_bridge.go imports context as stdctx), else the path's last element.
func importTable(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = path
	}
	return out
}

func modulePath(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	t.Fatal("no module line in go.mod")
	return ""
}

func relDir(path string) string {
	rel, err := filepath.Rel(moduleRoot, filepath.Dir(path))
	if err != nil {
		return filepath.Dir(path)
	}
	return rel
}

// TestTheGuardFindsWhatItIsFor is the guard's own non-vacuity: each shape it must catch, and the one
// it must allow, on synthetic sources.
func TestTheGuardFindsWhatItIsFor(t *testing.T) {
	const eg = "github.com/awslabs/ferret-scan/v2/internal/execguard"
	family := map[sentinel]bool{
		{"context", "DeadlineExceeded"}: true,
		{"context", "Canceled"}:         true,
		{eg, "ErrMatchBudgetExceeded"}:  true,
		{eg, "ErrContentTooLarge"}:      true,
		{eg, "ErrValidatorPanicked"}:    true,
	}
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"the keepMatches copy", `package p
import ("errors"; "github.com/awslabs/ferret-scan/v2/internal/execguard")
func keep(err error) bool { return err == nil || errors.Is(err, execguard.ErrMatchBudgetExceeded) }`, 1},
		{"an aliased context import", `package p
import ("errors"; stdctx "context")
func cut(err error) bool { return errors.Is(err, stdctx.DeadlineExceeded) || errors.Is(err, stdctx.Canceled) }`, 2},
		{"the predicate itself", `package p
import "github.com/awslabs/ferret-scan/v2/internal/execguard"
func cut(err error) bool { return execguard.IsCoverageCutShort(err) }`, 0},
		{"a sentinel outside the family", `package p
import ("errors"; "io")
func eof(err error) bool { return errors.Is(err, io.EOF) }`, 0},
		{"a wording switch under the predicate", `package p
import ("errors"; "context"; "github.com/awslabs/ferret-scan/v2/internal/execguard")
func word(err error) string {
	if execguard.IsCoverageCutShort(err) {
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return "timed out"
		}
	}
	return ""
}`, 0},
		{"a switch NOT under the predicate", `package p
import ("errors"; "context")
func word(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	}
	return ""
}`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", c.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := findHandCopies(fset, file, family, "example.com/p"); len(got) != c.want {
				t.Errorf("found %d hand copies %v, want %d", len(got), got, c.want)
			}
		})
	}
}

// TestFamilyFromSourceMatchesThePredicate checks the derivation against the predicate's behaviour,
// so a parse that silently read the wrong function cannot leave the guard checking nothing.
func TestFamilyFromSourceMatchesThePredicate(t *testing.T) {
	got := familyFromSource(t)
	names := make([]string, 0, len(got))
	for s := range got {
		names = append(names, s.name)
	}
	sort.Strings(names)
	want := []string{"Canceled", "DeadlineExceeded", "ErrContentTooLarge", "ErrMatchBudgetExceeded", "ErrValidatorPanicked"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("derived family %v; IsCoverageCutShort tests %v. If the predicate changed, this list is the "+
			"one place to update, and TestNoHandCopiesOfTheCutShortFamily follows it", names, want)
	}
}
