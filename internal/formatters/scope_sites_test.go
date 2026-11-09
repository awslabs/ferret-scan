// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Every place the CLI builds a FormatterOptions must give it a scope and stats (#904).
//
// Before this, five non-test sites built one and only --file's set Stats; none carried a scope. Go
// does not flag a field missing from a keyed literal, which is how a disclosure added at one site
// never reached the others: #699's expiry field reached one of main()'s two configFlags literals,
// and stdin's two FormatterOptions literals never got the stats block --file has had since #296.
//
// The check is per FUNCTION, not per literal: a site may set the field in the literal or assign it
// to the variable later in the same function, as main() does with Stats once the counts exist.

// formatterOptionsSitesAllowed are the functions that build a FormatterOptions without a scope, each
// with the reason. Adding one needs a reason a reviewer can check.
var formatterOptionsSitesAllowed = map[string]string{
	"internal/web/server.go:handleScan": "the /scan response is a ScanResponse built field by field from the " +
		"formatted JSON, and it has no slot for scan or stats yet; filling them here would reach no client " +
		"(follow-up: ScanResponse.Scan)",
	"internal/web/server.go:handleExport": "/export re-renders findings the browser posts back; it runs no scan " +
		"of its own, so it has no scope to report",
}

func TestEveryCLIFormatterOptionsSetsScanAndStats(t *testing.T) {
	root := filepath.Join("..", "..")
	sites := 0
	for _, dir := range []string{"cmd", filepath.Join("internal", "web")} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			rel := filepath.ToSlash(filepath.Join(dir, name))
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(root, dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", rel, err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				literals, setFields := formatterOptionsUse(fn.Body)
				if literals == 0 {
					continue
				}
				sites += literals
				key := rel + ":" + fn.Name.Name
				if reason, ok := formatterOptionsSitesAllowed[key]; ok {
					if setFields["Scan"] {
						t.Errorf("%s now sets Scan; remove it from the allowlist (it said: %s)", key, reason)
					}
					continue
				}
				for _, field := range []string{"Scan", "Stats"} {
					if !setFields[field] {
						t.Errorf("%s (%s) builds a formatters.FormatterOptions and never sets %s, so its reports "+
							"cannot say what the run could report", key, fset.Position(fn.Pos()), field)
					}
				}
			}
		}
	}
	// The sites this test knows: main()'s, stdin's one constructor, the two web handlers. A rename that
	// moved every literal out of reach would otherwise pass with nothing checked.
	if sites < 4 {
		t.Errorf("found %d FormatterOptions literals in cmd/ and internal/web/, want at least 4; the guard is not "+
			"looking where the literals are", sites)
	}
	for key := range formatterOptionsSitesAllowed {
		if !strings.Contains(key, ":") {
			t.Errorf("allowlist key %q is not file:function", key)
		}
	}
}

// formatterOptionsUse counts the formatters.FormatterOptions composite literals in body and reports
// which fields the body sets: keys of those literals, and selector assignments `x.Field = ...`.
func formatterOptionsUse(body *ast.BlockStmt) (literals int, set map[string]bool) {
	set = map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			sel, ok := node.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "FormatterOptions" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "formatters" {
				return true
			}
			literals++
			for _, elt := range node.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					if id, ok := kv.Key.(*ast.Ident); ok {
						set[id.Name] = true
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					set[sel.Sel.Name] = true
				}
			}
		}
		return true
	})
	return literals, set
}

// TestTheSiteGuardSeesAMissingField is the guard's control: the same walk over a function that builds a
// FormatterOptions without a scope must report Scan as unset.
func TestTheSiteGuardSeesAMissingField(t *testing.T) {
	src := `package p
func f() {
	o := formatters.FormatterOptions{Limit: 1}
	o.Stats = nil
	_ = o
}`
	file, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	literals, set := formatterOptionsUse(file.Decls[0].(*ast.FuncDecl).Body)
	if literals != 1 || set["Scan"] || !set["Stats"] || !set["Limit"] {
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("literals=%d set=%v: want 1 literal with Limit and Stats set and Scan unset", literals, keys)
	}
}
