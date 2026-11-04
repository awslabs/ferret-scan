// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Guards for #886, read off the source of every non-test .go file in the module.
//
// A synthetic replacement is drawn through a scope, so that one value gets one replacement per
// invocation. Three ways to undo that without any test noticing are ruled out here:
//
//  1. calling the unscoped draws (replacement.Synthetic, replacement.SyntheticName) to write a value:
//     each call is an independent draw, which is the bug;
//  2. passing a nil scope where the strategy may be synthetic: that is an error at run time, but a
//     path no test exercises would ship it;
//  3. seeding a scope outside a test: every "synthetic" value would become a function of a constant.

type sourceCall struct {
	file string // module-relative, slash-separated
	pos  token.Position
	call *ast.CallExpr
	name string // the function called
	qual string // the package qualifier, "" for a call from inside the declaring package
}

// of reports whether the call reaches pkg's function: qualified by pkg's name from anywhere, or
// unqualified from a file in pkg's own directory.
func (c sourceCall) of(pkg, dir string) bool {
	if c.qual != "" {
		return c.qual == pkg
	}
	return filepath.ToSlash(filepath.Dir(c.file)) == dir
}

// productionCalls returns every call of a function whose name is in names, written pkg.Name(...) or
// Name(...), in every non-test .go file of the module.
func productionCalls(t *testing.T, names map[string]bool) []sourceCall {
	t.Helper()
	root := moduleRoot(t)
	var out []sourceCall
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
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			c := sourceCall{file: rel, pos: fset.Position(call.Pos()), call: call}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				c.name = fn.Sel.Name
				if id, ok := fn.X.(*ast.Ident); ok {
					c.qual = id.Name
				} else {
					c.qual = "?" // a method on a value: never one of the package functions guarded here
				}
			case *ast.Ident:
				c.name = fn.Name
			}
			if names[c.name] {
				out = append(out, c)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const replacementDir = "internal/redactors/replacement"

func TestNoProductionCodeDrawsASyntheticValueWithoutAScope(t *testing.T) {
	for _, c := range productionCalls(t, map[string]bool{"Synthetic": true, "SyntheticName": true}) {
		if c.of("replacement", replacementDir) {
			t.Errorf("%s: replacement.%s is one independent draw; write synthetic values through "+
				"Generate, Render or RenderGroup with the invocation's scope (#886)", c.pos, c.name)
		}
	}
}

func TestNoProductionCallPassesANilScopeForSynthetic(t *testing.T) {
	checked := 0
	for _, c := range productionCalls(t, map[string]bool{"Generate": true, "Render": true, "RenderGroup": true}) {
		if !c.of("replacement", replacementDir) {
			continue
		}
		checked++
		if len(c.call.Args) != 4 {
			t.Errorf("%s: replacement.%s with %d arguments; the guard expects (…, strategy, scope)", c.pos, c.name, len(c.call.Args))
			continue
		}
		if id, ok := c.call.Args[3].(*ast.Ident); !ok || id.Name != "nil" {
			continue
		}
		// A nil scope is allowed only beside a strategy that cannot be synthetic, named as a constant.
		st, ok := c.call.Args[2].(*ast.SelectorExpr)
		if !ok || (st.Sel.Name != "RedactionFormatPreserving" && st.Sel.Name != "RedactionSimple") {
			t.Errorf("%s: replacement.%s passes a nil scope with a strategy that may be synthetic; pass the "+
				"redactor's scope (#886)", c.pos, c.name)
		}
	}
	if checked == 0 {
		t.Fatal("found no replacement.Generate/Render/RenderGroup call: the guard is not looking at the code")
	}
}

func TestNoProductionCodeSeedsTheSyntheticScope(t *testing.T) {
	for _, c := range productionCalls(t, map[string]bool{"NewSeededSyntheticScope": true}) {
		if c.of("redactors", "internal/redactors") {
			t.Errorf("%s: a seeded synthetic scope outside a test makes every synthetic value a function of a constant", c.pos)
		}
	}
}
