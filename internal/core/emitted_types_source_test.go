// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// THE LIST'S OWN HEADER RECORDS THE DEFECT THIS GUARD CLOSES. knownDetectionTypes says it was
// "derived by enumerating the rules the tool ACTUALLY emitted, not by reading validator source",
// and TestEveryEmittedTypeIsKnown harvests the golden SARIF corpus — real output, but only the
// output the corpus happens to produce. The corpus emits 32 distinct types; the source can emit
// more. Measured on 2026-09-23, five types were reachable in production code and absent from the
// list, from docs/checks.md, and from every helpUri: CERTIFICATE, PGP_PRIVATE_KEY (secrets),
// CUSTOM_PROPERTY, DOCUMENT_DESCRIPTION, MANAGER_INFO (metadata). A consumer keying a suppression
// on one of those ruleIds had no documented name to key on, and the SARIF helpUri for them 404s —
// the exact failure knownDetectionTypes was created to end.
//
// A corpus harvest measures a population that cannot reach the defect: the fixture set pins
// exactly the axis the guard is supposed to bound. So this guard harvests the SOURCE.
//
// WHAT IT HARVESTS. Every string that can flow into detector.Match.Type through the shapes the
// codebase actually uses, found by AST walk over production .go files:
//
//  1. a composite literal's Type field:            detector.Match{Type: "SSN", ...}
//  2. a field assignment:                          m.Type = "SSN"
//  3. one hop of indirection through a helper:     Type: v.classify(x)   where
//     classify contains `return "CERTIFICATE"` — the shape the five missing types used.
//     The hop also covers `t := v.classify(x); ... Type: t` within one function.
//
// Deeper indirection (a type name built by string concatenation, or crossing more than one call)
// does not exist in this codebase today; if someone introduces it, the floors below shrink and
// this test says so rather than silently under-harvesting.
func TestEverySourceEmittableTypeIsKnown(t *testing.T) {
	root := repoRootFromGoMod(t)

	var files []string
	for _, dir := range []string{"internal", "pkg"} {
		err := filepath.Walk(filepath.Join(root, dir), func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			files = append(files, p)
			return nil
		})
		if err != nil {
			t.Fatalf("walk: %v", err)
		}
	}
	if len(files) < 150 {
		t.Fatalf("walked only %d production files; the tree has far more, so the harvest below "+
			"would be measuring a partial checkout", len(files))
	}

	fset := token.NewFileSet()

	// Pass structure: parse every file once; collect direct literals, per-function helper-call
	// names used as Type, and every function's returned string literals. Then resolve the one hop.
	typeLit := regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`)
	direct := map[string][]string{}        // literal -> files
	helperReturns := map[string][]string{} // funcName -> returned string literals
	typeCallees := map[string]bool{}       // funcNames whose result feeds a Type field
	calleeSites := map[string][]string{}   // funcName -> files where used as Type

	strLit := func(e ast.Expr) (string, bool) {
		if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
			s, err := strconv.Unquote(b.Value)
			return s, err == nil
		}
		return "", false
	}
	calleeName := func(e ast.Expr) (string, bool) {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return "", false
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			return f.Name, true
		case *ast.SelectorExpr:
			return f.Sel.Name, true
		}
		return "", false
	}

	parsed := 0
	for _, f := range files {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		parsed++
		rel, _ := filepath.Rel(root, f)

		ast.Inspect(af, func(n ast.Node) bool {
			fd, ok := n.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				return true
			}
			// identifiers assigned from a call within this function: ident -> callee
			identFrom := map[string]string{}
			ast.Inspect(fd.Body, func(m ast.Node) bool {
				switch x := m.(type) {
				case *ast.AssignStmt:
					// t := v.classify(...)  /  m.Type = ...
					for i, lhs := range x.Lhs {
						if i >= len(x.Rhs) {
							break
						}
						if id, ok := lhs.(*ast.Ident); ok {
							if cn, ok := calleeName(x.Rhs[i]); ok {
								identFrom[id.Name] = cn
							}
						}
						if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Type" {
							if s, ok := strLit(x.Rhs[i]); ok && typeLit.MatchString(s) {
								direct[s] = append(direct[s], rel)
							} else if cn, ok := calleeName(x.Rhs[i]); ok {
								typeCallees[cn] = true
								calleeSites[cn] = append(calleeSites[cn], rel)
							}
						}
					}
				case *ast.CompositeLit:
					// Only a Match composite counts. The first version of this guard read the
					// Type key of EVERY composite literal and harvested SECURITY_FINDINGS — a
					// JUnit XML failure-type attribute from the junit formatter, not a
					// detection type. The field name alone does not identify the field.
					if !compositeIsMatch(x) {
						return true
					}
					for _, el := range x.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						id, ok := kv.Key.(*ast.Ident)
						if !ok || id.Name != "Type" {
							continue
						}
						if s, ok := strLit(kv.Value); ok {
							if typeLit.MatchString(s) {
								direct[s] = append(direct[s], rel)
							}
						} else if cn, ok := calleeName(kv.Value); ok {
							typeCallees[cn] = true
							calleeSites[cn] = append(calleeSites[cn], rel)
						} else if vid, ok := kv.Value.(*ast.Ident); ok {
							if cn, ok := identFrom[vid.Name]; ok {
								typeCallees[cn] = true
								calleeSites[cn] = append(calleeSites[cn], rel)
							}
						}
					}
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						if s, ok := strLit(r); ok && typeLit.MatchString(s) {
							helperReturns[fd.Name.Name] = append(helperReturns[fd.Name.Name], s)
						}
					}
				}
				return true
			})
			return true
		})
	}

	// Resolve the one hop: every literal returned by a function whose result feeds Type.
	viaHelper := map[string][]string{}
	for fn := range typeCallees {
		for _, s := range helperReturns[fn] {
			viaHelper[s] = append(viaHelper[s], fn)
		}
	}

	emitted := map[string]string{} // type -> provenance for the failure message
	for s, where := range direct {
		emitted[s] = "Type literal in " + where[0]
	}
	for s, fns := range viaHelper {
		if _, dup := emitted[s]; !dup {
			emitted[s] = "returned by " + fns[0] + "() whose result feeds Match.Type"
		}
	}

	// The detector package itself and shared plumbing use placeholder types in constructors the
	// walk cannot tell from real emission. Only concrete, screaming-snake identifiers survive the
	// regexp; single lowercase words never entered. What remains that is NOT a detection type is
	// excluded HERE, each with the reason it is a false hit of the walk, so the next person can
	// re-check the claim instead of trusting it.
	notDetectionTypes := map[string]string{
		"POSITIONAL": "redactors/position placeholder written into Match.Type by a test-support constructor",
	}

	// NON-VACUITY, three floors and two controls.
	if parsed < 150 {
		t.Fatalf("parsed %d files", parsed)
	}
	if len(emitted) < 50 {
		t.Fatalf("harvested only %d candidate types; the tool emits 60+, so the walk is broken "+
			"and every containment check below would pass vacuously", len(emitted))
	}
	if _, ok := emitted["SSN"]; !ok {
		t.Fatal("control failed: SSN not harvested — the direct-literal arm is broken")
	}
	if _, ok := emitted["CERTIFICATE"]; !ok {
		t.Fatal("control failed: CERTIFICATE not harvested — the one-hop helper arm is broken " +
			"(it is emitted via `return \"CERTIFICATE\"` in the secrets validator)")
	}

	var missing []string
	for typ, prov := range emitted {
		if notDetectionTypes[typ] != "" {
			continue
		}
		if !IsKnownType(typ) {
			missing = append(missing, typ+"  ("+prov+")")
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d type(s) the source can emit are missing from knownDetectionTypes:\n  %s\n\n"+
			"Every one is a SARIF ruleId with a helpUri that 404s and a name absent from "+
			"docs/checks.md — a consumer cannot discover it to suppress it. Add each to "+
			"knownDetectionTypes (internal/core/typemeta.go), map it in typeParent if a family "+
			"description fits (typemeta_inherit.go), and regenerate docs with "+
			"UPDATE_CHECK_DOCS=1. If a hit is not really a detection type, add it to "+
			"notDetectionTypes in this test WITH the reason.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// compositeIsMatch reports whether a composite literal constructs a detector Match — the named
// type is Match or SuppressedMatch, with or without a package qualifier. Named loosely on purpose:
// within package detector the literal is `Match{...}`, outside it `detector.Match{...}`.
func compositeIsMatch(cl *ast.CompositeLit) bool {
	name := ""
	switch t := cl.Type.(type) {
	case *ast.Ident:
		name = t.Name
	case *ast.SelectorExpr:
		name = t.Sel.Name
	case nil:
		// an element of []detector.Match{{...}} has a nil Type; the enclosing slice was already
		// filtered, but a nested bare literal cannot be classified, so it is skipped. Every
		// production emission site names the type; measured, skipping nil costs no harvest.
		return false
	}
	return name == "Match" || name == "SuppressedMatch"
}

// repoRootFromGoMod climbs to go.mod. A fixed "../.." broke a previous guard in this repo when the
// file moved one directory deeper and it silently checked one site instead of three.
func repoRootFromGoMod(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found climbing from the test's working directory")
		}
		dir = parent
	}
}
