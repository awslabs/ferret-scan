// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestValidatorConfigKeysMatchTheSource is what makes the hand-written validatorConfigKeys map safe
// to hand-write: it harvests the truth from the validator sources by AST and fails on ANY
// disagreement, in either direction.
//
//	read but not declared  -> the unknown-key warning would fire on a key that WORKS (worse than
//	                          the old silence: it teaches users to ignore the warnings)
//	declared but not read  -> documentation fiction; the map claims a knob the code ignores,
//	                          which is exactly the disabled_types-under-secrets failure (#726)
//
// Harvest shape, from the two idioms the codebase uses:
//
//	consumers:  cfg.Validators["intellectual_property"]  ->  section name + consuming package
//	reads:      ipConfig["internal_urls"]                ->  keys, within that package
func TestValidatorConfigKeysMatchTheSource(t *testing.T) {
	root := repoRootFromGoModConfig(t)
	fset := token.NewFileSet()

	sectionsByPkg := map[string]map[string]bool{} // package dir -> section names consumed there
	keysByPkg := map[string]map[string]bool{}     // package dir -> string literals used as map index

	files := 0
	err := filepath.Walk(filepath.Join(root, "internal"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		af, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		files++
		pkg := filepath.Dir(p)
		ast.Inspect(af, func(n ast.Node) bool {
			idx, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			lit, ok := idx.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			key, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			// cfg.Validators["name"]
			if sel, ok := idx.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "Validators" {
				if sectionsByPkg[pkg] == nil {
					sectionsByPkg[pkg] = map[string]bool{}
				}
				sectionsByPkg[pkg][key] = true
				return true
			}
			// <somethingConfig>["key"] — the section-read idiom (ipConfig, smConfig, cloudConfig).
			if id, ok := idx.X.(*ast.Ident); ok && strings.HasSuffix(id.Name, "onfig") {
				if keysByPkg[pkg] == nil {
					keysByPkg[pkg] = map[string]bool{}
				}
				keysByPkg[pkg][key] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Assemble section -> keys actually read, joining the two harvests by package. cmd/ also
	// WRITES Validators["intellectual_property"] to inject the --disable-ip-types flag; only
	// validator packages both consume a section and read keys, which is what the join expresses.
	read := map[string]map[string]bool{}
	for pkg, sections := range sectionsByPkg {
		for name := range sections {
			if !strings.Contains(pkg, string(filepath.Separator)+"validators"+string(filepath.Separator)) {
				continue
			}
			if read[name] == nil {
				read[name] = map[string]bool{}
			}
			for k := range keysByPkg[pkg] {
				read[name][k] = true
			}
		}
	}

	// NON-VACUITY: floors and one per-arm control.
	if files < 150 {
		t.Fatalf("parsed only %d production files; partial tree", files)
	}
	if len(read) < 3 {
		t.Fatalf("harvested only %d consuming sections; the join is broken (sectionsByPkg=%d pkgs)",
			len(read), len(sectionsByPkg))
	}
	if !read["intellectual_property"]["internal_urls"] {
		t.Fatal("control failed: intellectual_property/internal_urls not harvested — the read arm is broken")
	}

	// Both directions.
	for name, keys := range read {
		declared, ok := validatorConfigKeys[name]
		if !ok {
			t.Errorf("validator section %q is READ by the source but not declared in "+
				"validatorConfigKeys — its keys would all warn as unknown while working", name)
			continue
		}
		for k := range keys {
			if !declared[k] {
				t.Errorf("%s.%s is read by the source but not declared — a working key would warn "+
					"as unknown", name, k)
			}
		}
	}
	for name, declared := range validatorConfigKeys {
		got, ok := read[name]
		if !ok {
			t.Errorf("validatorConfigKeys declares section %q which no validator reads — "+
				"documentation fiction, the #726 failure shape", name)
			continue
		}
		for k := range declared {
			if !got[k] {
				t.Errorf("validatorConfigKeys declares %s.%s which the source never reads — "+
					"a user setting it gets silence, the exact defect this map exists to end", name, k)
			}
		}
	}
}

func repoRootFromGoModConfig(t *testing.T) string {
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
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}
