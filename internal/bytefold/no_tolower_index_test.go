// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytefold_test

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

// The guard for the case-fold-then-index class, which has now produced FOUR shipped bugs and two more
// found by this test's own sweep.
//
// The shape: an offset is taken from a case-folded copy of a string and then applied to the ORIGINAL.
// strings.ToLower is not length-preserving — enumerating the code point space, 25 runes shrink and 2
// grow — so any length-changing rune before the match shifts every subsequent offset.
//
// The consequences are not uniform, which is why this kept getting through:
//
//	panic          bankaccount, vin (#658) — the slice overran and the whole file returned 0 findings
//	silent misread personname, dob (#660) — a band inversion and a false positive at confidence 90
//	corrupted out  cloudresources (#659) — an Azure resource type came back "" or as mojibake
//	silent misread driverslicense (#659) — the aside window read a digit of the value itself
//
// internal/bytefold exists precisely for this job and is byte-position preserving. This test asserts
// nothing in production code still reaches for strings.ToLower where the result will be indexed.
//
// # Why the AST and not a grep
//
// Three times in this repository a regexp guard matched its own explanatory comment — including the
// comment that quotes the defective call in order to explain it. So this walks the AST and looks only
// at real call expressions; comments are not part of the tree.
//
// A grep also cannot see the difference that matters. `strings.ToLower(x) == y` is fine: a comparison
// uses no offsets. `strings.Index(strings.ToLower(x), ...)` is the defect, because the returned index
// belongs to a string that no longer exists. The AST distinguishes them exactly.

// indexFuncs are the strings functions that RETURN A BYTE OFFSET. An offset is only meaningful in the
// string it was computed from, which is the whole bug.
var indexFuncs = map[string]bool{
	"Index":     true,
	"LastIndex": true,
	"IndexAny":  true,
	"IndexByte": true,
	"IndexRune": true,
}

func TestNoProductionCodeIndexesAToLoweredCopy(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	filesWalked, callsSeen := 0, 0

	for _, dir := range []string{"internal", "pkg", "cmd"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			filesWalked++
			fset := token.NewFileSet()
			// ParseFile without ParseComments: a comment cannot be a call expression, and this test's
			// own predecessors were satisfied by comments quoting the defect.
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Errorf("parsing %s: %v", path, perr)
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				callsSeen++
				if !isStringsCall(call, indexFuncs) {
					return true
				}
				// The HAYSTACK — the first argument — is what the returned offset belongs to.
				if len(call.Args) == 0 {
					return true
				}
				inner, ok := call.Args[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				if isStringsCall(inner, map[string]bool{"ToLower": true, "ToUpper": true}) {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders,
						rel+":"+itoa(fset.Position(call.Pos()).Line))
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}

	// NON-VACUITY. A walk that found no files, or a parser that silently failed, would report a clean
	// tree. Both numbers are floors rather than snapshots.
	if filesWalked < 200 {
		t.Fatalf("only %d production .go files were walked; the tree has far more, so this guard is "+
			"asserting almost nothing", filesWalked)
	}
	if callsSeen < 5000 {
		t.Fatalf("only %d call expressions were inspected across %d files; the AST walk is not "+
			"descending properly", callsSeen, filesWalked)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d production site(s) take a byte offset from a case-folded copy and will apply it "+
			"to the original:\n  %s\n\n"+
			"strings.ToLower/ToUpper do not preserve byte length — 25 runes shrink and 2 grow under "+
			"ToLower — so a length-changing rune before the match shifts the offset. This class has "+
			"produced four shipped bugs: two panics that made a whole file report 0 findings (#658), "+
			"and two silent misreads, one of them a false positive at confidence 90 (#660).\n\n"+
			"Use internal/bytefold.Lower, which preserves every byte position. If the offset is genuinely "+
			"never applied to another string, restructure so that is visible — the point of this guard "+
			"is that the dangerous shape should not appear at all.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
	t.Logf("walked %d production files, inspected %d calls, 0 offenders", filesWalked, callsSeen)
}

// TestTheGuardCatchesThePlantedShapes is the control, and it is not optional: the assertion above is a
// search that finds nothing when the tree is clean, so a broken matcher is indistinguishable from
// success.
func TestTheGuardCatchesThePlantedShapes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "the cloudresources shape",
			src:  `package p; import "strings"; func f(a, b string) int { return strings.Index(strings.ToLower(a), strings.ToLower(b)) }`,
			want: true,
		},
		{
			name: "LastIndex counts too",
			src:  `package p; import "strings"; func f(a, b string) int { return strings.LastIndex(strings.ToLower(a), b) }`,
			want: true,
		},
		{
			name: "ToUpper is the same defect",
			src:  `package p; import "strings"; func f(a, b string) int { return strings.Index(strings.ToUpper(a), b) }`,
			want: true,
		},
		{
			name: "a folded NEEDLE alone is fine",
			src:  `package p; import "strings"; func f(a, b string) int { return strings.Index(a, strings.ToLower(b)) }`,
			want: false,
		},
		{
			name: "a comparison uses no offset",
			src:  `package p; import "strings"; func f(a, b string) bool { return strings.ToLower(a) == strings.ToLower(b) }`,
			want: false,
		},
		{
			name: "Contains returns no offset",
			src:  `package p; import "strings"; func f(a, b string) bool { return strings.Contains(strings.ToLower(a), b) }`,
			want: false,
		},
		{
			name: "bytefold is the fix, not the defect",
			src:  `package p; import ("strings"; "x/internal/bytefold"); func f(a, b string) int { return strings.Index(bytefold.Lower(a), b) }`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "p.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parsing the fixture: %v", err)
			}
			found := false
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isStringsCall(call, indexFuncs) || len(call.Args) == 0 {
					return true
				}
				if inner, ok := call.Args[0].(*ast.CallExpr); ok {
					if isStringsCall(inner, map[string]bool{"ToLower": true, "ToUpper": true}) {
						found = true
					}
				}
				return true
			})
			if found != tc.want {
				t.Errorf("detected=%v want=%v for: %s", found, tc.want, tc.src)
			}
		})
	}
}

// isStringsCall reports whether call is strings.<one of names>(...).
func isStringsCall(call *ast.CallExpr, names map[string]bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "strings" {
		return false
	}
	return names[sel.Sel.Name]
}

// repoRoot walks up to the directory holding go.mod.
//
// Not filepath.Abs("..") — a previous guard in this repository resolved its root that way from a nested
// package, landed one level short, and walked 1 site instead of 3 while reporting success.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("no go.mod found above %s; the guard cannot locate the tree to walk", dir)
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
