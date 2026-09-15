package preprocessors

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

// Every production strings.ToValidUTF8 call must SUBSTITUTE, never delete.
//
// The deleting form — ToValidUTF8(s, "") — silently removes each invalid byte, and for a
// legacy single-byte file (Windows-125x, ISO-8859-x) EVERY non-ASCII byte is invalid UTF-8.
// "Employee José García" became "Employee Jos Garca": the accented bytes were dropped, the
// name no longer matched PERSON_NAME, and nothing anywhere reported that content had been
// discarded. Under the sink rule an undetected value is a cleartext value, so a deletion
// here is a leak, not a cosmetic defect.
//
// This is a GUARD, not a restatement of the fix. The module had three production call sites
// when this was written and two of them — cmd/stdin.go and pkg/redact/engine.go — already
// passed U+FFFD. Only the plaintext preprocessor deleted. So the bug was never a considered
// design choice; it was one site drifting from the other two, which is exactly the kind of
// divergence a reviewer reading one file cannot see.
//
// PARSED, not grepped. The first cut of this test was a regexp, and it failed immediately on
// the two COMMENTS above and in encoding.go that quote the defective call in order to explain
// it — prose describing the bug read as the bug. Comment-blindness has bitten a guard in this
// repo before (a goroutine test was satisfied by the word "recover()" inside the very comment
// explaining why a recover was needed). An AST walk cannot make that mistake: a comment is
// not a CallExpr and a quoted example is not an argument, so the guard sees only real calls
// and this file may describe the defect as plainly as it likes.
//
// A non-empty replacement is required rather than specifically U+FFFD: "?" (used by a JFIF
// test helper) is equally position-safe, and the property that matters is that the byte
// leaves a trace. What must never come back is the empty string.
func TestNoProductionCodeDeletesInvalidUTF8(t *testing.T) {
	root := moduleRoot(t)

	var checked, sites int
	fset := token.NewFileSet()

	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if n := info.Name(); n == "vendor" || n == "node_modules" || n == ".git" || n == "build" || n == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		// Tests may legitimately build the deleting form to pin the old behaviour.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, 0) // 0: drop comments entirely
		if parseErr != nil {
			// A file this module cannot parse is a separate problem; do not mask it.
			t.Errorf("%s: parse: %v", path, parseErr)
			return nil
		}
		checked++

		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ToValidUTF8" || len(call.Args) != 2 {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "strings" {
				return true
			}
			sites++

			lit, ok := call.Args[1].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				// A non-literal replacement (variable, const) cannot be judged here.
				// Report it rather than pass silently — it defeats this guard.
				t.Errorf("%s: strings.ToValidUTF8 replacement is not a string literal, so this "+
					"guard cannot tell whether it deletes; inline a literal or exempt it here",
					rel(root, fset.Position(call.Pos())))
				return true
			}
			repl, unqErr := strconv.Unquote(lit.Value)
			if unqErr != nil {
				t.Errorf("%s: unquoting the replacement %s: %v",
					rel(root, fset.Position(call.Pos())), lit.Value, unqErr)
				return true
			}
			if repl == "" {
				t.Errorf("%s: strings.ToValidUTF8 with an EMPTY replacement deletes every "+
					"invalid byte.\n"+
					"  For a legacy single-byte file that is every non-ASCII byte, so values are\n"+
					"  silently mangled out of detection — a leak under the sink rule.\n"+
					"  Pass \"\\uFFFD\" (as cmd/stdin.go and pkg/redact/engine.go already do).",
					rel(root, fset.Position(call.Pos())))
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking the module: %v", walkErr)
	}

	// Non-vacuity. A walk that reached nothing, or a selector match that stopped resolving,
	// would make this test pass by seeing no calls at all. Three production sites existed when
	// this was written; the floor is set below that so a legitimate refactor does not trip it,
	// but a silently-broken matcher does.
	if checked < 50 {
		t.Errorf("only %d non-test .go files parsed; the walk is not reaching the module", checked)
	}
	if sites < 3 {
		t.Errorf("matched %d strings.ToValidUTF8 call sites, want >= 3 — the matcher has stopped "+
			"resolving real calls, so this guard is asserting nothing", sites)
	}
	t.Logf("%d non-test files parsed, %d strings.ToValidUTF8 call sites checked", checked, sites)
}

// moduleRoot walks up from the test's own directory to the directory holding go.mod.
//
// Found rather than hardcoded because the first cut used filepath.Abs("..") — which from
// internal/preprocessors is internal/, NOT the module root. cmd/stdin.go and
// pkg/redact/engine.go sat outside the walk, so the guard saw ONE call site instead of three
// and would have missed a deleting call reintroduced in either of them. Only the sites >= 3
// floor below revealed it; without that floor this test would have passed while guarding a
// third of what it claims to. A relative ".." is a silent dependency on where the test file
// lives, so it is worth not having one.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found above %s; cannot locate the module root", dir)
		}
		dir = parent
	}
}

// rel shortens a position to a module-relative path so failures are clickable and stable
// across machines (an absolute path in a CI log names the runner's checkout directory).
func rel(root string, pos token.Position) string {
	if r, err := filepath.Rel(root, pos.Filename); err == nil {
		return r + ":" + strconv.Itoa(pos.Line)
	}
	return pos.String()
}
