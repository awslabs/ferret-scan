// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every reason CanProcessFile can return must be deliberately assigned a LEDGER BUCKET.
//
// # What went wrong without this
//
// The bucket — files_skipped ("deliberately out of scope") versus files_not_examined ("we could not
// examine this", which feeds --fail-on-incomplete and SARIF toolExecutionNotifications) — was decided
// in cmd by `strings.HasPrefix(reason, ReasonUnreadable)`, and everything unmatched fell through to
// files_skipped. So the DEFAULT for a reason added later was "pretend the user asked for this".
//
// A .env holding API_KEY=abc123 with one NUL byte came back "Unsupported file type" and was counted
// as scope, and --fail-on-incomplete — the flag whose only job is to report incomplete coverage —
// exited 0 on a top-value target the tool never scanned (#667).
//
// # Two halves, because either alone is insufficient
//
// TestEveryRouterReasonHasABucket walks the SOURCE of CanProcessFile and requires every reason it can
// return to be named in the table below. That is what catches a reason added in future: a behavioural
// test only covers the reasons its fixtures happen to trigger, and the whole failure mode here is a
// reason nobody thought to trigger.
//
// TestReasonBucketsMatchRealFiles then drives real files through the router and checks the table
// describes what actually happens — because a table that agrees with itself proves nothing.
var reasonBuckets = map[string]struct {
	coverageLoss bool
	why          string
}{
	"Text file": {false, "processed, not refused at all"},
	"Binary document": {false,
		"processed through a preprocessor"},
	"Binary document (requires preprocessors)": {false,
		"the caller disabled preprocessors, so this is the scope they asked for"},
	"Unsupported file type": {false,
		"no handler for this type; nobody expected a result from it"},
	"File too large (max: %dMB)": {false,
		"a bound the caller set. NOTE: an oversize file the tool COULD have processed is routed " +
			"to the unexamined ledger at DISCOVERY time via CanProcessType, so the coverage loss " +
			"is disclosed there rather than here"},
	ReasonUnreadable: {true,
		"the file could not be read at all — permissions, a dangling link, a non-regular file"},
	ReasonRefusedNotText: {true,
		"the file WAS read and IS text, and the tool declined it anyway. This is the #667 case: " +
			"a coverage loss that used to be reported as an unsupported type"},
}

func TestEveryRouterReasonHasABucket(t *testing.T) {
	fset := token.NewFileSet()
	src, err := os.ReadFile("file_router.go")
	if err != nil {
		t.Fatalf("reading router source: %v", err)
	}
	f, err := parser.ParseFile(fset, "file_router.go", src, 0)
	if err != nil {
		t.Fatalf("parsing router source: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if ok && fd.Name.Name == "CanProcessFile" {
			fn = fd
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("CanProcessFile not found in file_router.go — this guard is asserting nothing")
	}

	// Collect the reason expression of every return in the function: the SECOND result.
	var reasons []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 2 {
			return true
		}
		reasons = append(reasons, reasonTextOf(ret.Results[1]))
		return true
	})

	if len(reasons) < 5 {
		t.Errorf("only %d returns found in CanProcessFile; the walk is not reaching its body, so "+
			"this guard would pass on any new reason", len(reasons))
	}

	for _, r := range reasons {
		if r == "" {
			t.Errorf("a return in CanProcessFile yields a reason this guard cannot read statically. " +
				"Give it a named constant or a literal so the bucket can be reviewed, or the ledger " +
				"decision for it is unreviewable")
			continue
		}
		if _, known := reasonBuckets[r]; !known {
			t.Errorf("CanProcessFile can return the reason %q, and reasonBuckets does not say which "+
				"LEDGER it belongs in.\n"+
				"  Decide explicitly: is this a coverage LOSS (the tool tried and could not — goes to "+
				"files_not_examined, trips --fail-on-incomplete, appears in SARIF) or SCOPE (nobody "+
				"expected a result — files_skipped)?\n"+
				"  Then add it here AND to RefusalIsCoverageLoss. Falling through to skip is how a "+
				".env full of secrets was reported as an unsupported type at exit 0 (#667).", r)
			continue
		}
		want := reasonBuckets[r].coverageLoss
		if got := RefusalIsCoverageLoss(r); got != want {
			t.Errorf("RefusalIsCoverageLoss(%q) = %v, table says %v (%s)",
				r, got, want, reasonBuckets[r].why)
		}
	}
	t.Logf("%d reason returns in CanProcessFile, all bucketed", len(reasons))
}

// reasonTextOf renders a reason expression as the string the table keys on.
//
// Handles the three shapes the router uses: a bare literal, a named constant, and a
// fmt.Sprintf whose FORMAT is what identifies the reason (its arguments are per-file values).
func reasonTextOf(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			return strings.Trim(v.Value, `"`)
		}
	case *ast.Ident:
		switch v.Name {
		case "ReasonUnreadable":
			return ReasonUnreadable
		case "ReasonRefusedNotText":
			return ReasonRefusedNotText
		}
	case *ast.CallExpr:
		// fmt.Sprintf("...", ...) — the format string identifies the reason. A format built from
		// a constant prefix plus ": %v" is keyed by the constant, which is what
		// RefusalIsCoverageLoss matches on too.
		if len(v.Args) > 0 {
			if lit, ok := v.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				format := strings.Trim(lit.Value, `"`)
				// "%s: ..." with a Reason constant as the first argument.
				if strings.HasPrefix(format, "%s") && len(v.Args) > 1 {
					if id, ok := v.Args[1].(*ast.Ident); ok {
						switch id.Name {
						case "ReasonUnreadable":
							return ReasonUnreadable
						case "ReasonRefusedNotText":
							return ReasonRefusedNotText
						}
					}
				}
				return format
			}
		}
	}
	return ""
}

// TestReasonBucketsMatchRealFiles drives real files through the router so the table describes
// behaviour rather than itself.
func TestReasonBucketsMatchRealFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, content []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, mode); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return p
	}

	// A text file with a stray NUL: the #667 case. Long enough to clear the sniff's minimum and
	// mostly printable, which is what makes it text rather than binary.
	nulEnv := write(".env", []byte("API_KEY=abc123\x00binary\nSECRET=xyz\nDB=postgres://h/db\n"), 0o600)
	// A genuine binary: mostly NUL, which is what an executable's header region looks like.
	realBinary := write("blob.bin", append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 600)...), 0o600)
	plain := write("notes.txt", []byte("ordinary prose with no nul bytes\n"), 0o600)

	fr := NewFileRouter(false)

	cases := []struct {
		name             string
		path             string
		wantProcess      bool
		wantCoverageLoss bool
		why              string
	}{
		{"plain text", plain, true, false, "control: must be processed, or the others prove nothing"},
		{"text with a stray NUL", nulEnv, false, true,
			"THE #667 CASE: read fine, is text, declined anyway — a coverage LOSS, not scope"},
		{"genuine binary", realBinary, false, false,
			"CONTROL in the other direction: must stay a quiet skip, or --fail-on-incomplete " +
				"starts firing on every compiled artifact in a repository"},
	}
	for _, c := range cases {
		canProcess, reason := fr.CanProcessFile(c.path, false)
		if canProcess != c.wantProcess {
			t.Errorf("%s: canProcess=%v want %v (reason %q) — %s", c.name, canProcess, c.wantProcess, reason, c.why)
			continue
		}
		if canProcess {
			continue
		}
		if got := RefusalIsCoverageLoss(reason); got != c.wantCoverageLoss {
			t.Errorf("%s: reason %q classified coverageLoss=%v, want %v — %s",
				c.name, reason, got, c.wantCoverageLoss, c.why)
		}
	}
}
