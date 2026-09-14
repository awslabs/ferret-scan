// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Structural guards for the two CLASSES behind #667, as opposed to the three instances.
//
// Each instance was fixable in a line. What made them recur is that nothing prevented the next one:
// any formatter could invent its own verdict, and any predicate could match a user's pattern as a raw
// substring. These two tests make the next instance a test failure instead of a bug report.

// A verdict a user reads must come from ONE resolver, so no output surface can invent its own.
//
// The #667 instance: internal/formatters/text/formatter.go printed the pre-commit block verdict
// whenever any match had Confidence >= 90, while the exit code was decided in internal/precommit from
// FERRET_PRECOMMIT_EXIT_ON. With EXIT_ON=none the tool therefore asserted the commit was stopped and
// exited 0.
//
// The class is wider than that one string: there are seven output formats, and any of them could
// decide a verdict locally. This guard pins the mechanism — the verdict TEXT exists as a literal in
// exactly one production file, the resolver — so a formatter that wants to say it must be handed it.
//
// Checked over STRING LITERALS via the AST, not over file text. The first cut grepped raw bytes and
// failed on the comments in cmd/main.go and both formatter files that quote the phrase in order to
// explain the defect: prose describing the bug read as the bug. That is the same comment-blindness
// that has caught a guard in this repository twice. Parsing with comments dropped means only what
// could actually be PRINTED counts, which is exactly the property being protected.
func TestOnlyTheResolverDeclaresTheBlockVerdict(t *testing.T) {
	root := moduleRootForGuard(t)

	// Assembled at runtime so this file does not contain the literal it forbids.
	needle := "commit blocked" + " for security"

	var holders []string
	parsed := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "vendor", "node_modules", ".git", "build", "testdata", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		// Production Go only: a test may quote the phrase to assert it.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed++
		if stringLiteralContains(t, path, needle) {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
			// ToSlash so the comparison below is one spelling on every platform: filepath.Rel
			// yields `internal\precommit\decision.go` on Windows, which would never equal the
			// forward-slash literal and made this guard fail there rather than on the property
			// it guards.
			holders = append(holders, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if parsed < 50 {
		t.Errorf("only %d production files parsed; the walk is not reaching the module", parsed)
	}

	const owner = "internal/precommit/decision.go"
	if len(holders) != 1 || holders[0] != owner {
		t.Errorf("the pre-commit block verdict must be a literal in exactly one place (%s), found it in %v.\n"+
			"  A second declaration is how #667 happened: the formatter decided the commit was "+
			"stopped from Confidence >= 90 while the exit code came from FERRET_PRECOMMIT_EXIT_ON, so "+
			"EXIT_ON=none printed the verdict and exited 0.\n"+
			"  If a formatter needs to say this, take it from precommit.Decision.Message via "+
			"FormatterOptions.PrecommitBlockMessage — do not re-derive it.", owner, holders)
	}
}

// stringLiteralContains reports whether any STRING LITERAL in the file at path contains needle.
func stringLiteralContains(t *testing.T, path, needle string) bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0) // 0: comments dropped entirely
	if err != nil {
		t.Errorf("%s: parse: %v", path, err)
		return false
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		unquoted, unqErr := strconv.Unquote(lit.Value)
		if unqErr != nil {
			unquoted = lit.Value // raw or malformed: use the token text so nothing is missed
		}
		if strings.Contains(unquoted, needle) {
			found = true
			return false
		}
		return true
	})
	return found
}

// A user-supplied path pattern must never be matched as a raw SUBSTRING.
//
// The #667 instance: isExcluded had an arm `strings.Contains(cleanPath, pattern)` alongside its glob
// arms, so `--exclude t` matched every path containing the letter "t" and the run scanned nothing at
// exit 0 with no warning. Any short typo did it.
//
// Parsed rather than grepped. A regexp over this source matches the prose above and the comments in
// isExcluded that explain what was removed — the same comment-blindness that has caught a guard in
// this repository before, where a test was satisfied by the very comment describing the defect. An
// AST walk sees calls, so this file and those comments can describe the bug as plainly as they like.
func TestNoUserPatternIsMatchedBySubstring(t *testing.T) {
	root := moduleRootForGuard(t)
	target := filepath.Join(root, "cmd", "main.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, target, nil, 0) // 0: comments dropped entirely
	if err != nil {
		t.Fatalf("parsing cmd/main.go: %v", err)
	}

	// The functions that decide whether a user's pattern matches a path. A new one added here is
	// covered by the same rule.
	patternDeciders := map[string]bool{
		"isExcluded":              true,
		"validateExcludePatterns": true,
		"excludedBy":              true,
		"recordExcluded":          true,
	}

	inspected := 0
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil || !patternDeciders[fd.Name.Name] {
			return true
		}
		inspected++
		ast.Inspect(fd.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "strings" {
				return true
			}
			switch sel.Sel.Name {
			case "Contains", "HasPrefix", "Index":
				// TrimSuffix and Split are fine — they normalise a pattern, they do not match it.
				pos := fset.Position(call.Pos())
				t.Errorf("%s:%d: %s uses strings.%s on a user-supplied pattern.\n"+
					"  A pattern must be matched with filepath.Match, against the whole path, the "+
					"base name, or a path SEGMENT. Substring matching is what made `--exclude t` "+
					"exclude every path containing a \"t\" and scan nothing at exit 0 (#667).\n"+
					"  If this is normalisation rather than matching, use strings.TrimSuffix or "+
					"strings.Split, which this guard permits.",
					filepath.Base(pos.Filename), pos.Line, fd.Name.Name, sel.Sel.Name)
			}
			return true
		})
		return false
	})

	// Non-vacuity: the functions must actually have been found. A rename would otherwise make this
	// guard pass by inspecting nothing.
	if inspected < 3 {
		t.Errorf("only %d of the %d pattern-deciding functions were found in cmd/main.go; the guard "+
			"is inspecting almost nothing. Update patternDeciders after a rename.",
			inspected, len(patternDeciders))
	}
	t.Logf("%d pattern-deciding functions inspected", inspected)
}

// moduleRootForGuard finds the directory holding go.mod by walking up from the test's directory.
//
// Found rather than hardcoded as "..": a relative parent is a silent dependency on where the test
// file lives, and getting it wrong makes a guard walk the wrong subtree and pass by seeing nothing.
func moduleRootForGuard(t *testing.T) string {
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
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// A run that BLOCKS the commit must say so, in every output format.
//
// The fourth instance of #667's class, and the inverse of the reported one: there the tool printed
// "commit blocked" and exited 0; here it exits 1 and prints NOTHING. The confidence filter narrows the
// report while the exit policy judges the unfiltered match set, so a finding inside the blocking policy
// but outside the display filter rejects a developer's commit with no file named, no finding named, and
// zero bytes on stdout and stderr.
//
// Reachable with one documented environment variable and no other flags, because pre-commit mode
// auto-applies the built-in `precommit` profile whose ConfidenceLevels is "high,medium". Measured on
// the parent commit, with a file holding two LOW findings:
//
//	FERRET_PRECOMMIT_EXIT_ON=none    rc 0   stdout 0   stderr 0
//	FERRET_PRECOMMIT_EXIT_ON=high    rc 0   stdout 0   stderr 0
//	FERRET_PRECOMMIT_EXIT_ON=medium  rc 0   stdout 0   stderr 0
//	FERRET_PRECOMMIT_EXIT_ON=low     rc 1   stdout 0   stderr 0   <- blocks, discloses nothing
//
// The blocking run was byte-identical to a clean pass on both streams; only the exit code differed.
// junit, sarif and gitlab-sast were worse than silent, emitting an affirmatively clean envelope
// (`failures="0"`, `results: []`) while the commit was rejected.
//
// All seven formats are asserted because the silence had four separate implementations (text, json,
// yaml, csv each decided it locally) and the structured three reached the same outcome through the
// filter instead. A per-format assertion is the only thing that would have caught that spread.
func TestABlockingRunAlwaysDisclosesWhy(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	// LOW-confidence findings only: inside EXIT_ON=low's blocking policy, outside the precommit
	// profile's "high,medium" display filter. That gap is the bug.
	fixture := filepath.Join(dir, "lowcand.txt")
	if err := os.WriteFile(fixture,
		[]byte("contact: a.person@example.org\nreach me at 555-0143\nnode ip 10.11.12.13\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	// Non-vacuity: the fixture must actually produce LOW-only findings, or every row below is
	// asserting about an empty scan.
	all := runCapture(t, bin, nil, "--file", fixture, "--config", os.DevNull, "--checks", "all",
		"--format", "json", "--limit", "0", "--confidence", "all")
	if !strings.Contains(all.stdout, "\"results\"") || strings.Contains(all.stdout, "\"results\": []") {
		t.Fatalf("fixture produced no findings at all; the rows below would be vacuous.\n%s",
			truncateForLog(all.stdout))
	}

	formats := []string{"text", "json", "yaml", "csv", "junit", "gitlab-sast", "sarif"}

	// BLOCKING: exit non-zero, and the output must name the finding.
	for _, format := range formats {
		t.Run("blocking/"+format, func(t *testing.T) {
			r := runCapture(t, bin, []string{"FERRET_PRECOMMIT_EXIT_ON=low"},
				"--file", fixture, "--config", os.DevNull, "--pre-commit-mode",
				"--format", format, "--limit", "0")
			if r.code == 0 {
				t.Fatalf("EXIT_ON=low did not block on a LOW finding (rc 0); this row cannot test "+
					"disclosure. stdout: %s", truncateForLog(r.stdout))
			}
			combined := r.stdout + r.stderr
			if strings.TrimSpace(combined) == "" {
				t.Fatalf("the run BLOCKED (rc %d) and printed nothing on either stream. A developer's "+
					"commit is rejected with no file named and no finding named.", r.code)
			}
			// Naming the finding, not merely producing bytes: an affirmatively clean envelope is
			// worse than silence, because it asserts the opposite of the exit code.
			named := strings.Contains(combined, "lowcand") ||
				strings.Contains(combined, "BUSINESS") ||
				strings.Contains(combined, "PHONE") ||
				strings.Contains(combined, "IP_ADDRESS")
			if !named {
				t.Errorf("the run BLOCKED (rc %d) and its %s output names no finding and no file.\n"+
					"  junit/sarif/gitlab-sast previously emitted failures=\"0\" and results: [] here, "+
					"which asserts the run was clean while the commit was rejected.\n  output: %s",
					r.code, format, truncateForLog(combined))
			}
		})
	}

	// THE CONVERSE: a non-blocking run must stay quiet, or pre-commit mode becomes noise on every
	// commit and gets switched off — which costs exactly the disclosures this test exists to add.
	for _, policy := range []string{"none", "high"} {
		t.Run("not-blocking/"+policy, func(t *testing.T) {
			r := runCapture(t, bin, []string{"FERRET_PRECOMMIT_EXIT_ON=" + policy},
				"--file", fixture, "--config", os.DevNull, "--pre-commit-mode")
			if r.code != 0 {
				t.Fatalf("EXIT_ON=%s blocked on a LOW-only file (rc %d); this row cannot test the "+
					"converse", policy, r.code)
			}
			if strings.TrimSpace(r.stdout) != "" {
				t.Errorf("a non-blocking pre-commit run printed %d bytes; silence on a clean commit "+
					"is deliberate noise reduction and must be preserved.\n  output: %s",
					len(r.stdout), truncateForLog(r.stdout))
			}
		})
	}

	// And --confidence still narrows an ORDINARY run: the widening applies only when blocking.
	t.Run("confidence-filter-still-narrows", func(t *testing.T) {
		r := runCapture(t, bin, nil, "--file", fixture, "--config", os.DevNull, "--checks", "all",
			"--format", "json", "--limit", "0", "--confidence", "high")
		if !strings.Contains(r.stdout, "\"results\": []") {
			t.Errorf("--confidence high on a LOW-only file should report no results; widening must "+
				"apply only to a blocking run, or the flag stops meaning what it says.\n  output: %s",
				truncateForLog(r.stdout))
		}
	})
}

type captured struct {
	stdout string
	stderr string
	code   int
}

func runCapture(t *testing.T, bin string, env []string, args ...string) captured {
	t.Helper()
	cmd := exec.Command(bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("running scanner: %v", err)
		}
	}
	return captured{stdout: out.String(), stderr: errBuf.String(), code: code}
}
