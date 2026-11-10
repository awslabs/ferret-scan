// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
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

// The gate for #943: a comma-list flag given twice must mean both values, exactly as the comma form
// does. These flags were flag.String, which keeps the last occurrence and says nothing, so
// `--exclude '.git/**' --exclude 'build/**'` excluded build/ only and the scan walked .git/.

// commaListFlags are the flags whose value is split on commas. A repeat of any of them appends.
var commaListFlags = []string{"checks", "confidence", "disable-ip-types", "exclude", "validator-budget"}

// TestCommaListFlagSetAppends checks the Set function the comma-list flags are registered with.
func TestCommaListFlagSetAppends(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"-x", "a"}, "a"},
		{[]string{"-x", "a", "-x", "b"}, "a,b"},
		{[]string{"-x", "a,b", "-x", "c"}, "a,b,c"},
		{[]string{"-x=a", "--x", "b", "-x", "c"}, "a,b,c"},
		{[]string{"-x", "", "-x", "b"}, "b"},
		{[]string{"-x", "a", "-x", ""}, "a"},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("rlf", flag.ContinueOnError)
		got := new(string)
		fs.Func("x", "", appendCommaList(got))
		if err := fs.Parse(c.args); err != nil {
			t.Fatalf("parse %q: %v", c.args, err)
		}
		if *got != c.want {
			t.Errorf("%q gave %q, want %q", c.args, *got, c.want)
		}
	}
}

// TestEveryCommaListFlagIsRegisteredToAppend reads cmd/main.go's registrations, so a comma-list flag
// moved back to flag.String, or a new one added with it, fails here rather than in a user's scan.
func TestEveryCommaListFlagIsRegisteredToAppend(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}
	appending := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		nameLit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		name := strings.Trim(nameLit.Value, `"`)
		switch sel.Sel.Name {
		case "Func":
			usage, _ := renderUsage(call.Args[1])
			set, ok := call.Args[2].(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, isIdent := set.Fun.(*ast.Ident); isIdent && id.Name == "appendCommaList" {
				appending[name] = true
				if !strings.Contains(strings.ToLower(usage), "repeatable") {
					t.Errorf("--%s appends on repeat but its usage text does not say so: %q", name, usage)
				}
			}
		case "String":
			usage, _ := renderUsage(call.Args[2])
			if strings.Contains(strings.ToLower(usage), "comma-separated") {
				t.Errorf("--%s takes a comma-separated list but is a flag.String, so a repeat keeps "+
					"only the last value; register it with flag.Func(..., appendCommaList(...))", name)
			}
		}
		return true
	})
	for _, name := range commaListFlags {
		if !appending[name] {
			t.Errorf("--%s is a comma-list flag but is not registered with appendCommaList, so "+
				"`--%s a --%s b` would not mean `--%s a,b`", name, name, name, name)
		}
	}
}

// TestRepeatedListFlagMatchesCommaForm runs the binary both ways and requires the same scan.
func TestRepeatedListFlagMatchesCommaForm(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the scanner")
	}
	bin := buildScanner(t)
	dir := t.TempDir()
	tree := filepath.Join(dir, "tree")
	content := []byte("SSN: 452-11-9384\nContact: jane.roe@example.org\nServer: 192.0.2.10\n")
	for _, rel := range []string{"keep.txt", ".git/logs/HEAD.txt", "build/out.txt"} {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := isolatedEnv(t, dir)
	base := []string{"--file", ".", "--recursive", "--config", os.DevNull, "--format", "json", "--quiet", "--limit", "0"}

	cases := []struct {
		name     string
		repeated []string
		comma    []string
	}{
		{"exclude", []string{"--exclude", ".git/**", "--exclude", "build/**"}, []string{"--exclude", ".git/**,build/**"}},
		{"checks", []string{"--checks", "SSN", "--checks", "EMAIL"}, []string{"--checks", "SSN,EMAIL"}},
		{"confidence", []string{"--confidence", "high", "--confidence", "medium"}, []string{"--confidence", "high,medium"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := runCLI(t, bin, tree, env, "", append(append([]string{}, base...), c.repeated...)...)
			com := runCLI(t, bin, tree, env, "", append(append([]string{}, base...), c.comma...)...)
			if rep.rc != com.rc {
				t.Fatalf("exit codes differ: repeated %d, comma %d\nrepeated stderr: %s\ncomma stderr: %s",
					rep.rc, com.rc, rep.stderr, com.stderr)
			}
			got, want := rlfView(t, rep.stdout), rlfView(t, com.stdout)
			if strings.HasSuffix(want, "findings=") {
				t.Fatalf("the comma form found nothing, so the fixture is not exercising --%s:\n%s", c.name, com.stdout)
			}
			if got != want {
				t.Errorf("%q and %q scanned differently:\nrepeated: %s\ncomma:    %s", c.repeated, c.comma, got, want)
			}
		})
	}

	// The comparison alone would pass if both forms were equally broken, so pin the exclude result.
	r := runCLI(t, bin, tree, env, "", append(append([]string{}, base...), "--exclude", ".git/**", "--exclude", "build/**")...)
	if view := rlfView(t, r.stdout); !strings.HasPrefix(view, "processed=1 files=[keep.txt]") {
		t.Errorf("--exclude .git/** --exclude build/** should leave keep.txt only; got %s", view)
	}
}

// rlfView reduces a JSON report to what the flags decide: how many files were scanned, which files
// had findings, and the type and level of every finding.
func rlfView(t *testing.T, stdout string) string {
	t.Helper()
	var rep struct {
		Stats struct {
			FilesProcessed int `json:"files_processed"`
		} `json:"stats"`
		Results []struct {
			Filename string `json:"filename"`
			Type     string `json:"type"`
			Level    string `json:"confidence_level"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decoding the JSON report: %v\n%s", err, stdout)
	}
	files := map[string]bool{}
	var findings []string
	for _, r := range rep.Results {
		files[filepath.ToSlash(r.Filename)] = true
		findings = append(findings, filepath.ToSlash(r.Filename)+":"+r.Type+":"+r.Level)
	}
	var names []string
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)
	sort.Strings(findings)
	return "processed=" + strconv.Itoa(rep.Stats.FilesProcessed) + " files=[" + strings.Join(names, " ") + "] findings=" + strings.Join(findings, ",")
}
