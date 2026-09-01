// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #564: #556 removed the non-existent `scan` subcommand from 88 shell command lines and #559 added a
// guard. Eight sites survived, because they express the invocation as an ARGUMENT ARRAY rather than a
// shell command line, and the #559 regex only recognises the latter:
//
//	"args": ["scan", ".", "--debug"]                                   launch.json
//	$args = @("scan", $Path, "--format", $Format)                        PowerShell array
//	-ArgumentList "scan", ".", "--format", "json"                        Start-Process
//	$commands = @('scan', 'web', '--help', ...)                          tab completion
//	args: ['--file', '--confidence', 'high,medium', ...]                 pre-commit YAML
//
// The last one is the same defect reached a different way: `--file` takes a value, so with no value it
// consumes `--confidence`, and from there every remaining flag becomes a positional path. Measured on
// the documented line verbatim: four `Error processing ...` lines and **exit 0**, with
// `--confidence`, `--format` and `--quiet` all silently ignored.
//
// So this guard checks argument LISTS for the two shapes that silently lose flags: a leading token
// that is not a flag, and a value-taking flag with no value after it.
//
// Identifiers are prefixed `arr` to stay distinct from cmd/documented_invocations_test.go (#559) and
// cmd/documented_flag_values_test.go — three guards now live in this package, and duplicate top-level
// names merge cleanly then fail to compile.

// arrDocsDir is the documentation tree relative to this package.
const arrDocsDir = "../docs"

// arrListForms are the ways this documentation expresses an argument list. Each captures the list body.
//
// Deliberately anchored on the ARGUMENT-LIST syntax rather than on the word "scan", because a JSON key
// happens to be named "scan" too: the gitlab-sast report schema has a top-level `"scan": {` object,
// documented in COVERAGE_DISCLOSURE.md and GITLAB_INTEGRATION.md. Matching the verb instead of the
// syntax would flag those, and a guard that fires on correct documentation gets disabled.
var arrListForms = []*regexp.Regexp{
	regexp.MustCompile(`"args"\s*:\s*\[([^\]]*)\]`),    // launch.json / tasks.json
	regexp.MustCompile(`(?m)^\s*args:\s*\[([^\]]*)\]`), // YAML inline list
	regexp.MustCompile(`\$args\s*=\s*@\(([^)]*)\)`),    // PowerShell array
	regexp.MustCompile(`-ArgumentList\s+([^|;&\n]*)`),  // Start-Process
}

// arrValueTakingFlags are flags that REQUIRE a value. A list ending at one, or following it with
// another flag, silently loses everything after it.
//
// Read from the binary's own registrations rather than restated, so the set cannot drift: a flag that
// stops taking a value stops being checked, and a new one starts being checked, without an edit here.
func arrValueTakingFlags(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	reg := regexp.MustCompile(`flag\.(String|Int|Int64|Uint|Uint64|Float64|Duration)\("([a-z0-9-]+)"`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- a file in this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range reg.FindAllStringSubmatch(string(raw), -1) {
			out[m[2]] = true
		}
	}
	if len(out) < 5 {
		t.Fatalf("found only %d value-taking flags in this package; the registration regex has "+
			"stopped matching, so every assertion below would pass vacuously", len(out))
	}
	return out
}

// arrTokens splits a captured list body into its elements, stripping quotes and whitespace.
func arrTokens(body string) []string {
	var out []string
	for _, raw := range strings.Split(body, ",") {
		tok := strings.TrimSpace(raw)
		tok = strings.Trim(tok, `\'"`)
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

type arrProblem struct {
	line int
	kind string
	text string
}

// arrScanDocs returns, per doc file, the argument lists that silently lose flags.
func arrScanDocs(t *testing.T) (map[string][]arrProblem, int) {
	t.Helper()
	needsValue := arrValueTakingFlags(t)
	out := map[string][]arrProblem{}
	total := 0
	err := filepath.WalkDir(arrDocsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "proposals" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a markdown file inside the repo's docs tree
		if err != nil {
			return err
		}
		rel := "docs/" + strings.TrimPrefix(filepath.ToSlash(path), "../docs/")
		for i, line := range strings.Split(string(raw), "\n") {
			for _, re := range arrListForms {
				for _, m := range re.FindAllStringSubmatch(line, -1) {
					toks := arrTokens(m[1])
					if len(toks) == 0 {
						continue
					}
					total++
					// Shape 1: a leading token that is not a flag, AND a flag after it. `scan`,
					// `web` — a subcommand this tool does not have, taken as the path, with every
					// later flag dropped.
					//
					// The "and a flag after it" half is load-bearing: `args: ["/data"]` in the
					// Docker guide is a bare positional with nothing following, so nothing is
					// dropped and it is correct usage. Flagging it would make this guard fire on
					// working documentation, and a guard that does that gets disabled.
					if !strings.HasPrefix(toks[0], "-") {
						if arrHasFlagAfter(toks, 0) {
							out[rel] = append(out[rel], arrProblem{i + 1, "leading non-flag " + toks[0] + " precedes a flag", strings.TrimSpace(line)})
						}
						continue
					}
					// Shape 2: a value-taking flag with no value. The next token is another flag,
					// or the list ends.
					for j, tok := range toks {
						name := strings.TrimLeft(tok, "-")
						if !strings.HasPrefix(tok, "-") || !needsValue[name] {
							continue
						}
						if j+1 >= len(toks) {
							out[rel] = append(out[rel], arrProblem{i + 1, tok + " ends the list with no value", strings.TrimSpace(line)})
						} else if strings.HasPrefix(toks[j+1], "-") {
							out[rel] = append(out[rel], arrProblem{i + 1, tok + " is followed by " + toks[j+1] + ", not a value", strings.TrimSpace(line)})
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", arrDocsDir, err)
	}
	return out, total
}

// TestNoDocumentedArgArrayLosesItsFlags is the regression guard for #564.
func TestNoDocumentedArgArrayLosesItsFlags(t *testing.T) {
	bad, total := arrScanDocs(t)

	// Non-vacuity: the extraction must find real argument lists, or a broken regex reports a clean
	// tree. There are well over a dozen across the pre-commit, Docker and Windows guides.
	if total < 10 {
		t.Fatalf("found only %d argument lists across %s; the list-form regexes have stopped "+
			"matching, so every assertion below would pass vacuously", total, arrDocsDir)
	}

	for rel, problems := range bad {
		var detail []string
		for _, p := range problems {
			detail = append(detail, fmt.Sprintf("line %d: %s", p.line, p.kind))
		}
		t.Errorf("%s documents %d argument list(s) that silently lose flags: %s\n"+
			"Flag parsing stops at the first non-flag argument, and a value-taking flag with no "+
			"value swallows whatever follows it. Either way the command still exits 0.\n"+
			"Write the path as a flag value (`--file <path>`) and give every value-taking flag a "+
			"value.", rel, len(problems), strings.Join(detail, "; "))
	}
}

// TestTheArgArrayGuardCatchesThePlantedShapes proves the guard is not inert and pins the boundary
// against the JSON key that is legitimately named "scan".
func TestTheArgArrayGuardCatchesThePlantedShapes(t *testing.T) {
	needsValue := arrValueTakingFlags(t)

	check := func(line string) (fired bool) {
		for _, re := range arrListForms {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				toks := arrTokens(m[1])
				if len(toks) == 0 {
					continue
				}
				if !strings.HasPrefix(toks[0], "-") {
					if arrHasFlagAfter(toks, 0) {
						return true
					}
					continue
				}
				for j, tok := range toks {
					name := strings.TrimLeft(tok, "-")
					if !strings.HasPrefix(tok, "-") || !needsValue[name] {
						continue
					}
					if j+1 >= len(toks) || strings.HasPrefix(toks[j+1], "-") {
						return true
					}
				}
			}
		}
		return false
	}

	for _, tc := range []struct {
		name string
		line string
		want bool
	}{
		// The eight shapes #564 is about.
		{"launch.json scan", `"args": ["scan", ".", "--debug"],`, true},
		{"launch.json web", `"args": ["web", "--port", "8080"],`, true},
		{"powershell array", `    $args = @("scan", $Path, "--format", $Format)`, true},
		{"ArgumentList scan", `Start-Process ferret-scan -ArgumentList "scan", ".", "--format", "json"`, true},
		{"yaml valueless --file", `        args: ['--file', '--confidence', 'high,medium']`, true},
		{"value-taking flag ends the list", `        args: ["--format"]`, true},

		// Correct forms must NOT fire.
		{"launch.json corrected", `"args": ["--file", ".", "--recursive", "--debug"],`, false},
		{"web flag", `"args": ["--web", "--port", "8080"],`, false},
		{"yaml corrected", `        args: ['--confidence', 'high,medium', '--format', 'text', '--quiet']`, false},
		{"bare boolean flags", `        args: [--pre-commit-mode, --respect-gitignore]`, false},
		{"docker positional data dir", `        args: ["/data"]`, false},

		// The boundary that matters: a JSON KEY named "scan" is not an argument list. Matching the
		// verb rather than the list syntax would flag these two real, correct documents.
		{"gitlab report schema key", `"scan": {`, false},
		{"gitlab report schema key indented", `  "scan": {`, false},
		{"jq over the report", `jq 'has("version") and has("vulnerabilities") and has("scan")' r.json`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := check(tc.line); got != tc.want {
				t.Errorf("line %q: guard fired=%v, want %v", tc.line, got, tc.want)
			}
		})
	}
}

// arrHasFlagAfter reports whether any token after index i starts with "-".
//
// This is what separates a positional that LOSES something from one that does not: flag parsing stops
// at the first non-flag argument, so a positional is only a defect when a flag follows it.
func arrHasFlagAfter(toks []string, i int) bool {
	for _, tok := range toks[i+1:] {
		if strings.HasPrefix(tok, "-") {
			return true
		}
	}
	return false
}

// TestACompletionListOffersOnlyRealFlags covers the eighth #564 site, which is NOT an argument list:
// `$commands = @('scan', 'web', '--help', ...)` is a tab-completion candidate set, so its flags
// legitimately carry no values and the argument-list rules above do not apply. What must hold is that
// every candidate EXISTS — the original offered `scan` and `web`, two subcommands this tool has never
// had, so a user pressing Tab was handed them.
func TestACompletionListOffersOnlyRealFlags(t *testing.T) {
	registered := arrRegisteredFlags(t)
	listRe := regexp.MustCompile(`\$commands\s*=\s*@\(([^)]*)\)`)

	var checked int
	err := filepath.WalkDir(arrDocsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a markdown file inside the repo's docs tree
		if err != nil {
			return err
		}
		rel := "docs/" + strings.TrimPrefix(filepath.ToSlash(path), "../docs/")
		for i, line := range strings.Split(string(raw), "\n") {
			for _, m := range listRe.FindAllStringSubmatch(line, -1) {
				for _, tok := range arrTokens(m[1]) {
					checked++
					name := strings.TrimLeft(tok, "-")
					if !strings.HasPrefix(tok, "-") {
						t.Errorf("%s:%d offers %q as a completion candidate, but this tool has no "+
							"subcommands — every candidate must be a flag. A user pressing Tab is "+
							"handed a word that makes the tool stat a path of that name and ignore "+
							"every flag after it.", rel, i+1, tok)
						continue
					}
					if !registered[name] {
						t.Errorf("%s:%d offers the flag %q, which the binary does not register.",
							rel, i+1, tok)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", arrDocsDir, err)
	}
	if checked == 0 {
		t.Fatal("no completion candidates found, so this test asserted nothing; if the completion " +
			"example was deleted, delete this test with it")
	}
}

// arrRegisteredFlags returns every flag name this package registers, of any type.
func arrRegisteredFlags(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	reg := regexp.MustCompile(`flag\.(Bool|String|Int|Int64|Uint|Uint64|Float64|Duration|Var|Func)\("([a-z0-9-]+)"`)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- a file in this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range reg.FindAllStringSubmatch(string(raw), -1) {
			out[m[2]] = true
		}
	}
	// "help" is handled by the flag package itself rather than registered here.
	out["help"] = true
	if len(out) < 20 {
		t.Fatalf("found only %d registered flags; the registration regex has stopped matching, so "+
			"this test would accept anything", len(out))
	}
	return out
}
