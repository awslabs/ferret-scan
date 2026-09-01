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

// #555 turned up a second way a documented command can be unrunnable, and the existing flag guard is
// blind to it by construction.
//
//	docs/development/file-router-metadata-capabilities.md:340
//	  ferret-scan --file large_codebase/ --recursive --profile
//	  -> rc=2, `flag needs an argument: -profile`
//
// `--profile` IS registered, so TestDocumentedFlagsExist is satisfied — it only asks whether a flag
// exists. But a value-taking flag written with no value fails exactly as loudly as an absent one, at
// the same rc=2, with a message that again reads as the reader's mistake. Fixing the sibling
// `--dry-run` on line 337 while leaving this one would have left the block unfollowable with a green
// suite, which is the failure mode this family of guards exists to prevent.
//
// This guard closes that half: every value-taking flag advertised on a `ferret-scan` command line in
// docs/ must be given a value. It found one further instance the issue did not mention —
// docs/upstream-asks.md told the reader to "verify against `ferret-scan --checks`", which exits 2 with
// `flag needs an argument: -checks`; the real listing command is `ferret-scan --help checks`.
//
// Identifiers here are prefixed `dfv` and the command regex is duplicated rather than shared, matching
// the choice already made in cmd/documented_invocations_test.go: these guards are read one at a time,
// and a shared symbol makes each one harder to change without thinking about the others.

// dfvRegistration matches the standard-library registrations in cmd/*.go and captures the KIND as well
// as the name, because the kind is what says whether a value is required:
//
//	flag.Bool("no-color", false, "...")   -> no value needed
//	flag.String("profile", "", "...")     -> value required
//
// flag.Var and flag.Func are both value-taking in the standard library, so they group with String.
var dfvRegistration = regexp.MustCompile(`flag\.(String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Func)\("([a-zA-Z0-9_-]+)"`)

// dfvCommand finds a ferret-scan invocation and captures the rest of the command. Same boundary rules
// as the sibling guards: leading indentation allowed, whitespace required after the binary name so
// `ferret-scan-profile.exe` is excluded, capture stops at a shell separator.
var dfvCommand = regexp.MustCompile(`(?:^\s*|[$>]\s*|\|\s*|&&\s*|;\s*|` + "`" + `)(?:\./|\.\\)?ferret-scan(?:\.exe)?(?:[ \t]+([^|;&` + "`" + `]*)|\s*$)`)

// dfvDocsDir is the documentation tree relative to this package.
const dfvDocsDir = "../docs"

// dfvValueTakingFlags returns the registered flags that require a value, and the ones that do not.
func dfvValueTakingFlags(t *testing.T) (needsValue map[string]bool, registered map[string]bool) {
	t.Helper()
	needsValue = map[string]bool{}
	registered = map[string]bool{}
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
		for _, m := range dfvRegistration.FindAllStringSubmatch(string(raw), -1) {
			registered[m[2]] = true
			if m[1] != "Bool" {
				needsValue[m[2]] = true
			}
		}
	}
	// Non-vacuity: if the extraction breaks, nothing needs a value and every document passes.
	if len(needsValue) < 10 {
		t.Fatalf("only %d value-taking flag registrations found in cmd/*.go; the extraction regex has "+
			"stopped matching, which would make every assertion below pass vacuously", len(needsValue))
	}
	for _, must := range []string{"file", "checks", "confidence", "profile", "format"} {
		if !needsValue[must] {
			t.Fatalf("--%s is registered with flag.String and must be reported as value-taking; the "+
				"extractor is not reading registrations correctly", must)
		}
	}
	for _, must := range []string{"debug", "verbose", "recursive"} {
		if needsValue[must] {
			t.Fatalf("--%s is registered with flag.Bool and must NOT be reported as value-taking; the "+
				"extractor is treating booleans as needing an argument, which would report false "+
				"violations on correct documentation", must)
		}
	}
	return needsValue, registered
}

// dfvOffender is one advertised flag left without its value.
type dfvOffender struct {
	line int
	flag string
	text string
}

// dfvValueMissing reports whether the token following flag position i supplies a value.
//
// Two shapes are values even though they begin with a dash, and both appear in the tree:
//
//   - a bare `-`, which is how `--file -` asks for stdin (measured: rc=0, scans stdin);
//   - a trailing `\`, a shell line continuation, which means the value is on the next line and this
//     guard cannot see it — treated as supplied rather than guessed at.
func dfvValueMissing(tokens []string, i int) bool {
	if i+1 >= len(tokens) {
		return true
	}
	next := tokens[i+1]
	if next == "-" || next == `\` {
		return false
	}
	return strings.HasPrefix(next, "-")
}

// dfvScanDocs walks the documentation tree and returns, per file, the value-taking flags advertised
// with no value, plus how many ferret-scan command lines were examined.
func dfvScanDocs(t *testing.T, needsValue map[string]bool) (map[string][]dfvOffender, int) {
	t.Helper()
	out := map[string][]dfvOffender{}
	total := 0
	err := filepath.WalkDir(dfvDocsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Proposals describe designs that were never built, so a command there is a proposal.
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
			for _, m := range dfvCommand.FindAllStringSubmatch(line, -1) {
				total++
				tokens := strings.Fields(m[1])
				for j, tok := range tokens {
					if !strings.HasPrefix(tok, "--") || strings.Contains(tok, "=") {
						continue // --flag=value supplies its own value
					}
					name := strings.TrimPrefix(tok, "--")
					if !needsValue[name] {
						continue
					}
					if dfvValueMissing(tokens, j) {
						out[rel] = append(out[rel], dfvOffender{
							line: i + 1, flag: name, text: strings.TrimSpace(line),
						})
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dfvDocsDir, err)
	}
	return out, total
}

// TestDocumentedFlagsThatNeedAValueAreGivenOne is the regression guard for the second half of #555.
func TestDocumentedFlagsThatNeedAValueAreGivenOne(t *testing.T) {
	needsValue, _ := dfvValueTakingFlags(t)
	bad, total := dfvScanDocs(t, needsValue)

	// Non-vacuity: the extraction must find real command lines, or a broken regex reports a clean tree.
	if total < 100 {
		t.Fatalf("extracted only %d ferret-scan command lines across %s; the command regex has stopped "+
			"matching, so every assertion below would pass vacuously", total, dfvDocsDir)
	}

	for rel, offs := range bad {
		var detail []string
		for _, o := range offs {
			detail = append(detail, fmt.Sprintf("--%s (line %d): %q", o.flag, o.line, o.text))
		}
		t.Errorf("%s advertises %d value-taking flag(s) with no value: %s\n"+
			"The flag exists, so TestDocumentedFlagsExist passes — but the command still exits 2 with "+
			"`flag needs an argument`, and the reader cannot tell that from their own mistake. Supply "+
			"the value (`--profile debug`), or use the flag that actually does what the step wants.\n"+
			"A bare `-` and a trailing `\\` already count as values; if some other token should, widen "+
			"dfvValueMissing rather than the document.",
			rel, len(offs), strings.Join(detail, ", "))
	}
}

// TestTheValueGuardCatchesThePlantedShapes proves the guard is not inert and pins its boundaries.
//
// Every assertion above is over real files, so a silently broken extractor would leave the suite green
// while the tree rotted. The first case is #555's own line, verbatim.
func TestTheValueGuardCatchesThePlantedShapes(t *testing.T) {
	needsValue, _ := dfvValueTakingFlags(t)

	for _, tc := range []struct {
		name string
		line string
		want string // the flag that must be reported, "" for none
	}{
		{"the shape #555 documented", "ferret-scan --file large_codebase/ --recursive --profile", "profile"},
		{"value-taking flag last on the line", "ferret-scan --file x.txt --checks", "checks"},
		{"followed by another flag", "ferret-scan --confidence --verbose", "confidence"},
		{"inside backticks in prose", "Verify against `ferret-scan --checks` rather than this table", "checks"},
		// Must NOT fire: the value is supplied.
		{"value supplied", "ferret-scan --file x.txt --profile debug", ""},
		{"equals form", "ferret-scan --file=x.txt --profile=debug", ""},
		// Must NOT fire: `--file -` is how stdin is requested, and it works (rc=0).
		{"stdin dash", `echo "4111-1111-1111-1111" | ferret-scan --file -`, ""},
		// Must NOT fire: a shell continuation means the value is on the next line.
		{"line continuation", `ferret-scan --file x.txt \`, ""},
		// Must NOT fire: booleans take no value.
		{"boolean last", "ferret-scan --file x.txt --debug", ""},
		{"two booleans", "ferret-scan --file x.txt --debug --verbose", ""},
		// Must NOT fire: --help is a Bool, and `--help checks` is a real, working invocation (rc=0).
		{"help checks", "ferret-scan --help checks", ""},
		// Must NOT fire: an unregistered flag is TestDocumentedFlagsExist's business, not this one.
		{"absent flag", "ferret-scan --file x.txt --dry-run", ""},
		// Must NOT fire: another program's flags on a line that mentions ferret-scan.
		{"pre-commit hook id", "pre-commit run ferret-scan --all-files", ""},
		{"different binary", `.\ferret-scan-profile.exe scan . --cpuprofile`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var found []string
			for _, m := range dfvCommand.FindAllStringSubmatch(tc.line, -1) {
				tokens := strings.Fields(m[1])
				for j, tok := range tokens {
					if !strings.HasPrefix(tok, "--") || strings.Contains(tok, "=") {
						continue
					}
					name := strings.TrimPrefix(tok, "--")
					if needsValue[name] && dfvValueMissing(tokens, j) {
						found = append(found, name)
					}
				}
			}
			if tc.want == "" {
				if len(found) != 0 {
					t.Errorf("line %q reported %v, but every value-taking flag on it has a value — the "+
						"guard would raise a false violation and train readers to ignore it", tc.line, found)
				}
				return
			}
			var hit bool
			for _, f := range found {
				if f == tc.want {
					hit = true
				}
			}
			if !hit {
				t.Errorf("line %q did not yield %q (got %v); the guard cannot see the defect it exists "+
					"to catch", tc.line, tc.want, found)
			}
		})
	}
}
