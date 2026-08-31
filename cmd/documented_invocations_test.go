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

// #556: the Windows documentation invoked the tool as `ferret-scan scan <path>` in 88 places, and
// there is no `scan` subcommand. The word was taken as the POSITIONAL PATH, and the failure is quiet
// in a way that matters:
//
//	$ ferret-scan scan p.txt --checks SSN --enable-redaction
//	Error processing scan: path does not exist or is not accessible: stat ./scan: no such file
//	Error processing --checks: path does not exist or is not accessible: stat ./--checks: ...
//	Error processing SSN: path does not exist or is not accessible: stat ./SSN: ...
//	<scans p.txt with ALL checks, writes no redacted file, exits 0>
//
// Go's flag package stops parsing at the first non-flag argument, so `scan` does not merely add a
// bogus path — every flag AFTER it becomes a path too and is therefore ignored. Measured: with
// `--enable-redaction` in that position no redacted artifact is written at all, and the exit code is
// still 0. A reader following the Windows guide to redact a directory gets nothing redacted and a
// success code. `ferret-scan web` had the same shape; the real flag is `--web`.
//
// This guard is deliberately narrow: it fires only when a positional argument comes FIRST and a flag
// follows it, which is the shape in which flags are silently dropped. Prose that merely mentions the
// program ("ferret-scan can read from stdin") has no following flag and is not a command.
//
// Identifiers here are prefixed `inv` to stay distinct from cmd/documented_flags_test.go, which
// covers the sibling concern of flags that do not exist.

// invCommandRe finds a ferret-scan invocation and captures the rest of the command. Same boundary
// rules as the flag guard: leading indentation allowed (commands live in fenced blocks), whitespace
// required after the name so `ferret-scan-profile.exe` is excluded, and the capture stops at a shell
// separator.
var invCommandRe = regexp.MustCompile(`(?:^\s*|[$>]\s*|\|\s*|&&\s*|;\s*|` + "`" + `)(?:\./|\.\\)?ferret-scan(?:\.exe)?(?:[ \t]+([^|;&` + "`" + `]*)|\s*$)`)

// invDocsDir is the documentation tree relative to this package.
const invDocsDir = "../docs"

// invKnownPositional records files that still contain a positional-first invocation, with the issue
// tracking each. Listed explicitly rather than skipped, and TestInvKnownPositionalGapsHaveNotRotted
// fails if one becomes clean, so an entry cannot outlive the problem.
// It is EMPTY, and that is the point: after #556 no documented invocation drops its flags. The map and
// its rot test are kept because the next one to appear should be recorded here with an issue rather
// than silently tolerated — an allowlist that starts empty cannot hide anything.
//
// The orphaned enhanced-architecture-runbook.md used to contribute 17 of the invocations counted here;
// #555 deleted it, so the non-vacuity floor below is now met by 294 rather than 311.
var invKnownPositional = map[string]string{}

// invOffender is one bad invocation.
type invOffender struct {
	line  int
	first string
	flag  string
	text  string
}

// invScanDocs returns, per doc file, the positional-first invocations that drop a following flag.
func invScanDocs(t *testing.T) (map[string][]invOffender, int) {
	t.Helper()
	out := map[string][]invOffender{}
	total := 0
	err := filepath.WalkDir(invDocsDir, func(path string, d os.DirEntry, err error) error {
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
			for _, m := range invCommandRe.FindAllStringSubmatch(line, -1) {
				rest := strings.Fields(strings.TrimSpace(m[1]))
				if len(rest) == 0 {
					continue
				}
				total++
				if strings.HasPrefix(rest[0], "-") {
					continue // starts with a flag: correct
				}
				// A positional first. It only DROPS something if a flag follows.
				for _, tok := range rest[1:] {
					if strings.HasPrefix(tok, "-") {
						out[rel] = append(out[rel], invOffender{
							line: i + 1, first: rest[0], flag: tok, text: strings.TrimSpace(line),
						})
						break
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", invDocsDir, err)
	}
	return out, total
}

// TestNoDocumentedInvocationSilentlyDropsItsFlags is the regression guard for #556.
func TestNoDocumentedInvocationSilentlyDropsItsFlags(t *testing.T) {
	bad, total := invScanDocs(t)

	// Non-vacuity: the extraction must find real invocations, or a broken regex reports a clean tree.
	if total < 100 {
		t.Fatalf("found only %d ferret-scan invocations across %s; the command regex has stopped "+
			"matching, so every assertion below would pass vacuously", total, invDocsDir)
	}

	for rel, offs := range bad {
		if issue, known := invKnownPositional[rel]; known {
			t.Logf("%s: %d positional-first invocations, tracked in %s", rel, len(offs), issue)
			continue
		}
		var detail []string
		for _, o := range offs {
			detail = append(detail, fmt.Sprintf("line %d: %q comes before %q", o.line, o.first, o.flag))
		}
		t.Errorf("%s documents %d invocation(s) whose flags are SILENTLY IGNORED: %s\n"+
			"Flag parsing stops at the first non-flag argument, so every flag after a positional "+
			"becomes a path. The command still exits 0, so this fails quietly — measured, "+
			"--enable-redaction in that position writes no redacted file at all.\n"+
			"Write the path as a flag value: `ferret-scan --file <path> --other-flags`.",
			rel, len(offs), strings.Join(detail, "; "))
	}
}

// TestInvKnownPositionalGapsHaveNotRotted keeps the allowlist honest.
func TestInvKnownPositionalGapsHaveNotRotted(t *testing.T) {
	bad, _ := invScanDocs(t)
	for rel, issue := range invKnownPositional {
		if len(bad[rel]) == 0 {
			t.Errorf("invKnownPositional lists %s (%s) but it no longer contains a positional-first "+
				"invocation. Remove the entry, so the exemption does not outlive the problem.", rel, issue)
		}
	}
}

// TestTheInvocationGuardCatchesThePlantedShapes proves the guard is not inert, and pins the boundary
// between a real command and prose.
func TestTheInvocationGuardCatchesThePlantedShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		want bool // should be reported as dropping flags
	}{
		{"the shape #556 documented", `ferret-scan scan "C:\dir" --format json`, true},
		{"the web variant", "ferret-scan web --port 8080", true},
		{"windows exe", `.\ferret-scan.exe scan . --debug --verbose`, true},
		{"indented in a fenced block", "        ferret-scan scan $file --format json", true},
		// Correct forms must NOT fire.
		{"flag first", "ferret-scan --file report.docx --format json", false},
		{"web flag", "ferret-scan --web --port 8080", false},
		{"help only", "ferret-scan --help", false},
		// A bare positional with NO following flag loses nothing, so it is not this defect.
		{"bare path, no flags", "ferret-scan report.docx", false},
		// Prose mentioning the program is not a command.
		{"prose", "ferret-scan can read content from standard input", false},
		{"prose with a later flag reference", "ferret-scan validates input before scanning", false},
		// Another program on the same line.
		{"pre-commit hook id", "pre-commit run ferret-scan --all-files", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fired bool
			for _, m := range invCommandRe.FindAllStringSubmatch(tc.line, -1) {
				rest := strings.Fields(strings.TrimSpace(m[1]))
				if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
					continue
				}
				for _, tok := range rest[1:] {
					if strings.HasPrefix(tok, "-") {
						fired = true
					}
				}
			}
			if fired != tc.want {
				t.Errorf("line %q: guard fired=%v, want %v", tc.line, fired, tc.want)
			}
		})
	}
}

// TestThereIsNoScanSubcommand pins the fact the documentation got wrong, at the source rather than in
// prose: the binary registers flags only, and nothing parses a subcommand.
func TestThereIsNoScanSubcommand(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	var sawSubcommandDispatch bool
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- a file in this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		// A subcommand dispatcher would compare an argument against a literal verb.
		for _, verb := range []string{`== "scan"`, `== "web"`, `case "scan"`, `case "web"`} {
			if strings.Contains(string(raw), verb) {
				sawSubcommandDispatch = true
				t.Logf("%s contains %s", e.Name(), verb)
			}
		}
	}
	if sawSubcommandDispatch {
		t.Error("something now dispatches on a subcommand verb. If `scan` or `web` became a real " +
			"subcommand, the documentation this test protects should be updated to use it and this " +
			"test replaced — but until then, the docs must use flags.")
	}
}
