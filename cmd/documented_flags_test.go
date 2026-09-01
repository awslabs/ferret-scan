// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #503 deleted a 764-line troubleshooting guide in which all 17 of the flags it instructed the reader
// to run did not exist. That was not one bad file: the same fiction sat in
// docs/development/content-router-architecture.md, and a reader following either had no way to tell a
// documented-but-absent feature from their own mistake.
//
// This is the guard for the class. A flag advertised on a `ferret-scan` command line in the
// documentation must be a flag the binary actually registers. Nothing else in the tree checks that,
// which is why 17 of them survived long enough to be audited.
//
// The real flag set is read from the registrations in this package rather than from `--help`, because
// --help is itself hand-written prose that can drift: 40 flags are registered and 37 appear in the
// help text. Registration is the source of truth for "would this parse".

// flagRegistration matches the standard-library registrations in cmd/*.go, e.g.
//
//	flag.String("file", "", "...")
//	flag.Bool("no-color", false, "...")
var flagRegistration = regexp.MustCompile(`flag\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Var|Func)\("([a-zA-Z0-9_-]+)"`)

// ferretCommand finds a `ferret-scan` invocation and captures the rest of the command.
//
// Three details are load-bearing, and each was wrong in the first draft — the control test
// TestTheGuardCatchesAPlantedAbsentFlag caught all three:
//
//   - **The leading boundary allows indentation** (`^\s*`). Commands in documentation are usually
//     inside a fenced block and often indented; anchoring on a bare `^` silently missed them, which
//     understated the command count and let a real violation through.
//   - **It keeps `pre-commit run ferret-scan --all-files` out**, where `--all-files` is pre-commit's
//     flag and `ferret-scan` is a hook ID rather than the program.
//   - **Whitespace is required after the binary name**, which is what excludes
//     `ferret-scan-profile.exe`. A trailing `\b` does NOT do this: RE2 treats `-` as a non-word
//     character, so `ferret-scan\b` matches happily inside `ferret-scan-profile`, and the guard then
//     attributed that program's `--memprofile` to us. RE2 has no negative lookahead, so the exclusion
//     has to be expressed by consuming the separator.
//
// The trailing class stops at a shell separator so a second command on the same line is not
// attributed to us.
var ferretCommand = regexp.MustCompile(`(?:^\s*|[$>]\s*|\|\s*|&&\s*|;\s*|` + "`" + `)(?:\./|\.\\)?ferret-scan(?:\.exe)?(?:[ \t]+([^|;&` + "`" + `]*)|\s*$)`)

var flagToken = regexp.MustCompile(`--([a-zA-Z0-9][a-zA-Z0-9-]*)`)

// knownGaps are files that still advertise absent flags, with the issue tracking each. They are
// listed EXPLICITLY rather than skipped silently, because a guard that quietly tolerates violations
// reads as "the tree is clean" when it is not.
//
// A file listed here that becomes clean also fails the test — see
// TestKnownFlagGapsAreStillGapsSoTheListCannotRot. That is what stops this list from outliving the
// problem and quietly exempting a file forever.
var knownGaps = map[string]string{
	// --file-list, on `ferret-scan scan` lines which are themselves wrong (no such subcommand)
	"docs/user-guides/README-Windows-Usage.md": "#556",
	// --continue-on-error, same
	"docs/troubleshooting/WINDOWS_TROUBLESHOOTING.md": "#556",
}

// docsRoot is the documentation tree relative to this package.
const docsRoot = "../docs"

// realFlags returns every flag name registered in this package.
func realFlags(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(e.Name()) // #nosec G304 -- a file in this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, m := range flagRegistration.FindAllStringSubmatch(string(raw), -1) {
			out[m[1]] = true
		}
	}
	// Non-vacuity: if the regex stops matching, every doc passes and the guard is worthless.
	if len(out) < 20 {
		t.Fatalf("only %d flag registrations found in cmd/*.go; the extraction regex has stopped "+
			"matching, which would make every assertion below pass vacuously", len(out))
	}
	for _, must := range []string{"file", "checks", "debug", "format", "confidence"} {
		if !out[must] {
			t.Fatalf("flag %q not found by the extractor, so it is not reading registrations correctly", must)
		}
	}
	return out
}

// docFile is one markdown file plus the ferret-scan flags it advertises.
type docFile struct {
	rel   string
	flags map[string][]int // flag name -> 1-indexed line numbers
	cmds  int              // how many ferret-scan command lines were found
}

// scanDocs walks the documentation tree and extracts the flags advertised on ferret-scan commands.
func scanDocs(t *testing.T) []docFile {
	t.Helper()
	var out []docFile
	err := filepath.WalkDir(docsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Proposals describe designs that were never built, so a flag there is a proposal, not a
			// claim about the shipped binary.
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
		df := docFile{rel: filepath.ToSlash(filepath.Join("docs", strings.TrimPrefix(filepath.ToSlash(path), "../docs/"))), flags: map[string][]int{}}
		for i, line := range strings.Split(string(raw), "\n") {
			for _, cmd := range ferretCommand.FindAllStringSubmatch(line, -1) {
				df.cmds++
				for _, f := range flagToken.FindAllStringSubmatch(cmd[1], -1) {
					df.flags[f[1]] = append(df.flags[f[1]], i+1)
				}
			}
		}
		out = append(out, df)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", docsRoot, err)
	}
	return out
}

// absentFlags returns the flags a file advertises that the binary does not register.
func absentFlags(df docFile, real map[string]bool) []string {
	var bad []string
	for name := range df.flags {
		if !real[name] {
			bad = append(bad, name)
		}
	}
	sort.Strings(bad)
	return bad
}

// TestDocumentedFlagsExist is the regression guard for #503.
func TestDocumentedFlagsExist(t *testing.T) {
	real := realFlags(t)
	docs := scanDocs(t)

	// Non-vacuity: the extraction must actually find ferret-scan command lines, or a broken regex
	// would report a clean tree.
	var totalCmds, filesWithCmds int
	for _, df := range docs {
		totalCmds += df.cmds
		if df.cmds > 0 {
			filesWithCmds++
		}
	}
	if len(docs) < 20 {
		t.Fatalf("found only %d markdown files under %s; the walk is not reaching the docs tree",
			len(docs), docsRoot)
	}
	if totalCmds < 100 || filesWithCmds < 10 {
		t.Fatalf("extracted only %d ferret-scan command lines across %d files; the command regex has "+
			"stopped matching, so every assertion below would pass vacuously", totalCmds, filesWithCmds)
	}

	for _, df := range docs {
		bad := absentFlags(df, real)
		if len(bad) == 0 {
			continue
		}
		if issue, known := knownGaps[df.rel]; known {
			t.Logf("%s: %d absent flags, tracked in %s: %s", df.rel, len(bad), issue, strings.Join(bad, " "))
			continue
		}
		var detail []string
		for _, name := range bad {
			detail = append(detail, fmt.Sprintf("--%s (line %v)", name, df.flags[name]))
		}
		t.Errorf("%s advertises %d flag(s) the binary does not register: %s\n"+
			"A reader who runs one of these gets `flag provided but not defined` at rc=2 and cannot "+
			"tell a documented-but-absent feature from their own mistake — this is the defect #503 "+
			"was filed for. Either remove the flag from the document or register it.\n"+
			"If the flag belongs to a DIFFERENT program that happens to share the line, the command "+
			"regex needs the boundary tightened rather than the document changed.",
			df.rel, len(bad), strings.Join(detail, ", "))
	}
}

// TestKnownFlagGapsAreStillGapsSoTheListCannotRot.
//
// An allowlist that is never revisited becomes a permanent exemption. If a listed file is cleaned up
// (or renamed, or deleted) this fails, so the entry is removed in the same change rather than
// silently protecting a file that no longer needs it.
func TestKnownFlagGapsAreStillGapsSoTheListCannotRot(t *testing.T) {
	real := realFlags(t)
	docs := scanDocs(t)
	byRel := map[string]docFile{}
	for _, df := range docs {
		byRel[df.rel] = df
	}

	for rel, issue := range knownGaps {
		df, ok := byRel[rel]
		if !ok {
			t.Errorf("knownGaps lists %s (%s) but no such file is in the docs tree — it was renamed or "+
				"deleted; drop the entry", rel, issue)
			continue
		}
		if bad := absentFlags(df, real); len(bad) == 0 {
			t.Errorf("knownGaps lists %s (%s) but it no longer advertises any absent flag. Remove the "+
				"entry, so the exemption does not outlive the problem.", rel, issue)
		}
	}
}

// TestTheGuardCatchesAPlantedAbsentFlag proves the guard is not inert.
//
// Every assertion above is over real files, so if the extraction silently broke, the suite would stay
// green while the tree rotted. This plants the exact shape #503 was about and requires it to be
// caught.
func TestTheGuardCatchesAPlantedAbsentFlag(t *testing.T) {
	real := realFlags(t)

	for _, tc := range []struct {
		name string
		line string
		want string // the flag that must be detected, "" for none
	}{
		{"the shape #503 documented", "ferret-scan --file document.pdf --debug-content-routing", "debug-content-routing"},
		{"with a shell prompt", "$ ferret-scan --profile-performance report.docx", "profile-performance"},
		{"windows exe", `.\ferret-scan.exe --file x.txt --legacy-validation`, "legacy-validation"},
		{"piped into", "cat x | ferret-scan --stdin --dry-run", "dry-run"},
		// Must NOT fire: another program's flag on a line that mentions ferret-scan.
		{"pre-commit hook id", "pre-commit run ferret-scan --all-files", ""},
		// Must NOT fire: a different binary whose name starts the same.
		{"different binary", `.\ferret-scan-profile.exe scan . --memprofile=mem.prof`, ""},
		// Must NOT fire: a real flag.
		{"a real flag", "ferret-scan --file x.txt --confidence high", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var found []string
			for _, cmd := range ferretCommand.FindAllStringSubmatch(tc.line, -1) {
				for _, f := range flagToken.FindAllStringSubmatch(cmd[1], -1) {
					if !real[f[1]] {
						found = append(found, f[1])
					}
				}
			}
			if tc.want == "" {
				if len(found) != 0 {
					t.Errorf("line %q flagged %v, but nothing on it is a ferret-scan flag the binary "+
						"lacks — the guard would report a false violation and train readers to ignore it",
						tc.line, found)
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

// TestTheDeletedGuideIsGone.
//
// #503's file was deleted rather than corrected, and three documents linked to it. A dangling
// relative link renders as ordinary text in most viewers, so nothing would announce a mistake here.
func TestTheDeletedGuideIsGone(t *testing.T) {
	const gone = "content-routing-troubleshooting"

	if _, err := os.Stat(filepath.Join(docsRoot, "development", "content-routing-troubleshooting.md")); err == nil {
		t.Errorf("docs/development/content-routing-troubleshooting.md is back. If it was restored " +
			"deliberately, it must first regain the 17 flags and 38 config keys it documented; see #503.")
	}

	err := filepath.WalkDir(docsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return err
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a markdown file inside the repo's docs tree
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, gone) {
				t.Errorf("%s:%d still links to the deleted guide: %s", path, i+1, strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", docsRoot, err)
	}
}
