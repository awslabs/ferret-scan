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

// #555: fourteen FERRET_* environment variables were advertised across docs/ and nothing read any of
// them. One was worse than inert — `FERRET_FAIL_ON=none`, documented as "never block commits", left
// the pre-commit hook exiting 1 on a HIGH finding — and one was SET in the shipped image
// (`ENV FERRET_QUIET_MODE=true`), so deleting the documentation alone would have left the container
// advertising a dead knob.
//
// This is the guard for the class, and its whole difficulty is the sentence you are reading in the
// tree right now: **not every mention is an advertisement.**
//
//	docs/development/debug_logging.md   "There is no `FERRET_VERBOSE` — it is not read anywhere"
//	docs/PRE_COMMIT_INTEGRATION.md      FERRET_CONFIDENCE / FERRET_FAIL_ON under "# OLD (remove this)"
//
// Both are CORRECT prose that names a dead variable, and both are worth keeping — a reader who has
// inherited a config full of FERRET_FAIL_ON needs to be told it is dead. A guard that counted every
// mention would pressure the next author into deleting true statements to get the suite green, which is
// a worse tree than the one it started from.
//
// So the unit of judgement is the enclosing BLOCK, not the line and not the file. A mention is an
// advertisement unless its block — the fenced code block it sits in, or the markdown paragraph it sits
// in — carries a negation marker. That is what lets `# OLD (remove this)` three lines above a
// `FERRET_FAIL_ON: "high"` exempt it, and what lets a two-line prose sentence exempt a name it
// mentions in its first line and refutes in its second.
//
// The oracle is deliberately NOT a repo-wide grep for os.Getenv. That set also contains FERRET_CHECKS,
// FERRET_STRATEGY and FERRET_INCLUDE_FINDINGS, which examples/lambda-redact/handler.go reads and the
// CLI does not — so a repo-wide grep would have declared FERRET_CHECKS "real" in a pre-commit env:
// block where it does nothing. Only cmd/, internal/ and pkg/ count.
//
// Identifiers here are prefixed `evg` and helpers are not shared with the sibling flag guards, matching
// the choice already made in cmd/documented_invocations_test.go.

// evgName matches a FERRET_* variable name wherever it appears.
var evgName = regexp.MustCompile(`FERRET_[A-Z0-9_]+`)

// evgGoLiteral matches a FERRET_* name written as a Go string literal, which is how any code that
// reads one has to name it — whether through os.Getenv, os.LookupEnv, or a named constant.
var evgGoLiteral = regexp.MustCompile(`"(FERRET_[A-Z0-9_]+)"`)

// evgProductionDirs are the trees that build the shipped binary and the published packages. Anything
// outside them (examples/, tests/) may read a variable the tool itself ignores.
var evgProductionDirs = []string{"../cmd", "../internal", "../pkg"}

// evgHarnessOnly are names documentation may legitimately tell a reader to SET even though no
// production code reads them, because something in this repo really does set them. The value says what
// sets it, so the entry can be checked rather than believed.
//
// TestEvgHarnessOnlyListCannotRot fails in BOTH directions: if production code starts reading one
// (then it belongs in the derived set and the exemption is stale) and if nothing in the repo sets it
// any more (then it is fiction like the other thirteen and the exemption is hiding it).
var evgHarnessOnly = map[string]string{
	"FERRET_TEST_MODE": "Makefile + scripts/run-tests.sh + tests/helpers; read only by tests/helpers",
}

// evgNegationMarkers are the phrasings that make a block a statement ABOUT a dead variable rather than
// an instruction to use one. Lower-cased substring match against the whole block.
//
// Kept short and literal on purpose. The cost of a marker that is too narrow is a false violation on
// true prose, so the failure message tells the author to widen this list rather than delete the text.
// Every marker here must be UNAMBIGUOUSLY a negation on its own. Three earlier candidates were
// dropped for failing that: "reads it" exempts the positive phrase "the CLI reads it from the
// environment", and "no longer"/"deprecated" both appear in prose that still instructs the reader to
// SET the variable ("FERRET_X is deprecated, use ..."). None of the three exempted anything in the
// tree, so removing them costs nothing today and closes the hole before a future doc walks into it.
var evgNegationMarkers = []string{
	"there is no", "there are no", "no such",
	"not read", "is not read", "read nowhere", "nothing reads", "nothing reads it",
	"none of", "does not exist", "do not exist",
	"remove this", "has been removed", "have been removed",
}

// evgShippedConfigFiles are non-markdown files that SET environment variables in something we ship or
// run. Prose has no place here, so the rule for them is strict: every FERRET_* name must be one
// production code reads. This is the half that #555 showed matters — the documentation for
// FERRET_QUIET_MODE could have been deleted while `ENV FERRET_QUIET_MODE=true` stayed in the image.
//
// Listed explicitly rather than discovered by a walk, so a file cannot drop out of coverage silently;
// each one is asserted to exist, because a missing file greps clean.
var evgShippedConfigFiles = []string{
	"../Dockerfile",
	"../docker-compose.yml",
	"../.gitlab-ci.yml",
	"../.pre-commit-config.yaml",
	"../.pre-commit-config-examples.yaml",
}

// evgDocsDir is the documentation tree relative to this package.
const evgDocsDir = "../docs"

// evgProductionNames returns the FERRET_* names that code building the binary refers to.
func evgProductionNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, root := range evgProductionDirs {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				// A vanished path is not a broken walk. Tests elsewhere in the tree create and
				// remove their own scratch directories, and under `go test ./...` this walk runs
				// concurrently with them, so an entry can disappear between being listed and being
				// stat'd. That flaked this guard on branches touching neither package (#577):
				// "walk ../internal: open ../internal/router/structured-sections-3058054452: no
				// such file or directory". Skipping is safe because the len(out) < 5 check below
				// still fails loudly if the walk stops finding anything.
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path) // #nosec G304 -- a Go source file inside this repo
			if err != nil {
				return err
			}
			for _, m := range evgGoLiteral.FindAllStringSubmatch(string(raw), -1) {
				out[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	// Non-vacuity: if the extraction breaks, every name looks real and every document passes.
	if len(out) < 5 {
		t.Fatalf("only %d FERRET_* names found in %v; the extraction has stopped matching, which would "+
			"make every assertion below pass vacuously", len(out), evgProductionDirs)
	}
	for _, must := range []string{"FERRET_DEBUG", "FERRET_CONFIG_DIR", "FERRET_PRECOMMIT_EXIT_ON"} {
		if !out[must] {
			t.Fatalf("%s is read by production code but the extractor did not find it, so it is not "+
				"reading the tree correctly", must)
		}
	}
	// The oracle must be narrower than a repo-wide grep. FERRET_CHECKS is read by
	// examples/lambda-redact/handler.go and by nothing the CLI runs; if it shows up here, the walk has
	// widened and the guard would bless it inside a pre-commit env: block where it does nothing.
	if out["FERRET_CHECKS"] {
		t.Errorf("FERRET_CHECKS appears in the production set. It is read only by " +
			"examples/lambda-redact/handler.go; if a production package now reads it, this assertion " +
			"should be replaced — but if the walk merely widened to examples/, narrow it back.")
	}
	return out
}

// evgBlock is one fenced code block or one markdown paragraph.
type evgBlock struct {
	first int // 1-indexed first line
	text  string
}

// evgSplitBlocks divides a markdown file into fenced code blocks and paragraphs.
//
// A fenced block runs from its opening ``` to its closing ```, inclusive, so an `# OLD (remove this)`
// comment at the top of a yaml example covers the whole example. Outside fences, a block is a maximal
// run of non-blank lines, which is a markdown paragraph — so a sentence that names a variable on one
// line and refutes it on the next is judged as one statement.
func evgSplitBlocks(raw string) []evgBlock {
	lines := strings.Split(raw, "\n")
	var out []evgBlock
	var cur []string
	curFirst := 0
	inFence := false

	flush := func() {
		if len(cur) > 0 {
			out = append(out, evgBlock{first: curFirst, text: strings.Join(cur, "\n")})
			cur = nil
		}
	}
	for i, line := range lines {
		isFence := strings.HasPrefix(strings.TrimSpace(line), "```")
		switch {
		case isFence && !inFence:
			flush()
			inFence = true
			curFirst = i + 1
			cur = []string{line}
		case isFence && inFence:
			cur = append(cur, line)
			flush()
			inFence = false
		case inFence:
			cur = append(cur, line)
		case strings.TrimSpace(line) == "":
			flush()
		default:
			if len(cur) == 0 {
				curFirst = i + 1
			}
			cur = append(cur, line)
		}
	}
	flush()
	return out
}

// evgIsNegation reports whether a block states that a variable is dead rather than telling the reader
// to set it.
func evgIsNegation(blockText string) bool {
	lower := strings.ToLower(blockText)
	for _, m := range evgNegationMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// evgAdvert is one advertised variable.
type evgAdvert struct {
	name  string
	first int
	text  string
}

// evgScanDocs returns, per documentation file, the FERRET_* names it ADVERTISES that neither production
// code reads nor evgHarnessOnly excuses, plus how many mentions and exemptions were seen overall.
func evgScanDocs(t *testing.T, real map[string]bool) (bad map[string][]evgAdvert, mentions, exempted, files int) {
	t.Helper()
	bad = map[string][]evgAdvert{}
	err := filepath.WalkDir(evgDocsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Proposals describe designs that were never built, so a variable there is a proposal.
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
		files++
		rel := "docs/" + strings.TrimPrefix(filepath.ToSlash(path), "../docs/")
		for _, blk := range evgSplitBlocks(string(raw)) {
			names := map[string]bool{}
			for _, n := range evgName.FindAllString(blk.text, -1) {
				names[n] = true
			}
			if len(names) == 0 {
				continue
			}
			negation := evgIsNegation(blk.text)
			for name := range names {
				mentions++
				if real[name] {
					continue
				}
				if _, ok := evgHarnessOnly[name]; ok {
					continue
				}
				if negation {
					exempted++
					continue
				}
				bad[rel] = append(bad[rel], evgAdvert{name: name, first: blk.first, text: blk.text})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", evgDocsDir, err)
	}
	return bad, mentions, exempted, files
}

// TestDocumentedEnvVarsAreRead is the regression guard for the environment-variable half of #555.
func TestDocumentedEnvVarsAreRead(t *testing.T) {
	real := evgProductionNames(t)
	bad, mentions, exempted, files := evgScanDocs(t, real)

	// Non-vacuity: the walk must reach the docs tree and actually find mentions.
	if files < 20 {
		t.Fatalf("found only %d markdown files under %s; the walk is not reaching the docs tree",
			files, evgDocsDir)
	}
	if mentions < 20 {
		t.Fatalf("found only %d FERRET_* mentions across %d documents; the name regex has stopped "+
			"matching, so every assertion below would pass vacuously", mentions, files)
	}
	// Non-vacuity of the exemption path specifically: the tree deliberately contains correct prose
	// naming dead variables. If NOTHING is exempted, evgIsNegation has stopped recognising it and the
	// next author to touch those files will be told to delete a true statement.
	if exempted == 0 {
		t.Errorf("no mention was exempted as correct prose, but the tree contains several — e.g. " +
			"docs/development/debug_logging.md's \"There is no `FERRET_VERBOSE`\" and " +
			"docs/PRE_COMMIT_INTEGRATION.md's `# OLD (remove this)` block. evgIsNegation is no longer " +
			"recognising them, so this guard is about to pressure someone into deleting accurate text.")
	}

	for rel, advs := range bad {
		var detail []string
		for _, a := range advs {
			detail = append(detail, fmt.Sprintf("%s (block at line %d)", a.name, a.first))
		}
		sort.Strings(detail)
		t.Errorf("%s advertises %d environment variable(s) no production code reads: %s\n"+
			"Setting one changes nothing, and the reader has no way to find that out — #555's "+
			"FERRET_FAIL_ON=none was documented as \"never block commits\" while still exiting 1.\n"+
			"If the capability is real under another name, REPLACE it (FERRET_FAIL_ON ->\n"+
			"FERRET_PRECOMMIT_EXIT_ON). If a test harness genuinely sets it, add it to evgHarnessOnly "+
			"with what sets it.\n"+
			"If this block is CORRECT PROSE saying the variable is dead, do NOT delete the prose — add "+
			"its phrasing to evgNegationMarkers.",
			rel, len(advs), strings.Join(detail, ", "))
	}
}

// TestShippedConfigOnlySetsRealEnvVars covers the half a docs-only guard would miss.
//
// FERRET_QUIET_MODE was `ENV FERRET_QUIET_MODE=true` in the Dockerfile. Deleting its two documentation
// lines would have left every container advertising it through `docker inspect` while nothing read it.
func TestShippedConfigOnlySetsRealEnvVars(t *testing.T) {
	real := evgProductionNames(t)

	for _, path := range evgShippedConfigFiles {
		// Vacuity trap: a file that is not there greps clean.
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s is listed as shipped configuration but is missing (%v). If it was renamed or "+
				"deleted, update evgShippedConfigFiles — an entry that cannot be read asserts nothing.",
				path, err)
			continue
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a file from a fixed in-repo list
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			for _, name := range evgName.FindAllString(line, -1) {
				if real[name] || evgHarnessOnly[name] != "" {
					continue
				}
				t.Errorf("%s:%d sets or names %s, which no production code reads: %q\n"+
					"A variable set in something we ship is worse than one merely documented: it "+
					"survives in the image and in `docker inspect` long after the doc line is gone.",
					path, i+1, name, strings.TrimSpace(line))
			}
		}
	}
}

// TestEvgHarnessOnlyListCannotRot keeps the harness-only exemption honest in both directions.
func TestEvgHarnessOnlyListCannotRot(t *testing.T) {
	real := evgProductionNames(t)

	// Where a harness-only variable is allowed to be set from.
	setterRoots := []string{"../Makefile", "../scripts", "../tests"}

	for name, why := range evgHarnessOnly {
		if real[name] {
			t.Errorf("evgHarnessOnly lists %s (%q) but production code now reads it. Drop the entry: it "+
				"is in the derived set, and the exemption would hide a future removal.", name, why)
		}
		var found []string
		for _, root := range setterRoots {
			err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				raw, err := os.ReadFile(path) // #nosec G304 -- a file inside this repo
				if err != nil {
					return nil // unreadable file is not evidence either way
				}
				if strings.Contains(string(raw), name) {
					found = append(found, filepath.ToSlash(path))
				}
				return nil
			})
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("walk %s: %v", root, err)
			}
		}
		if len(found) == 0 {
			t.Errorf("evgHarnessOnly lists %s (%q) but nothing under %v mentions it any more, so it is "+
				"fiction like the variables #555 deleted. Remove the entry and the documentation that "+
				"tells readers to set it.", name, why, setterRoots)
		}
	}
}

// TestTheEnvGuardTellsAnAdvertisementFromCorrectProse is the control test, and it is the reason this
// guard is safe to ship: the two must-NOT-fire cases are quoted from the tree verbatim.
func TestTheEnvGuardTellsAnAdvertisementFromCorrectProse(t *testing.T) {
	fence := "```"
	for _, tc := range []struct {
		name  string
		doc   string
		fires bool
	}{
		{
			name:  "a bare advertisement in prose",
			doc:   "Set `FERRET_MADE_UP_KNOB` to 1 to enable the thing.",
			fires: true,
		},
		{
			name:  "an advertisement in a shell block",
			doc:   fence + "bash\nexport FERRET_MADE_UP_KNOB=1\nferret-scan --file x.txt\n" + fence,
			fires: true,
		},
		{
			name:  "an advertisement in a yaml env block",
			doc:   fence + "yaml\nenv:\n  FERRET_MADE_UP_KNOB: \"high\"\n" + fence,
			fires: true,
		},
		{
			name:  "a PowerShell setter",
			doc:   fence + "powershell\n$env:FERRET_MADE_UP_KNOB = \"1\"\n" + fence,
			fires: true,
		},
		{
			name:  "a bullet listing it as a knob",
			doc:   "### Environment Variables\n- `FERRET_MADE_UP_KNOB` - Set to `true` to reduce output",
			fires: true,
		},
		// Must NOT fire: docs/development/debug_logging.md, verbatim. Deleting this sentence would
		// remove a measured, useful fact.
		{
			name: "correct prose: there is no FERRET_VERBOSE",
			doc: "`FERRET_DEBUG` is the only debug environment variable. There is no `FERRET_VERBOSE` — it is not read\n" +
				"anywhere in the codebase and setting it changes nothing (measured: byte-identical output with and\n" +
				"without it, while `--verbose` more than doubles it). Use the `--verbose` flag.",
			fires: false,
		},
		// Must NOT fire: docs/PRE_COMMIT_INTEGRATION.md, verbatim. The marker is three lines above the
		// name, which is why the block and not the line is the unit.
		{
			name: "correct prose: the OLD (remove this) migration block",
			doc: fence + "yaml\n# OLD (remove this)\nentry: scripts/enhanced-pre-commit-wrapper.sh\nenv:\n" +
				"  FERRET_CONFIDENCE: \"high\"\n  FERRET_FAIL_ON: \"high\"\n\n# NEW (use this)\n" +
				"entry: ./bin/ferret-scan --pre-commit-mode --confidence high\nenv:\n" +
				"  FERRET_PRECOMMIT_EXIT_ON: \"high\"\n" + fence,
			fires: false,
		},
		// Must NOT fire: a negation whose refutation is on the SECOND line of the paragraph.
		{
			name: "negation split across two prose lines",
			doc: "This document used to advertise `FERRET_MADE_UP_KNOB`. None of the three\n" +
				"is read anywhere either; all three have been removed.",
			fires: false,
		},
		// Must NOT fire: real variables.
		{
			name:  "a real variable",
			doc:   fence + "bash\nexport FERRET_DEBUG=1\n" + fence,
			fires: false,
		},
		{
			name:  "the real pre-commit variable",
			doc:   fence + "yaml\nenv:\n  FERRET_PRECOMMIT_EXIT_ON: \"none\"\n" + fence,
			fires: false,
		},
		// Must NOT fire: harness-only, which really is set by the Makefile.
		{
			name:  "harness-only variable",
			doc:   fence + "powershell\n$env:FERRET_TEST_MODE = \"1\"\n" + fence,
			fires: false,
		},
		// Must NOT fire: no variable at all.
		{
			name:  "no variable",
			doc:   "Run `ferret-scan --file x.txt --confidence high`.",
			fires: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			real := evgProductionNames(t)
			var fired []string
			for _, blk := range evgSplitBlocks(tc.doc) {
				names := map[string]bool{}
				for _, n := range evgName.FindAllString(blk.text, -1) {
					names[n] = true
				}
				if len(names) == 0 || evgIsNegation(blk.text) {
					continue
				}
				for name := range names {
					if real[name] {
						continue
					}
					if _, ok := evgHarnessOnly[name]; ok {
						continue
					}
					fired = append(fired, name)
				}
			}
			if tc.fires && len(fired) == 0 {
				t.Errorf("guard did not fire on:\n%s\nIt cannot see the defect it exists to catch.", tc.doc)
			}
			if !tc.fires && len(fired) != 0 {
				t.Errorf("guard fired %v on:\n%s\nThis text is correct as written; flagging it would "+
					"pressure the next author into deleting a true statement.", fired, tc.doc)
			}
		})
	}
}

// TestTheEnvGuardWouldHaveCaughtAllFourteen pins the guard against the actual defect it was written
// for, without depending on those documents still containing it.
//
// Each string below is the block as it stood before #555, reduced to the lines that matter. If the
// classifier ever stops recognising these shapes, the suite says so here rather than going quietly
// green on a tree that has regressed.
func TestTheEnvGuardWouldHaveCaughtAllFourteen(t *testing.T) {
	real := evgProductionNames(t)
	fence := "```"

	// name -> the pre-#555 block that advertised it.
	before := map[string]string{
		"FERRET_CONFIDENCE": fence + "yaml\nenv:\n  FERRET_CONFIDENCE: \"high,medium\"\n" + fence,
		"FERRET_CHECKS":     fence + "yaml\nenv:\n  FERRET_CHECKS: \"all\"\n" + fence,
		"FERRET_FAIL_ON":    fence + "yaml\nenv:\n  FERRET_FAIL_ON: \"none\"  # Never block commits\n" + fence,
		"FERRET_QUIET_MODE": "- `FERRET_QUIET_MODE` - Set to `true` in container to reduce debug output",
		"FERRET_TEMP_DIR": fence + "powershell\n" +
			"[Environment]::SetEnvironmentVariable(\"FERRET_TEMP_DIR\", \"$env:TEMP\\ferret-scan\", \"User\")\n" + fence,
		"FERRET_DEV_MODE": fence + "powershell\n" +
			"[Environment]::SetEnvironmentVariable(\"FERRET_DEV_MODE\", \"1\", \"User\")\n" + fence,
		"FERRET_LOG_LEVEL":      fence + "powershell\n$env:FERRET_LOG_LEVEL = \"debug\"\n" + fence,
		"FERRET_DEBUG_PLATFORM": fence + "powershell\n$env:FERRET_DEBUG_PLATFORM = \"1\"\n" + fence,
		"FERRET_DEBUG_PATHS":    fence + "powershell\n$env:FERRET_DEBUG_PATHS = \"1\"\n" + fence,
		"FERRET_LOG_FILE":       fence + "powershell\n$env:FERRET_LOG_FILE = \"debug.log\"\n" + fence,
		"FERRET_PERF":           fence + "powershell\n$env:FERRET_PERF = \"1\"\n" + fence,
		"FERRET_SERVICE_MODE":   fence + "powershell\n$env:FERRET_SERVICE_MODE = \"1\"\n" + fence,
		"FERRET_EVENTLOG":       fence + "powershell\n$env:FERRET_EVENTLOG = \"1\"\n" + fence,
		"FERRET_VERBOSE":        fence + "bash\nexport FERRET_VERBOSE=1\n" + fence,
	}
	if len(before) != 14 {
		t.Fatalf("this test claims to cover 14 variables but lists %d", len(before))
	}

	for name, doc := range before {
		t.Run(name, func(t *testing.T) {
			if real[name] {
				t.Skipf("%s is now read by production code, so it is no longer a gap", name)
			}
			var fired bool
			for _, blk := range evgSplitBlocks(doc) {
				if evgIsNegation(blk.text) {
					continue
				}
				for _, n := range evgName.FindAllString(blk.text, -1) {
					if n == name {
						fired = true
					}
				}
			}
			if !fired {
				t.Errorf("the pre-#555 block advertising %s would NOT be reported:\n%s", name, doc)
			}
		})
	}
}
