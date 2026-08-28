// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"sort"
	"testing"
)

// Pre-commit mode is inferred from the environment, and a test that means to exercise ORDINARY
// CLI behaviour has to switch that inference off — otherwise it measures pre-commit behaviour
// on some machines and not others.
//
// The mode is not cosmetic. It forces quiet output, and the json/csv/yaml formatters
// deliberately return an EMPTY document in pre-commit mode when there are no findings
// (internal/formatters/json/formatter.go:63 and siblings), on the stated grounds that
// pre-commit signals out of band through the exit code and stderr. So a test asserting on a
// machine artifact gets zero bytes rather than a parse error, and the failure names the test's
// own subject rather than the environment.
//
// This list went stale twice, each time producing a windows-only CI failure whose cause had
// nothing to do with the failing test:
//
//	#351  scrubbed nothing, so GIT_EXEC_PATH (always set by Git Bash) forced text output
//	#354  scrubbed GIT_EXEC_PATH but missed MSYSTEM, so quiet mode emptied two artifacts
//
// Both times the CI step ran under C:\Program Files\Git\bin\bash.EXE, which sets MSYSTEM,
// MINGW_PREFIX and GIT_EXEC_PATH.
//
// #353 removed that class at the root: the detector no longer treats MSYSTEM, MINGW_PREFIX,
// GIT_EXEC_PATH, GITHUB_DESKTOP or "a git repo containing a pre-commit hook file" as pre-commit
// signals, because none of them indicates a hook INVOCATION. So the list is shorter and the
// remaining names are set by pre-commit itself or name a hook directly.
//
// This file is kept, and matters as much as before, for two reasons. The precise triggers still
// exist and a test meaning to exercise ordinary CLI behaviour must still scrub them. And the
// reverse-direction check below is what forced this list to be updated in step with the detector
// when those five were removed, rather than leaving five dead names behind — which is exactly the
// drift that caused the two failures above, in the other direction.
//
// TestPrecommitTriggerListIsComplete below keeps the list honest by deriving it from the
// detector's own source, so a trigger added there fails here instead of on one runner.

// precommitTriggerEnv is every environment variable whose presence can put the tool into
// pre-commit mode. See TestPrecommitTriggerListIsComplete.
var precommitTriggerEnv = []string{
	// Set by pre-commit itself.
	"PRE_COMMIT",
	"_PRE_COMMIT_RUNNING",
	"PRE_COMMIT_HOME",
	// Hook-context indicators, cross-platform since #353.
	"PRE_COMMIT_HOOK",
	"GIT_HOOK_TYPE",
	// The explicit opt-out. Scrubbed so a developer who exports it does not silently disable
	// the detection these tests are about — the tests that WANT the opt-out set it themselves.
	"FERRET_PRECOMMIT",
}

// MSYSTEM, MINGW_PREFIX, GIT_EXEC_PATH and GITHUB_DESKTOP used to be on the list above and are
// gone because the detector no longer reads them (#353). They were the ones that made detection
// fire without anyone opting in: Git Bash always sets MSYSTEM, so on Windows the usual shell was
// treated as a hook. The reverse-direction check at the bottom of
// TestPrecommitTriggerListMatchesTheDetector is what forced this list to be updated with the
// detector rather than drifting from it.

// precommitFreeEnv returns the current environment with every pre-commit trigger emptied.
//
// Emptied rather than removed because that is enough — the detector tests each with
// `os.Getenv(x) != ""` — and because Go's exec applies last-wins deduplication, so appending
// overrides an inherited value on every platform, including Windows where the names are
// case-insensitive.
//
// Since #353 the detector reads ONLY environment variables, so emptying them is sufficient. It
// previously also shelled out to `git rev-parse --git-dir` and looked for a pre-commit hook file
// beside it, which meant a caller had to run from outside any git repository as well — a
// requirement that was easy to forget and produced Windows-only failures when it was.
func precommitFreeEnv() []string {
	env := os.Environ()
	for _, k := range precommitTriggerEnv {
		env = append(env, k+"=")
	}
	return env
}

// TestPrecommitTriggerListIsComplete derives the trigger set from the detector's source and
// fails if precommitTriggerEnv has drifted from it.
//
// Reading the source rather than calling the detector is deliberate: detectEnvironment's Git
// Bash branch is compiled for every platform but only REACHED on Windows, so a table-driven
// test of the real function cannot observe those triggers on a Linux or macOS runner — which is
// exactly where this list gets edited.
func TestPrecommitTriggerListIsComplete(t *testing.T) {
	const detectorPath = "../internal/precommit/detector.go"

	src, err := os.ReadFile(detectorPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v — if the detector moved, this guard must move with it, or "+
			"the trigger list silently stops being checked", detectorPath, err)
	}

	// Variables that do NOT cause detection and so must not be scrubbed.
	notATrigger := map[string]string{
		// These only tune an ALREADY-detected pre-commit config (batch size, exit policy).
		// Emptying them would change nothing about whether the mode is entered.
		"FERRET_PRECOMMIT_BATCH_SIZE":    "tunes an already-detected config",
		"FERRET_PRECOMMIT_EXIT_ON":       "tunes an already-detected config",
		"FERRET_PRECOMMIT_EXIT_ON_FIRST": "tunes an already-detected config",
		// Only raises BatchSize from 50 to 75 inside applyWindowsConfigOptimizations. It is
		// read AFTER the mode has been decided, so it cannot cause detection. Listed here
		// because this guard found it on its first run — a case-insensitive name that a
		// hand-written [A-Z_]+ grep of the detector had silently skipped.
		"PSModulePath": "tunes BatchSize after the mode is already decided",
		// MSYSTEM was a DETECTION trigger until #353 — Git Bash always sets it, which is what
		// made the usual Windows shell look like a hook. It is now read only by
		// applyWindowsConfigOptimizations, so it can no longer decide the mode, and it belongs
		// in this map for the same reason PSModulePath does.
		"MSYSTEM": "tunes BatchSize after the mode is already decided (was a trigger before #353)",
		// COMSPEC is a trigger only in combination with PRE_COMMIT_HOOK or GIT_HOOK_TYPE, both
		// of which ARE scrubbed, so the combination cannot fire. It is left alone on purpose:
		// it is a core Windows variable and blanking it could affect anything the tool shells
		// out to.
		"COMSPEC": "only triggers together with PRE_COMMIT_HOOK/GIT_HOOK_TYPE, which are scrubbed",
	}

	scrubbed := make(map[string]bool, len(precommitTriggerEnv))
	for _, k := range precommitTriggerEnv {
		scrubbed[k] = true
	}

	seen := map[string]bool{}
	var missing []string
	for _, m := range regexp.MustCompile(`os\.Getenv\("([A-Za-z_][A-Za-z0-9_]*)"\)`).FindAllStringSubmatch(string(src), -1) {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if _, ok := notATrigger[name]; ok {
			continue
		}
		if !scrubbed[name] {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%s reads %v, which precommitTriggerEnv does not scrub.\n"+
			"Add each one to precommitTriggerEnv, or to notATrigger with the reason it cannot "+
			"cause detection.\n"+
			"An unscrubbed trigger does not fail here — it fails as an unrelated assertion on "+
			"whichever runner happens to set it, which has already cost two windows-only CI "+
			"failures.", detectorPath, missing)
	}

	// The reverse direction: a name scrubbed here but no longer read by the detector is dead
	// weight that suggests the list is being maintained by guesswork.
	for _, k := range precommitTriggerEnv {
		if !seen[k] {
			t.Errorf("precommitTriggerEnv scrubs %q but %s no longer reads it", k, detectorPath)
		}
	}
}
