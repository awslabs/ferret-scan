// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import (
	"os"
	"testing"
)

// #353: pre-commit mode was inferred from a Git ENVIRONMENT rather than a hook INVOCATION, on
// Windows only.
//
// detectWindowsGitEnvironment returned true for any of these, each independently:
//
//	MSYSTEM, MINGW_PREFIX        set by Git Bash, always
//	GIT_EXEC_PATH                set by Git whenever git runs a subprocess
//	GITHUB_DESKTOP               set by GitHub Desktop
//	a git repo with a
//	  .git/hooks/pre-commit file true for anyone working in such a repo, hook running or not
//
// Detection then set QuietMode, NoColor, Format "text" and ExitOnFindings "high", so an ordinary
// scan lost its colour, was forced to text and acquired hook exit-code semantics. MSYSTEM is the
// one that mattered: Git Bash is how the tool is normally run on Windows, so the normal case was
// the misdetected one. It cost two windows-only CI failures (#351, #354) whose causes had nothing
// to do with the tests that failed.
//
// These tests run on every platform. The removed function was compiled everywhere and reached only
// on Windows, which is precisely why the bug survived: no Linux or macOS run could observe it.

// clearAllTriggers empties every variable this package reads, so each test starts from a known
// state regardless of the developer's shell or the CI runner.
func clearAllTriggers(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PRE_COMMIT", "_PRE_COMMIT_RUNNING", "PRE_COMMIT_HOME",
		"PRE_COMMIT_HOOK", "GIT_HOOK_TYPE", "FERRET_PRECOMMIT",
		"MSYSTEM", "MINGW_PREFIX", "GIT_EXEC_PATH", "GITHUB_DESKTOP",
		"FERRET_PRECOMMIT_BATCH_SIZE", "FERRET_PRECOMMIT_EXIT_ON", "FERRET_PRECOMMIT_EXIT_ON_FIRST",
	} {
		t.Setenv(k, "")
	}
}

// TestAGitEnvironmentIsNotAHookInvocation is the regression test.
//
// Each variable is set ALONE, because each was independently sufficient before the fix.
func TestAGitEnvironmentIsNotAHookInvocation(t *testing.T) {
	cases := []struct{ name, why string }{
		{"MSYSTEM", "Git Bash always sets it — the usual way to run this tool on Windows"},
		{"MINGW_PREFIX", "also set by Git Bash"},
		{"GIT_EXEC_PATH", "set by Git whenever git runs a subprocess, hook or not"},
		{"GITHUB_DESKTOP", "indicates GitHub Desktop, not a hook"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAllTriggers(t)
			t.Setenv(tc.name, "/some/path")

			d := NewPrecommitDetector()
			if d.IsPrecommitEnvironment() {
				t.Errorf("%s alone put the tool into pre-commit mode.\n%s.\n"+
					"Detection forces quiet output, no colour and hook exit-code semantics, so "+
					"an ordinary scan is silently reshaped (#353).", tc.name, tc.why)
			}
			// And the config it hands out must be the ordinary one.
			cfg := d.GetOptimizedConfig()
			if cfg.QuietMode {
				t.Errorf("%s alone produced QuietMode=true", tc.name)
			}
			if cfg.NoColor {
				t.Errorf("%s alone produced NoColor=true", tc.name)
			}
		})
	}
}

// TestAllTheGitEnvironmentVariablesTogetherAreStillNotAHook: the four in combination, which is
// what a real Git Bash session looks like.
func TestAllTheGitEnvironmentVariablesTogetherAreStillNotAHook(t *testing.T) {
	clearAllTriggers(t)
	t.Setenv("MSYSTEM", "MINGW64")
	t.Setenv("MINGW_PREFIX", "/mingw64")
	t.Setenv("GIT_EXEC_PATH", "C:/Program Files/Git/mingw64/libexec/git-core")
	t.Setenv("GITHUB_DESKTOP", "1")

	if NewPrecommitDetector().IsPrecommitEnvironment() {
		t.Error("a Git Bash session with all four variables set was treated as a pre-commit hook. " +
			"This is the exact environment of the two windows-only CI failures (#351, #354).")
	}
}

// TestTheRealSignalsStillDetect is the other direction, and the half that matters most: a fix that
// stopped detecting genuine hooks would be worse than the bug.
func TestTheRealSignalsStillDetect(t *testing.T) {
	for _, k := range []string{
		// Set by pre-commit itself.
		"PRE_COMMIT", "_PRE_COMMIT_RUNNING", "PRE_COMMIT_HOME",
		// Name a hook invocation directly.
		"PRE_COMMIT_HOOK", "GIT_HOOK_TYPE",
	} {
		t.Run(k, func(t *testing.T) {
			clearAllTriggers(t)
			t.Setenv(k, "1")

			d := NewPrecommitDetector()
			if !d.IsPrecommitEnvironment() {
				t.Errorf("%s no longer triggers detection. It is set by pre-commit itself, or "+
					"names a hook invocation, so it must.", k)
			}
			if cfg := d.GetOptimizedConfig(); !cfg.QuietMode {
				t.Errorf("%s detected but QuietMode is false", k)
			}
		})
	}
}

// TestTheHookSignalsWorkOnEveryPlatform.
//
// PRE_COMMIT_HOOK and GIT_HOOK_TYPE used to be reachable only on Windows AND only when COMSPEC
// named cmd.exe, so the same hook behaved differently depending on the shell that ran it. Nothing
// about a hook is Windows-specific.
func TestTheHookSignalsWorkOnEveryPlatform(t *testing.T) {
	for _, k := range []string{"PRE_COMMIT_HOOK", "GIT_HOOK_TYPE"} {
		t.Run(k+"_without_COMSPEC", func(t *testing.T) {
			clearAllTriggers(t)
			t.Setenv("COMSPEC", "") // the old gate
			t.Setenv(k, "pre-commit")

			if !NewPrecommitDetector().IsPrecommitEnvironment() {
				t.Errorf("%s did not trigger detection without COMSPEC set. A hook is a hook "+
					"whatever shell invoked it.", k)
			}
		})
	}
}

// TestTheOptOutWins covers the missing escape hatch.
//
// Detection changes quiet mode, colour and exit-code semantics, and there was no way to decline
// it: the FERRET_PRECOMMIT_* variables could tune the behaviour but nothing could switch it off.
func TestTheOptOutWins(t *testing.T) {
	falsey := []string{"0", "false", "FALSE", "f", "F"}
	for _, v := range falsey {
		t.Run("FERRET_PRECOMMIT="+v, func(t *testing.T) {
			clearAllTriggers(t)
			t.Setenv("PRE_COMMIT", "1") // a genuine, strongest signal
			t.Setenv("FERRET_PRECOMMIT", v)

			d := NewPrecommitDetector()
			if d.IsPrecommitEnvironment() {
				t.Errorf("FERRET_PRECOMMIT=%q did not switch detection off even with PRE_COMMIT "+
					"set. The opt-out has to beat every signal or it is not an opt-out.", v)
			}
			if cfg := d.GetOptimizedConfig(); cfg.QuietMode || cfg.NoColor {
				t.Errorf("FERRET_PRECOMMIT=%q left QuietMode=%v NoColor=%v", v, cfg.QuietMode, cfg.NoColor)
			}
		})
	}
}

// TestTheOptOutIsNotAnOptIn. Setting it to a true value must not FORCE the mode on — that is what
// --pre-commit-mode is for, and a variable that does both is a footgun.
func TestTheOptOutIsNotAnOptIn(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "", "garbage"} {
		t.Run("FERRET_PRECOMMIT="+v, func(t *testing.T) {
			clearAllTriggers(t)
			t.Setenv("FERRET_PRECOMMIT", v)

			if NewPrecommitDetector().IsPrecommitEnvironment() {
				t.Errorf("FERRET_PRECOMMIT=%q turned pre-commit mode ON with no other signal "+
					"present", v)
			}
		})
	}
}

// TestTheExplicitFlagStillForcesTheMode: --pre-commit-mode must keep working, and must beat the
// opt-out, since it is the more specific request of the two.
func TestTheExplicitFlagStillForcesTheMode(t *testing.T) {
	clearAllTriggers(t)
	if !NewPrecommitDetectorWithFlag(true).IsPrecommitEnvironment() {
		t.Error("--pre-commit-mode no longer forces the mode with no environment signal")
	}

	t.Setenv("FERRET_PRECOMMIT", "0")
	if !NewPrecommitDetectorWithFlag(true).IsPrecommitEnvironment() {
		t.Error("--pre-commit-mode was overridden by FERRET_PRECOMMIT=0. An explicit flag is a " +
			"more specific request than an environment variable and must win.")
	}
}

// TestDetectionDoesNotDependOnTheWorkingDirectory.
//
// The removed last condition shelled out to `git rev-parse --git-dir` and looked for a hook file,
// so detection depended on where the process happened to start — and this repository's own
// directory satisfies it. That made the outcome differ between running the tool from inside a
// checkout and from anywhere else, on Windows only.
func TestDetectionDoesNotDependOnTheWorkingDirectory(t *testing.T) {
	clearAllTriggers(t)

	inRepo := NewPrecommitDetector().IsPrecommitEnvironment()

	tmp := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	outsideRepo := NewPrecommitDetector().IsPrecommitEnvironment()

	if inRepo != outsideRepo {
		t.Errorf("detection differs by working directory: inside this repo %v, in a temp dir %v.\n"+
			"Nothing about the cwd indicates a hook invocation.", inRepo, outsideRepo)
	}
	if inRepo {
		t.Error("detection fired with every trigger cleared — some signal outside the " +
			"environment is still deciding the mode")
	}
}
