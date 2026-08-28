// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// PrecommitDetector handles detection of pre-commit environment and provides optimized configuration
type PrecommitDetector struct {
	isPrecommitEnv bool
	config         *PrecommitConfig
}

// PrecommitConfig contains pre-commit specific configuration settings
type PrecommitConfig struct {
	QuietMode      bool
	NoColor        bool
	ExitOnFirst    bool
	BatchSize      int
	Format         string
	ExitOnFindings string // "high", "medium", "low", "none"
	ProfileName    string // Suggested profile name for pre-commit
}

// NewPrecommitDetector creates a new PrecommitDetector instance
func NewPrecommitDetector() *PrecommitDetector {
	detector := &PrecommitDetector{}
	detector.detectEnvironment()
	detector.generateOptimizedConfig()
	return detector
}

// NewPrecommitDetectorWithFlag creates a new PrecommitDetector instance with explicit flag override
func NewPrecommitDetectorWithFlag(explicitMode bool) *PrecommitDetector {
	detector := &PrecommitDetector{}
	detector.detectEnvironment()

	// Override environment detection if explicit mode is enabled
	if explicitMode {
		detector.isPrecommitEnv = true
	}

	detector.generateOptimizedConfig()
	return detector
}

// IsPrecommitEnvironment returns true if running in a pre-commit environment
func (pd *PrecommitDetector) IsPrecommitEnvironment() bool {
	return pd.isPrecommitEnv
}

// GetOptimizedConfig returns pre-commit optimized configuration settings
func (pd *PrecommitDetector) GetOptimizedConfig() *PrecommitConfig {
	return pd.config
}

// GetSuggestedProfile returns the suggested profile name for pre-commit environment
func (pd *PrecommitDetector) GetSuggestedProfile() string {
	if pd.config != nil {
		return pd.config.ProfileName
	}
	return ""
}

// detectEnvironment checks for pre-commit environment indicators
func (pd *PrecommitDetector) detectEnvironment() {
	// An explicit opt-out wins over every signal below.
	if precommitOptOut() {
		pd.isPrecommitEnv = false
		return
	}

	// Primary detection: PRE_COMMIT environment variable
	if os.Getenv("PRE_COMMIT") != "" {
		pd.isPrecommitEnv = true
		return
	}

	// Secondary detection: _PRE_COMMIT_RUNNING (set by some pre-commit versions)
	if os.Getenv("_PRE_COMMIT_RUNNING") != "" {
		pd.isPrecommitEnv = true
		return
	}

	// Tertiary detection: PRE_COMMIT_HOME (indicates pre-commit installation)
	if os.Getenv("PRE_COMMIT_HOME") != "" {
		pd.isPrecommitEnv = true
		return
	}

	// Hook-specific detection, cross-platform.
	//
	// PRE_COMMIT_HOOK and GIT_HOOK_TYPE name a hook INVOCATION, so unlike the signals
	// removed below they mean what this detector is asking. They were previously reachable
	// only on Windows and only when COMSPEC named cmd.exe, which made the same hook behave
	// differently depending on the shell that ran it.
	if os.Getenv("PRE_COMMIT_HOOK") != "" || os.Getenv("GIT_HOOK_TYPE") != "" {
		pd.isPrecommitEnv = true
		return
	}

	pd.isPrecommitEnv = false
}

// precommitOptOut reports whether the operator has explicitly said this is not a pre-commit run.
//
// Detection changes quiet mode, colour and exit-code semantics, and there was no way to decline
// it: FERRET_PRECOMMIT_BATCH_SIZE, FERRET_PRECOMMIT_EXIT_ON and FERRET_PRECOMMIT_EXIT_ON_FIRST
// could tune the behaviour but nothing could switch it off (#353). A caller inside a genuine hook
// who wants ordinary output now has a way to ask for it.
//
// Accepts the values Go's strconv.ParseBool rejects a run for: "0", "false", "f", "FALSE", "F".
// Anything else, including an empty value, leaves detection alone — so setting the variable to "1"
// is not a way to force pre-commit mode on; --pre-commit-mode already does that explicitly.
func precommitOptOut() bool {
	v := os.Getenv("FERRET_PRECOMMIT")
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && !b
}

// generateOptimizedConfig creates optimized settings for pre-commit environment
func (pd *PrecommitDetector) generateOptimizedConfig() {
	config := &PrecommitConfig{
		QuietMode:      pd.isPrecommitEnv, // Enable quiet mode in pre-commit
		NoColor:        pd.isPrecommitEnv, // Disable colors in pre-commit
		ExitOnFirst:    false,             // Process all files by default
		BatchSize:      50,                // Reasonable batch size for pre-commit
		Format:         "text",            // Default format for pre-commit
		ExitOnFindings: "high",            // Exit on high confidence findings by default
		ProfileName:    "precommit",       // Suggest precommit profile when in pre-commit environment
	}

	// Windows-specific configuration adjustments
	if runtime.GOOS == "windows" {
		pd.applyWindowsConfigOptimizations(config)
	}

	// Allow environment variable overrides for batch size
	if batchSizeStr := os.Getenv("FERRET_PRECOMMIT_BATCH_SIZE"); batchSizeStr != "" {
		if batchSize, err := strconv.Atoi(batchSizeStr); err == nil && batchSize > 0 {
			config.BatchSize = batchSize
		}
	}

	// Allow environment variable override for exit behavior
	if exitOnFindings := os.Getenv("FERRET_PRECOMMIT_EXIT_ON"); exitOnFindings != "" {
		switch exitOnFindings {
		case "high", "medium", "low", "none":
			config.ExitOnFindings = exitOnFindings
		}
	}

	// Allow environment variable override for exit on first finding
	if exitOnFirstStr := os.Getenv("FERRET_PRECOMMIT_EXIT_ON_FIRST"); exitOnFirstStr != "" {
		if exitOnFirst, err := strconv.ParseBool(exitOnFirstStr); err == nil {
			config.ExitOnFirst = exitOnFirst
		}
	}

	pd.config = config
}

// applyWindowsConfigOptimizations applies Windows-specific configuration optimizations
func (pd *PrecommitDetector) applyWindowsConfigOptimizations(config *PrecommitConfig) {
	// Windows batch scripts may have different performance characteristics
	// Reduce batch size for better compatibility with Windows command prompt limitations
	if pd.isPrecommitEnv {
		config.BatchSize = 25 // Smaller batch size for Windows
	}

	// Check for Windows-specific environment variables that might affect configuration
	if os.Getenv("MSYSTEM") != "" {
		// Running in Git Bash/MSYS2 - can handle more like Unix
		config.BatchSize = 50
	}

	// Check for PowerShell environment
	if os.Getenv("PSModulePath") != "" {
		// Running in PowerShell - can handle larger batches
		config.BatchSize = 75
	}

	// Windows Command Prompt has limitations with long command lines
	if os.Getenv("COMSPEC") != "" && strings.Contains(strings.ToLower(os.Getenv("COMSPEC")), "cmd.exe") {
		// Running in cmd.exe - use smaller batch size
		config.BatchSize = 20
	}
}

// ShouldExitOnFindings determines if ferret-scan should exit based on confidence level
func (pd *PrecommitConfig) ShouldExitOnFindings(confidenceLevel string) bool {
	if pd.ExitOnFindings == "none" {
		return false
	}

	switch pd.ExitOnFindings {
	case "high":
		return confidenceLevel == "high"
	case "medium":
		return confidenceLevel == "high" || confidenceLevel == "medium"
	case "low":
		return confidenceLevel == "high" || confidenceLevel == "medium" || confidenceLevel == "low"
	default:
		return confidenceLevel == "high" // Default to high confidence only
	}
}

// detectWindowsGitEnvironment has been removed (#353).
//
// It ran only on Windows and treated a Git ENVIRONMENT as a hook INVOCATION. Each of these
// independently returned true, and the first is the one that mattered: Git Bash always sets
// MSYSTEM, so every Windows developer running ferret-scan from the usual shell was silently
// treated as being inside a pre-commit hook.
//
//	MSYSTEM, MINGW_PREFIX            set by Git Bash, always
//	GIT_EXEC_PATH                    set by Git whenever git runs a subprocess
//	GITHUB_DESKTOP                   set by GitHub Desktop
//	cwd is a git repo AND has a
//	  .git/hooks/pre-commit file     true for anyone working in a repo that uses pre-commit,
//	                                 whether or not a hook is running — and Windows-only, so
//	                                 the same repository behaved differently per platform
//
// Detection then set QuietMode, NoColor, Format "text" and ExitOnFindings "high", so an
// ordinary scan lost its colour, was forced to text and acquired hook exit-code semantics.
// #351 fixed the format half by letting an explicit --format win; the rest is fixed here by
// not making the inference in the first place.
//
// PRE_COMMIT_HOOK and GIT_HOOK_TYPE survive, in detectEnvironment and on every platform,
// because they name a hook invocation rather than a Git installation. The cross-platform
// PRE_COMMIT / _PRE_COMMIT_RUNNING / PRE_COMMIT_HOME are set by pre-commit itself and were
// always the precise signals.

// A BLOCKING FINDING OUTRANKS A PROCESSING ERROR.
//
// Both exit-code functions used to test hasErrors first, so a scan that found a
// real secret AND failed to read some unrelated file exited 2 instead of 1. That
// is not a cosmetic difference: a pre-commit hook reads 2 as "the tool broke" and
// 1 as "your commit contains a secret". Downgrading the second to the first turns
// a security stop into an infrastructure blip, and the commit proceeds.
//
// Reproduced before the change, same secret in every run:
//
//	leak alone                      rc=1  (blocked)
//	leak + a clean file             rc=1  (blocked)
//	leak + one unextractable file   rc=2  (read as a tool failure)
//
// One `.docx` that is really plain text is enough, and needs no attacker: an
// export pipeline that mislabels a file silently unblocks every secret in the
// commit. As an attack it is cheaper still — rename a file, and the hook stops
// enforcing.
//
// So findings are now checked FIRST. Errors still produce 2, but only when there
// is nothing worse to report. Nothing is hidden either way: the failed-file
// warning is written by the caller regardless of which code is returned, so a run
// that exits 1 with unreadable files still says so on stderr.
//
// exitCodeFor holds the single copy of that precedence. It used to be duplicated,
// which is how both copies came to carry the identical inversion.
func exitCodeFor(hasFindings bool, hasErrors bool, confidenceLevel string, config *PrecommitConfig) int {
	// A finding the config says should block outranks everything: this is the
	// answer that stops a commit.
	if hasFindings && config != nil && config.ShouldExitOnFindings(confidenceLevel) {
		return 1
	}

	// No blocking finding, but the scan could not read everything it was given.
	// The result is incomplete, so it must not read as a clean pass.
	if hasErrors {
		return 2
	}

	// Clean, or findings below the configured blocking threshold.
	return 0
}

// GetWindowsExitCode returns Windows-appropriate exit codes for batch script
// compatibility.
//
// The values match the Unix path deliberately, and always did:
//
//	0 = success
//	1 = findings that should block the commit
//	2 = system/critical error
//	3 = invalid usage/configuration (returned elsewhere)
//
// Windows batch scripts read the same numbers, so the two functions exist for
// documentation rather than for divergent behaviour. Both now delegate to
// exitCodeFor so they cannot drift again.
func GetWindowsExitCode(hasFindings bool, hasErrors bool, confidenceLevel string, config *PrecommitConfig) int {
	return exitCodeFor(hasFindings, hasErrors, confidenceLevel, config)
}

// GetExitCode returns the appropriate exit code based on findings and errors.
func GetExitCode(hasFindings bool, hasErrors bool, confidenceLevel string, config *PrecommitConfig) int {
	return exitCodeFor(hasFindings, hasErrors, confidenceLevel, config)
}

// isInGitRepository and hasPrecommitHooks were removed with detectWindowsGitEnvironment (#353).
//
// Together they formed its last condition — "the working directory is a git repository AND it has
// a pre-commit hook file" — which is true for anyone working inside a repo that uses pre-commit,
// running or not. They also shelled out to `git rev-parse --git-dir` on every scan to answer a
// question that no longer needs asking.
