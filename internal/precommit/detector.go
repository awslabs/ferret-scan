// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import (
	"os"
	"os/exec"
	"path/filepath"
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

	// Windows-specific detection: Check for Git Bash or Windows Git environment
	if runtime.GOOS == "windows" {
		if pd.detectWindowsGitEnvironment() {
			pd.isPrecommitEnv = true
			return
		}
	}

	pd.isPrecommitEnv = false
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

// detectWindowsGitEnvironment checks for Windows-specific Git and pre-commit indicators
func (pd *PrecommitDetector) detectWindowsGitEnvironment() bool {
	// Check for Git Bash environment variables
	if os.Getenv("MSYSTEM") != "" || os.Getenv("MINGW_PREFIX") != "" {
		return true
	}

	// Check for Windows Git environment variables
	if os.Getenv("GIT_EXEC_PATH") != "" {
		return true
	}

	// Check for PowerShell Git environment (GitHub Desktop, etc.)
	if os.Getenv("GITHUB_DESKTOP") != "" {
		return true
	}

	// Check for Windows-specific pre-commit indicators
	if os.Getenv("COMSPEC") != "" {
		// Check if we're running in a batch script context that might be pre-commit
		if strings.Contains(strings.ToLower(os.Getenv("COMSPEC")), "cmd.exe") {
			// Look for pre-commit related environment variables that might be set by batch scripts
			if os.Getenv("PRE_COMMIT_HOOK") != "" || os.Getenv("GIT_HOOK_TYPE") != "" {
				return true
			}
		}
	}

	// Check if Git is available and we're in a Git repository
	if pd.isInGitRepository() {
		// Additional check for pre-commit hooks directory
		if pd.hasPrecommitHooks() {
			return true
		}
	}

	return false
}

// isInGitRepository checks if the current directory is within a Git repository
func (pd *PrecommitDetector) isInGitRepository() bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	err := cmd.Run()
	return err == nil
}

// hasPrecommitHooks checks if pre-commit hooks are installed in the current Git repository
func (pd *PrecommitDetector) hasPrecommitHooks() bool {
	// Try to find .git directory
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	gitDir := strings.TrimSpace(string(output))
	hooksDir := filepath.Join(gitDir, "hooks")

	// Check for pre-commit hook file
	precommitHook := filepath.Join(hooksDir, "pre-commit")
	if runtime.GOOS == "windows" {
		// On Windows, also check for .bat extension
		if _, err := os.Stat(precommitHook + ".bat"); err == nil {
			return true
		}
	}

	if _, err := os.Stat(precommitHook); err == nil {
		return true
	}

	return false
}

// GetWindowsExitCode returns Windows-appropriate exit codes for batch script compatibility
func GetWindowsExitCode(hasFindings bool, hasErrors bool, confidenceLevel string, config *PrecommitConfig) int {
	if runtime.GOOS != "windows" {
		return GetExitCode(hasFindings, hasErrors, confidenceLevel, config)
	}

	// Windows batch scripts expect specific exit codes
	// Use standard Windows conventions:
	// 0 = Success
	// 1 = General error or findings that should block
	// 2 = System/critical error
	// 3 = Invalid usage/configuration

	// Exit code 2 for system errors (highest priority)
	if hasErrors {
		return 2
	}

	// Exit code 1 for findings that should block commit
	if hasFindings && config != nil && config.ShouldExitOnFindings(confidenceLevel) {
		return 1
	}

	// Exit code 0 for success or non-blocking findings
	return 0
}

// GetExitCode returns appropriate exit code based on findings and errors
func GetExitCode(hasFindings bool, hasErrors bool, confidenceLevel string, config *PrecommitConfig) int {
	// Use Windows-specific exit codes on Windows
	if runtime.GOOS == "windows" {
		return GetWindowsExitCode(hasFindings, hasErrors, confidenceLevel, config)
	}

	// Exit code 2 for system errors (highest priority)
	if hasErrors {
		return 2
	}

	// Exit code 1 for findings that should block commit
	if hasFindings && config != nil && config.ShouldExitOnFindings(confidenceLevel) {
		return 1
	}

	// Exit code 0 for success or non-blocking findings
	return 0
}
