// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/gitignore"
	"github.com/awslabs/ferret-scan/v2/internal/precommit"
	"github.com/awslabs/ferret-scan/v2/internal/version"
	"github.com/awslabs/ferret-scan/v2/internal/web"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/help"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/validators"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"

	"golang.org/x/term"

	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// exitCodeIncompleteCoverage is returned when --fail-on-incomplete is set and at
// least one file was not fully scanned — either its validator coverage was cut short
// (timeout, cancellation, or a per-validator budget) or the file could not be opened
// at all (permissions, a dangling symlink, deletion mid-scan). It is distinct from
// the other CLI exit codes — 0 (clean), 1 (system/usage error), and 2 (no files to
// process) — so CI can tell degraded coverage apart from a genuinely clean scan.
const exitCodeIncompleteCoverage = 3

// resolveIncompleteExitCode applies the --fail-on-incomplete policy on top of a
// base exit code: when enabled and coverage was incomplete, an otherwise-clean
// result (base 0) escalates to exitCodeIncompleteCoverage, but a non-zero base
// (findings/errors the caller already fails on) is never downgraded. It is a pure
// function so both the file and stdin paths share one tested decision.
func resolveIncompleteExitCode(base int, failOnIncomplete bool, incompleteCount int) int {
	if failOnIncomplete && incompleteCount > 0 && base == 0 {
		return exitCodeIncompleteCoverage
	}
	return base
}

// loadConfiguration loads the configuration file or returns default config.
//
// When the user passes an explicit --config <path> flag, parse errors and
// missing files are fatal so YAML escape gotchas and typo'd paths surface
// immediately instead of being silently swallowed. When configFile is empty,
// auto-discovery is best-effort (LoadConfigOrDefault) and falls back to
// built-in defaults with a stderr warning.
func loadConfiguration(configFile string) *config.Config {
	if configFile != "" {
		cfg, err := config.LoadConfigStrict(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			fmt.Fprintf(os.Stderr,
				"Hint: regex values in YAML need single-quoted or unquoted "+
					"scalars; double-quoted strings process \\b, \\s, etc. "+
					"as escape sequences. Either drop the quotes, switch to "+
					"single quotes, or double every backslash inside double "+
					"quotes (e.g. \"\\\\b(...)\\\\b\").\n")
			os.Exit(1)
		}
		return cfg
	}
	cfg := config.LoadConfigOrDefault(configFile)
	if cfg == nil {
		fmt.Fprintf(os.Stderr, "Warning: Error loading config file, using defaults\n")
		cfg, _ = config.LoadConfig("")
	}
	return cfg
}

// reportConfigProvenance names a config file that was DISCOVERED next to the working
// directory, so the user learns which file is governing the scan.
//
// It reports only the auto-discovered, working-directory case, and deliberately stays
// quiet for the other two:
//
//   - an explicit --config <path> is the user's own choice, so naming it back is noise;
//   - the user config dir is a standing personal preference, equally unsurprising.
//
// The working-directory case is the one nobody chose per-run. FindConfigFile searches
// the CWD before anything else, so a config.yaml or .ferret-scan.yaml sitting beside the
// scanned content wins, and such a config can switch off whole detection categories via
// validators.<name>.disabled_types. Measured: identical binary, flags and input went
// from 1 finding to 0 because of a file dropped next to the content, with nothing in the
// output naming it.
//
// That is a trust boundary the threat model does not evaluate. TB-7 already covers "an
// outside contributor's PR run through a maintainer's pre-commit/CI" and TM-11 covers
// that attacker driving confidence to zero through attacker-authored CONTENT; adding a
// config file to the same PR reaches the same outcome more directly, and for a hook or
// CI job running from the repository root it is the shorter path. This line does not
// close that hole — see #293 for the opt-in gating decision, which is a policy call —
// but it turns an invisible substitution into a reviewable one.
//
// NOT gated on --quiet. That flag suppresses progress output; which config governed the
// run is a disclosure, and in CI (where --quiet is most used) it matters more, not less.
func reportConfigProvenance(w io.Writer, cfg *config.Config, explicitConfigFlag string) {
	if w == nil || cfg == nil || cfg.SourcePath == "" {
		return
	}
	// The user asked for this file by name; do not read it back to them.
	if explicitConfigFlag != "" {
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	abs, err := filepath.Abs(cfg.SourcePath)
	if err != nil {
		return
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// Outside the working directory: the user config dir or similar. Expected.
		return
	}
	fmt.Fprintf(w,
		"Note: using project config %s found in the working directory; "+
			"it can disable detection types.\n", rel)
}

// warnUnknownConfigKeys reports config keys the schema does not recognize.
//
// Unknown keys are not an error — rejecting them would break any config written
// against an older or newer version, including this project's own shipped
// config.yaml before these keys were reconciled. But silence is worse: a typo'd
// option name looks exactly like a working one, so the setting is never applied
// and the user has no way to tell. This is the same courtesy the cloud_resources
// validator already extends for its own sub-keys.
//
// The warnings go to w rather than straight to os.Stderr because stderr is not
// always a human channel: in stdin redaction mode the findings document IS
// stderr, and prose there breaks `2> findings.json`. Callers pass io.Discard when
// shouldSuppressStdinProse says to stay quiet.
func warnUnknownConfigKeys(w io.Writer, cfg *config.Config) {
	if cfg == nil || w == nil {
		return
	}
	for _, key := range cfg.UnknownKeys {
		fmt.Fprintf(w,
			"Warning: unknown config key %q — ignored (check for a typo)\n", key)
	}
}

// configFlags holds command line flag values
type configFlags struct {
	outputFormat         string
	confidenceLevels     string
	checksToRun          string
	verbose              bool
	debug                bool
	noColor              bool
	recursive            bool
	enablePreprocessors  bool
	preprocessOnly       bool
	precommitMode        bool
	excludePatterns      []string
	respectGitignore     bool
	showMatch            bool
	quiet                bool
	showSuppressed       bool
	generateSuppressions bool
	failOnIncomplete     bool
	suppressionFile      string
	// Redaction flags
	enableRedaction    bool
	redactionOutputDir string
	redactionStrategy  string
	redactionAuditLog  string
	disableIPTypes     string
}

// finalConfiguration holds resolved configuration values
type finalConfiguration struct {
	format              string
	confidenceLevels    string
	checksToRun         string
	verbose             bool
	debug               bool
	noColor             bool
	recursive           bool
	enablePreprocessors bool
	preprocessOnly      bool
	precommitMode       bool
	// Redaction configuration
	enableRedaction      bool
	redactionOutputDir   string
	redactionStrategy    string
	redactionAuditLog    string
	excludePatterns      []string
	respectGitignore     bool
	showMatch            bool
	quiet                bool
	showSuppressed       bool
	generateSuppressions bool
	failOnIncomplete     bool
	suppressionFile      string
	disableIPTypes       string
}

// resolveConfiguration resolves final configuration values from config file, profile, and command line flags
func resolveConfiguration(cfg *config.Config, activeProfile *config.Profile, flags *configFlags) *finalConfiguration {
	final := &finalConfiguration{}

	// Format
	final.format = "text" // default fallback
	if cfg != nil && cfg.Defaults.Format != "" {
		final.format = cfg.Defaults.Format
	}
	if activeProfile != nil && activeProfile.Format != "" {
		final.format = activeProfile.Format
	}
	if isFlagSet("format") && flags.outputFormat != "" {
		final.format = flags.outputFormat
	}

	// Confidence levels
	final.confidenceLevels = "all" // default fallback
	if cfg != nil && cfg.Defaults.ConfidenceLevels != "" {
		final.confidenceLevels = cfg.Defaults.ConfidenceLevels
	}
	if activeProfile != nil && activeProfile.ConfidenceLevels != "" {
		final.confidenceLevels = activeProfile.ConfidenceLevels
	}
	if isFlagSet("confidence") && flags.confidenceLevels != "" {
		final.confidenceLevels = flags.confidenceLevels
	}

	// Checks to run
	final.checksToRun = "all" // default fallback
	if cfg != nil && cfg.Defaults.Checks != "" {
		final.checksToRun = cfg.Defaults.Checks
	}
	if activeProfile != nil && activeProfile.Checks != "" {
		final.checksToRun = activeProfile.Checks
	}
	if isFlagSet("checks") && flags.checksToRun != "" {
		final.checksToRun = flags.checksToRun
	}

	// Verbose
	final.verbose = false // default fallback
	if cfg != nil {
		final.verbose = cfg.Defaults.Verbose
	}
	if activeProfile != nil {
		final.verbose = activeProfile.Verbose
	}
	if isFlagSet("verbose") {
		final.verbose = flags.verbose
	}

	// Debug
	final.debug = false // default fallback
	if cfg != nil {
		final.debug = cfg.Defaults.Debug
	}
	if activeProfile != nil {
		final.debug = activeProfile.Debug
	}
	if isFlagSet("debug") {
		final.debug = flags.debug
	}

	// No color
	final.noColor = false // default fallback
	if cfg != nil {
		final.noColor = cfg.Defaults.NoColor
	}
	if activeProfile != nil {
		final.noColor = activeProfile.NoColor
	}
	if isFlagSet("no-color") {
		final.noColor = flags.noColor
	}

	// Recursive
	final.recursive = false // default fallback
	if cfg != nil {
		final.recursive = cfg.Defaults.Recursive
	}
	if activeProfile != nil {
		final.recursive = activeProfile.Recursive
	}
	if isFlagSet("recursive") {
		final.recursive = flags.recursive
	}

	// Enable preprocessors
	final.enablePreprocessors = true // default fallback
	if cfg != nil {
		final.enablePreprocessors = cfg.Defaults.EnablePreprocessors
	}
	if activeProfile != nil {
		final.enablePreprocessors = activeProfile.EnablePreprocessors
	}
	if isFlagSet("enable-preprocessors") {
		final.enablePreprocessors = flags.enablePreprocessors
	}

	// Preprocess only
	final.preprocessOnly = false // default fallback
	if isFlagSet("preprocess-only") || isFlagSet("p") {
		final.preprocessOnly = flags.preprocessOnly
	}

	// Pre-commit mode
	final.precommitMode = false // default fallback
	if isFlagSet("pre-commit-mode") {
		final.precommitMode = flags.precommitMode
	}

	// Redaction configuration
	final.enableRedaction = false // default fallback
	if cfg != nil {
		final.enableRedaction = cfg.Redaction.Enabled
	}
	if activeProfile != nil {
		final.enableRedaction = activeProfile.Redaction.Enabled
	}
	if isFlagSet("enable-redaction") {
		final.enableRedaction = flags.enableRedaction
	}

	final.redactionOutputDir = "./redacted" // default fallback
	if cfg != nil && cfg.Redaction.OutputDir != "" {
		final.redactionOutputDir = cfg.Redaction.OutputDir
	}
	if activeProfile != nil && activeProfile.Redaction.OutputDir != "" {
		final.redactionOutputDir = activeProfile.Redaction.OutputDir
	}
	if isFlagSet("redaction-output-dir") && flags.redactionOutputDir != "" {
		final.redactionOutputDir = flags.redactionOutputDir
	}

	final.redactionStrategy = "format_preserving" // default fallback
	if cfg != nil && cfg.Redaction.Strategy != "" {
		final.redactionStrategy = cfg.Redaction.Strategy
	}
	if activeProfile != nil && activeProfile.Redaction.Strategy != "" {
		final.redactionStrategy = activeProfile.Redaction.Strategy
	}
	if isFlagSet("redaction-strategy") && flags.redactionStrategy != "" {
		final.redactionStrategy = flags.redactionStrategy
	}

	final.redactionAuditLog = "" // default fallback (no audit log file)
	if cfg != nil && cfg.Redaction.IndexFile != "" {
		final.redactionAuditLog = cfg.Redaction.IndexFile
	}
	if activeProfile != nil && activeProfile.Redaction.IndexFile != "" {
		final.redactionAuditLog = activeProfile.Redaction.IndexFile
	}
	if isFlagSet("redaction-audit-log") && flags.redactionAuditLog != "" {
		final.redactionAuditLog = flags.redactionAuditLog
	}

	// Exclude patterns
	final.excludePatterns = []string{} // default fallback (no exclusions)
	if cfg != nil && len(cfg.Defaults.ExcludePatterns) > 0 {
		final.excludePatterns = cfg.Defaults.ExcludePatterns
	}
	if activeProfile != nil && len(activeProfile.ExcludePatterns) > 0 {
		final.excludePatterns = activeProfile.ExcludePatterns
	}
	if isFlagSet("exclude") && len(flags.excludePatterns) > 0 {
		final.excludePatterns = flags.excludePatterns
	}

	// Respect .gitignore (opt-in)
	final.respectGitignore = false // default fallback
	if cfg != nil {
		final.respectGitignore = cfg.Defaults.RespectGitignore
	}
	if activeProfile != nil {
		final.respectGitignore = activeProfile.RespectGitignore
	}
	if isFlagSet("respect-gitignore") {
		final.respectGitignore = flags.respectGitignore
	}

	// Show actual matched text in findings
	final.showMatch = false // default fallback
	if cfg != nil {
		final.showMatch = cfg.Defaults.ShowMatch
	}
	if activeProfile != nil {
		final.showMatch = activeProfile.ShowMatch
	}
	if isFlagSet("show-match") {
		final.showMatch = flags.showMatch
	}

	// Suppress progress output
	final.quiet = false // default fallback
	if cfg != nil {
		final.quiet = cfg.Defaults.Quiet
	}
	if activeProfile != nil {
		final.quiet = activeProfile.Quiet
	}
	if isFlagSet("quiet") {
		final.quiet = flags.quiet
	}

	// Include suppressed findings in output. The dedicated `suppressions:` block
	// is a peer of `defaults:`, so it is applied after it and before the profile.
	//
	// The two keys OR together: either can switch the behavior on, neither can
	// switch it back off. Both default to false and both mean "turn this on", so
	// there is no way to tell `suppressions.show_suppressed: false` apart from the
	// key being absent — treating an explicit false as an override would make
	// omitting the key silently disable defaults.show_suppressed.
	final.showSuppressed = false // default fallback
	if cfg != nil {
		final.showSuppressed = cfg.Defaults.ShowSuppressed || cfg.Suppressions.ShowSuppressed
	}
	if activeProfile != nil {
		final.showSuppressed = activeProfile.ShowSuppressed
	}
	if isFlagSet("show-suppressed") {
		final.showSuppressed = flags.showSuppressed
	}

	// Auto-generate suppression rules for all findings. Same OR semantics as
	// show_suppressed above.
	final.generateSuppressions = false // default fallback
	if cfg != nil {
		final.generateSuppressions = cfg.Defaults.GenerateSuppressions || cfg.Suppressions.GenerateOnScan
	}
	if activeProfile != nil {
		final.generateSuppressions = activeProfile.GenerateSuppressions
	}
	if isFlagSet("generate-suppressions") {
		final.generateSuppressions = flags.generateSuppressions
	}

	// Fail on incomplete coverage: config default -> profile -> flag (flag wins).
	final.failOnIncomplete = false // default fallback
	if cfg != nil {
		final.failOnIncomplete = cfg.Defaults.FailOnIncomplete
	}
	if activeProfile != nil {
		final.failOnIncomplete = activeProfile.FailOnIncomplete
	}
	if isFlagSet("fail-on-incomplete") {
		final.failOnIncomplete = flags.failOnIncomplete
	}

	// Suppression file: suppressions.file -> flag (flag wins). Empty means the
	// suppression manager picks its own platform default.
	final.suppressionFile = ""
	if cfg != nil {
		final.suppressionFile = cfg.Suppressions.File
	}
	if isFlagSet("suppression-file") && flags.suppressionFile != "" {
		final.suppressionFile = flags.suppressionFile
	}

	// Disable IP types
	if isFlagSet("disable-ip-types") && flags.disableIPTypes != "" {
		final.disableIPTypes = flags.disableIPTypes
	}

	return final
}

// processPreprocessOnly handles preprocess-only mode
func processPreprocessOnly(supportedFiles []string, fileRouter *router.FileRouter, finalConfig *finalConfiguration) error {
	if len(supportedFiles) == 0 {
		fmt.Println("No files to preprocess")
		return nil
	}

	// Check if preprocessors are enabled
	if !finalConfig.enablePreprocessors {
		fmt.Fprintf(os.Stderr, "Error: Preprocessors are disabled. Enable with --enable-preprocessors\n")
		return fmt.Errorf("preprocessors disabled")
	}

	processedCount := 0
	errorCount := 0

	for i, filePath := range supportedFiles {
		// Add separator between files (except for the first file)
		if i > 0 {
			fmt.Println()
		}

		// Print file header
		fmt.Printf("=== FILE: %s ===\n", filePath)

		// Enhanced file access error handling
		if _, err := os.Stat(filePath); err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("Status: Error - File not found: %s\n", filePath)
			} else if os.IsPermission(err) {
				fmt.Printf("Status: Error - Permission denied: %s\n", filePath)
			} else {
				fmt.Printf("Status: Error - File access error: %v\n", err)
			}
			errorCount++
			continue
		}

		// Check if file can be processed
		canProcess, reason := fileRouter.CanProcessFile(filePath, finalConfig.enablePreprocessors)
		if !canProcess {
			// Enhanced error messages for unsupported file types
			if strings.Contains(reason, "Unsupported file type") {
				ext := strings.ToLower(filepath.Ext(filePath))
				if ext == "" {
					fmt.Printf("Status: Error - No file extension detected, cannot determine file type\n")
				} else {
					fmt.Printf("Status: Error - Unsupported file type '%s' - no preprocessor available\n", ext)
				}
			} else {
				fmt.Printf("Status: Error - %s\n", reason)
			}
			errorCount++
			continue
		}

		// Create processing context with enhanced error handling
		processingContext, err := fileRouter.CreateProcessingContext(filePath, finalConfig.debug)
		if err != nil {
			// Provide more specific error messages
			if strings.Contains(err.Error(), "permission") {
				fmt.Printf("Status: Error - Permission denied accessing file: %v\n", err)
			} else if strings.Contains(err.Error(), "not found") {
				fmt.Printf("Status: Error - File not found during context creation: %v\n", err)
			} else {
				fmt.Printf("Status: Error - Failed to create processing context: %v\n", err)
			}
			errorCount++
			continue
		}

		// Process the file with enhanced error handling
		processedContent, err := fileRouter.ProcessFileWithContext(filePath, processingContext)
		if err != nil {
			// Provide meaningful error messages for preprocessing failures
			if strings.Contains(err.Error(), "no preprocessor can handle") {
				fmt.Printf("Status: Error - No suitable preprocessor found for this file type\n")
			} else if strings.Contains(err.Error(), "all preprocessors failed") {
				fmt.Printf("Status: Error - All available preprocessors failed to process this file\n")
			} else if strings.Contains(err.Error(), "permission") {
				fmt.Printf("Status: Error - Permission denied reading file: %v\n", err)
			} else if strings.Contains(err.Error(), "not found") {
				fmt.Printf("Status: Error - File not found during processing: %v\n", err)
			} else {
				fmt.Printf("Status: Error - Preprocessing failed: %v\n", err)
			}
			errorCount++
			continue
		}

		// Check if processing was successful with enhanced error reporting
		if processedContent == nil || !processedContent.Success {
			if processedContent != nil && processedContent.Error != nil {
				// Provide more specific error messages based on the error type
				errMsg := processedContent.Error.Error()
				if strings.Contains(errMsg, "corrupted") || strings.Contains(errMsg, "invalid") {
					fmt.Printf("Status: Error - File appears to be corrupted or invalid: %v\n", processedContent.Error)
				} else if strings.Contains(errMsg, "encrypted") || strings.Contains(errMsg, "password") {
					fmt.Printf("Status: Error - File is encrypted or password-protected: %v\n", processedContent.Error)
				} else if strings.Contains(errMsg, "format") {
					fmt.Printf("Status: Error - Unsupported or invalid file format: %v\n", processedContent.Error)
				} else {
					fmt.Printf("Status: Error - %v\n", processedContent.Error)
				}
			} else {
				fmt.Printf("Status: Error - Preprocessing failed with no specific error details\n")
			}
			errorCount++
			continue
		}

		// Display processor information and status
		fmt.Printf("Processor: %s\n", processedContent.ProcessorType)
		fmt.Printf("Status: Success\n")

		// Check if there's any extracted text with enhanced messaging
		if processedContent.Text == "" {
			// Provide more specific messages based on file type and processor
			if strings.Contains(processedContent.ProcessorType, "PDF") {
				fmt.Printf("\n[No text content found - PDF may contain only images or be empty]\n")
			} else if strings.Contains(processedContent.ProcessorType, "Office") {
				fmt.Printf("\n[No text content found - document may be empty or contain only images/objects]\n")
			} else if strings.Contains(processedContent.ProcessorType, "Image") {
				fmt.Printf("\n[No text content found - image may not contain readable text]\n")
			} else {
				fmt.Printf("\n[No preprocessable content found]\n")
			}
		} else {
			// Display metadata if available
			if processedContent.WordCount > 0 || processedContent.CharCount > 0 {
				fmt.Printf("Content: %d words, %d characters", processedContent.WordCount, processedContent.CharCount)
				if processedContent.PageCount > 0 {
					fmt.Printf(", %d pages", processedContent.PageCount)
				}
				fmt.Printf("\n")
			}

			// Output the preprocessed text
			fmt.Printf("\n%s\n", processedContent.Text)
		}

		processedCount++
	}

	// Print summary if processing multiple files
	if len(supportedFiles) > 1 {
		fmt.Printf("\n=== SUMMARY ===\n")
		fmt.Printf("Files processed: %d\n", processedCount)
		if errorCount > 0 {
			fmt.Printf("Files with errors: %d\n", errorCount)
		}
	}

	return nil
}

// handleProfiles handles profile listing and selection
func handleProfiles(cfg *config.Config, listProfiles bool, profileName, configFile string, precommitConfig *precommit.PrecommitConfig) *config.Profile {
	// List profiles if requested
	if listProfiles {
		if configFile == "" {
			fmt.Println("No configuration file found. No profiles available.")
			os.Exit(0)
		}

		profiles := cfg.ListProfiles()
		if len(profiles) == 0 {
			fmt.Println("No profiles defined in configuration file.")
		} else {
			fmt.Println("Available profiles:")
			for _, name := range profiles {
				profile := cfg.GetProfile(name)
				if profile != nil && profile.Description != "" {
					fmt.Printf("  - %s: %s\n", name, profile.Description)
				} else {
					fmt.Printf("  - %s\n", name)
				}
			}
		}
		os.Exit(0)
	}

	// Apply profile settings if specified
	var activeProfile *config.Profile
	if profileName != "" {
		if cfg == nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Cannot use profile '%s' - no configuration loaded", profileName),
				"Check that config file exists and is readable")
			os.Exit(1)
		}
		activeProfile = cfg.GetProfile(profileName)
		if activeProfile == nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Profile '%s' not found in config file", profileName),
				"Check available profiles with --help or verify config file")
			os.Exit(1)
		}
	}
	return activeProfile
}

// getBoolFlag safely gets the value of a boolean flag pointer, returning false if nil
func getBoolFlag(flag *bool) bool {
	if flag != nil {
		return *flag
	}
	return false
}

// getStringFlag safely gets the value of a string flag pointer, returning empty string if nil
func getStringFlag(flag *string) string {
	if flag != nil {
		return *flag
	}
	return ""
}

// setBoolFlag safely sets the value of a boolean flag pointer if it's not nil
func setBoolFlag(flag *bool, value bool) {
	if flag != nil {
		*flag = value
	}
}

// shouldSuppressProgressOutput determines if progress output should be suppressed
func shouldSuppressProgressOutput(finalConfig *finalConfiguration, precommitConfig *precommit.PrecommitConfig, isInteractive bool) bool {
	suppress := finalConfig.debug || finalConfig.quiet || !isInteractive
	if precommitConfig != nil && precommitConfig.QuietMode {
		suppress = true
	}
	return suppress
}

// writeIncompleteCoverageWarning emits the v2 Phase 4 incomplete-coverage warning
// to w when any file's validator coverage was cut short (per-file/per-validator
// timeout, cancellation, or match budget). It returns true if a warning was
// written. The warning goes to stderr (never stdout/JSON, so scripts parsing
// results are unaffected) and is a CORRECTNESS signal — callers gate it only on
// pre-commit mode, not on quiet/non-interactive, because CI is exactly where a
// silently-partial scan is most dangerous. It never changes the exit code.
func writeIncompleteCoverageWarning(w io.Writer, incompleteFiles []parallel.FileDiagnostic, totalFiles int) bool {
	if len(incompleteFiles) == 0 {
		return false
	}
	fmt.Fprintf(w, "WARNING: scan coverage incomplete — %d of %d file(s) were not fully scanned; findings may be missing:\n",
		len(incompleteFiles), totalFiles)
	for _, fd := range incompleteFiles {
		fmt.Fprintf(w, "  %s: %s\n", fd.FilePath, fd.Reason)
	}
	return true
}

// writeUnredactedFilesWarning emits a warning to w for every file that HAS
// findings but for which no redacted copy could be written (no redactor is
// registered for the extension, or the write failed). It returns true if a
// warning was written.
//
// This is the counterpart to writeIncompleteCoverageWarning, and the two mean
// opposite things: incomplete coverage says findings may be MISSING, this says
// the findings were found and reported but the sensitive values were NOT
// redacted anywhere — they remain in cleartext at the original path with no
// shareable artifact. Silence here is the dangerous case, because the point of
// --enable-redaction is to produce those artifacts. Goes to stderr (never
// stdout/JSON) and never changes the exit code.
func writeUnredactedFilesWarning(w io.Writer, unredactedFiles []parallel.FileDiagnostic, totalFiles int) bool {
	if len(unredactedFiles) == 0 {
		return false
	}
	fmt.Fprintf(w, "WARNING: redaction incomplete — %d of %d file(s) have findings but no redacted copy was written; the original values remain in cleartext:\n",
		len(unredactedFiles), totalFiles)
	for _, fd := range unredactedFiles {
		fmt.Fprintf(w, "  %s: %s\n", fd.FilePath, fd.Reason)
	}
	return true
}

// writeEmptyExtractionWarning emits a warning to w for every file whose
// extraction succeeded but produced no document-body text, for a file type that
// carries one. It returns true if a warning was written.
//
// This is the fourth member of the family, and it covers the quietest failure of
// the four. The other three describe something that went wrong; this one describes
// a scan that reported success over nothing. An OOXML container's body is selected
// by part name, and a name we do not recognize — one differing only in case, say —
// yields zero extracted text. Zero extracted text was indistinguishable from a
// genuinely empty document: extraction returned Success with textLen 0, the router
// stamped Success:true, no output format mentioned it, and --fail-on-incomplete
// exited 0. So a 40-page document that contributed nothing to the scan read
// exactly like a blank one.
//
// Gated only on pre-commit mode, like its siblings. Goes to stderr (never
// stdout/JSON). It does not change the exit code by itself; these files are
// counted toward --fail-on-incomplete alongside cut-short and unreadable ones,
// which is the same opt-in escalation PR #235 gave unreadable files.
func writeEmptyExtractionWarning(w io.Writer, emptyFiles []parallel.FileDiagnostic, totalFiles int) bool {
	if len(emptyFiles) == 0 {
		return false
	}
	fmt.Fprintf(w, "WARNING: extraction empty — %d of %d file(s) yielded no document text, so their contents were NOT scanned; any sensitive data in them was NOT detected:\n",
		len(emptyFiles), totalFiles)
	for _, fd := range emptyFiles {
		fmt.Fprintf(w, "  %s: %s\n", fd.FilePath, fd.Reason)
	}
	return true
}

// writeFailedFilesWarning emits a warning to w for every file whose processing
// returned an error, so it was never scanned. It returns true if a warning was
// written.
//
// The fifth member of the family, and it existed because of the worst gap of the
// five: these files were counted as NEITHER processed nor skipped. The collector
// logged the error and fell through without incrementing a counter or recording a
// diagnostic, so the file left no trace at all. Measured on six files where five
// were unparseable containers: "Files: 1 processed, 0 skipped", no warning, and
// exit 0 even under --fail-on-incomplete. A corrupt or truncated document read
// exactly like a directory that had been fully scanned and found clean.
//
// Same conventions as its siblings: gated only on pre-commit mode, stderr only
// (never stdout/JSON), and it does not change the exit code by itself — these
// files are counted toward --fail-on-incomplete alongside cut-short, unreadable
// and empty-extraction ones.
func writeFailedFilesWarning(w io.Writer, failedFiles []parallel.FileDiagnostic, totalFiles int) bool {
	if len(failedFiles) == 0 {
		return false
	}
	fmt.Fprintf(w, "WARNING: processing failed — %d of %d file(s) could not be processed, so they were NOT scanned; any sensitive data in them was NOT detected:\n",
		len(failedFiles), totalFiles)
	for _, fd := range failedFiles {
		fmt.Fprintf(w, "  %s: %s\n", fd.FilePath, fd.Reason)
	}
	return true
}

// writeUnreadableFilesWarning emits a warning to w for every file that could not
// be opened or stat'ed — a permission error, a dangling symlink, a file deleted
// mid-scan. It returns true if a warning was written.
//
// This is the third member of the family alongside writeIncompleteCoverageWarning
// and writeUnredactedFilesWarning, and it covers the earliest failure: the file was
// never read at all. Before this existed, such a file was counted as an
// "unsupported type", so scanning a directory of .txt files with one unreadable
// member reported "1 files skipped (1 unsupported types)" — describing a supported
// extension as an unrecognized format, and giving no hint that a file which may be
// full of PII went unexamined. Scanning that file alone printed an empty result set
// and exited 0: a clean bill of health for a file the tool never opened.
//
// Gated only on pre-commit mode, like its siblings — not on quiet or
// non-interactive — because CI is exactly where an unnoticed unscanned file
// matters. Goes to stderr (never stdout/JSON). It does not change the exit code by
// itself, but these files are counted toward --fail-on-incomplete alongside
// cut-short scans, so CI can opt into failing on them.
func writeUnreadableFilesWarning(w io.Writer, unreadableFiles []string, totalFiles int) bool {
	if len(unreadableFiles) == 0 {
		return false
	}
	fmt.Fprintf(w, "WARNING: scan incomplete — %d of %d file(s) could not be opened, so they were not scanned at all; any sensitive data they contain was NOT detected:\n",
		len(unreadableFiles), totalFiles)
	for _, entry := range unreadableFiles {
		fmt.Fprintf(w, "  %s\n", entry)
	}
	return true
}

// extractedFlags holds safely extracted flag values to avoid repeated nil checks
type extractedFlags struct {
	webMode              bool
	webPort              string
	webBind              string
	inputFile            string
	configFile           string
	profileName          string
	listProfiles         bool
	outputFormat         string
	outputFile           string
	confidenceLevels     string
	checksToRun          string
	verbose              bool
	debug                bool
	quiet                bool
	noColor              bool
	recursive            bool
	enablePreprocessors  bool
	preprocessOnly       bool
	precommitMode        bool
	showMatch            bool
	showSuppressed       bool
	generateSuppressions bool
	failOnIncomplete     bool
	enableRedaction      bool
	redactionOutputDir   string
	redactionStrategy    string
	redactionAuditLog    string
	suppressionFile      string
	excludePatterns      []string
	respectGitignore     bool
	disableIPTypes       string
}

// flagPointers groups all flag pointers for easier management
type flagPointers struct {
	// Boolean flags
	webMode              *bool
	quiet                *bool
	debug                *bool
	noColor              *bool
	verbose              *bool
	recursive            *bool
	enablePreprocessors  *bool
	preprocessOnly       *bool
	preprocessOnlyShort  *bool
	precommitMode        *bool
	showMatch            *bool
	showSuppressed       *bool
	generateSuppressions *bool
	failOnIncomplete     *bool
	enableRedaction      *bool
	listProfiles         *bool
	respectGitignore     *bool

	// String flags
	webPort            *string
	webBind            *string
	inputFile          *string
	configFile         *string
	profileName        *string
	outputFormat       *string
	confidenceLevels   *string
	checksToRun        *string
	redactionOutputDir *string
	redactionStrategy  *string
	redactionAuditLog  *string
	outputFile         *string
	suppressionFile    *string
	excludePatterns    *string
	disableIPTypes     *string
}

// extractAllFlags safely extracts all flag values once to avoid repeated nil checks
func extractAllFlags(flags flagPointers) extractedFlags {
	return extractedFlags{
		webMode:              getBoolFlag(flags.webMode),
		webPort:              getStringFlag(flags.webPort),
		webBind:              getStringFlag(flags.webBind),
		inputFile:            getStringFlag(flags.inputFile),
		configFile:           getStringFlag(flags.configFile),
		profileName:          getStringFlag(flags.profileName),
		listProfiles:         getBoolFlag(flags.listProfiles),
		outputFormat:         getStringFlag(flags.outputFormat),
		confidenceLevels:     getStringFlag(flags.confidenceLevels),
		checksToRun:          getStringFlag(flags.checksToRun),
		verbose:              getBoolFlag(flags.verbose),
		debug:                getBoolFlag(flags.debug),
		quiet:                getBoolFlag(flags.quiet),
		noColor:              getBoolFlag(flags.noColor),
		recursive:            getBoolFlag(flags.recursive),
		enablePreprocessors:  getBoolFlag(flags.enablePreprocessors),
		preprocessOnly:       getBoolFlag(flags.preprocessOnly) || getBoolFlag(flags.preprocessOnlyShort),
		precommitMode:        getBoolFlag(flags.precommitMode),
		showMatch:            getBoolFlag(flags.showMatch),
		showSuppressed:       getBoolFlag(flags.showSuppressed),
		generateSuppressions: getBoolFlag(flags.generateSuppressions),
		failOnIncomplete:     getBoolFlag(flags.failOnIncomplete),
		enableRedaction:      getBoolFlag(flags.enableRedaction),
		redactionOutputDir:   getStringFlag(flags.redactionOutputDir),
		redactionStrategy:    getStringFlag(flags.redactionStrategy),
		redactionAuditLog:    getStringFlag(flags.redactionAuditLog),
		outputFile:           getStringFlag(flags.outputFile),
		suppressionFile:      getStringFlag(flags.suppressionFile),
		excludePatterns:      parseExcludePatterns(getStringFlag(flags.excludePatterns)),
		respectGitignore:     getBoolFlag(flags.respectGitignore),
		disableIPTypes:       getStringFlag(flags.disableIPTypes),
	}
}

// parseExcludePatterns parses comma-separated exclude patterns
func parseExcludePatterns(excludeStr string) []string {
	if excludeStr == "" {
		return []string{}
	}

	patterns := strings.Split(excludeStr, ",")
	var result []string
	for _, pattern := range patterns {
		trimmed := strings.TrimSpace(pattern)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func main() {
	// Parse command line flags
	inputFile := flag.String("file", "", "Path to the input file, directory, or glob pattern (e.g., *.pdf)")
	configFile := flag.String("config", "", "Path to configuration file (YAML)")
	profileName := flag.String("profile", "", "Profile name to use from config file")
	listProfiles := flag.Bool("list-profiles", false, "List available profiles in config file")
	outputFormat := flag.String("format", "", "Output format: text, json, csv, yaml, junit, gitlab-sast, sarif (default: text)")
	confidenceLevels := flag.String("confidence", "", "Confidence levels to display: high, medium, low, or combinations like 'high,medium'")
	checksToRun := flag.String("checks", "", "Specific checks to run: "+strings.Join(core.CheckNames(), ", ")+", all (default: all)")
	verbose := flag.Bool("verbose", false, "Display detailed information for each finding")
	debug := flag.Bool("debug", false, "Enable debug logging to show preprocessing and validation flow")
	outputFile := flag.String("output", "", "Path to output file (if not specified, output to stdout)")
	noColor := flag.Bool("no-color", false, "Disable colored output")
	showHelp := flag.Bool("help", false, "Show help information")
	showVersion := flag.Bool("version", false, "Show version information")
	showMatch := flag.Bool("show-match", false, "Display the actual matched text in findings")
	recursive := flag.Bool("recursive", false, "Recursively scan directories")
	enablePreprocessors := flag.Bool("enable-preprocessors", true, "Enable text extraction from documents (PDF, Office files) (default: true, use --enable-preprocessors=false to disable)")
	preprocessOnly := flag.Bool("preprocess-only", false, "Output preprocessed text and exit (no validation or redaction)")
	preprocessOnlyShort := flag.Bool("p", false, "Output preprocessed text and exit (alias for --preprocess-only)")
	explainFindings := flag.Bool("explain", false, "Annotate each finding with a plain-language rationale, a verdict (likely real/test/uncertain), and a drafted suppression reason. Fully offline; no data leaves the host.")
	suppressionFile := flag.String("suppression-file", "", "Path to suppression configuration file (default: $XDG_CONFIG_HOME/ferret-scan/suppressions.yaml on Unix, %APPDATA%\\ferret-scan\\suppressions.yaml on Windows)")
	generateSuppressions := flag.Bool("generate-suppressions", false, "Generate suppression rules for all findings (disabled by default, can be enabled in YAML)")

	showSuppressed := flag.Bool("show-suppressed", false, "Include suppressed findings in output with suppression details (marked as [SUPP] in text format)")
	quiet := flag.Bool("quiet", false, "Suppress progress output (useful for scripts and CI/CD)")
	precommitMode := flag.Bool("pre-commit-mode", false, "Enable pre-commit optimizations (quiet mode, no colors, appropriate exit codes)")
	failOnIncomplete := flag.Bool("fail-on-incomplete", false, "Exit non-zero (3) if any file was not fully scanned — coverage cut short (timeout, cancellation, or budget), the file could not be opened at all, or a document yielded no extractable text. Default off: all three conditions only warn on stderr.")

	// Redaction flags
	enableRedaction := flag.Bool("enable-redaction", false, "Enable redaction of sensitive data found in documents")
	redactionOutputDir := flag.String("redaction-output-dir", "./redacted", "Directory where redacted files will be stored")
	redactionStrategy := flag.String("redaction-strategy", "format_preserving", "Default redaction strategy: simple, format_preserving, or synthetic")
	redactionAuditLog := flag.String("redaction-audit-log", "", "Path to save redaction audit log file (JSON format for compliance)")

	// Exclusion flag
	excludePatterns := flag.String("exclude", "", "Comma-separated list of patterns to exclude from scanning (e.g., '.git,*.log,temp/')")

	// Gitignore flag — opt-in. Off by default because .gitignore commonly hides
	// files with high secret-scanning value (.env, *.pem, credentials/).
	respectGitignore := flag.Bool("respect-gitignore", false, "Honor .gitignore files, .git/info/exclude, and global git excludes when scanning (opt-in; .git directory is always skipped when enabled)")

	// IP sub-type control flag
	disableIPTypes := flag.String("disable-ip-types", "", "Comma-separated list of IP sub-types to disable: copyright,patent,trademark,trade_secret,internal_url")
	validatorBudget := flag.String("validator-budget", "", "Per-validator time budget as NAME=DURATION pairs. DURATION takes any Go duration unit — ms, s, m, h (e.g. 'SSN=500ms,IP_ADDRESS=2m'). Use 'all=<dur>' for every validator; specific names override it. A validator exceeding its budget is stopped and the scan is marked incomplete. Default: no budget.")
	maxLiveBytes := flag.String("max-live-bytes", "", "Cap total extracted content held in memory across concurrently scanned files, e.g. '256MB' or '1GB' (units: B, KB, MB, GB; bare number = bytes). Bounds peak memory on constrained hosts (e.g. Lambda) so many large files cannot multiply memory. Default: no cap (bounded only by the 100MB per-file limit × worker count).")

	// Web server flags
	webMode := flag.Bool("web", false, "Start web server mode instead of CLI scanning")
	webPort := flag.String("port", "8080", "Port for web server (default: 8080)")
	webBind := flag.String("bind", "", "Network interface for the web server (default: 127.0.0.1; auto-detects 0.0.0.0 inside containers). Pass --bind 0.0.0.0 to expose on the LAN — note that the UI has no authentication.")

	// Stdin input. --file - is also accepted as a POSIX-style alias.
	// stdin content is treated as plain text; binary inputs should be written
	// to a file first.
	stdinMode := flag.Bool("stdin", false, "Read content to scan from standard input (treated as plain text)")
	stdinName := flag.String("stdin-name", "<stdin>", "Synthetic label used as the filename in findings when scanning stdin")

	// Output limit flag
	limitFlag := flag.Int("limit", 200, "Maximum number of findings to display (sorted by confidence, descending). Use --limit 0 to show all findings.")

	flag.Parse()

	// Parse --validator-budget once, up front, so a malformed spec fails fast with
	// a clear message before any scanning (and before the stdin/file split). A nil
	// map means no budgets (byte-identical default behavior).
	validatorBudgets, budgetErr := parseValidatorBudgets(*validatorBudget)
	if budgetErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", budgetErr)
		os.Exit(1)
	}

	// Parse --max-live-bytes up front too. 0 means no cap (byte-identical default).
	maxLiveBytesVal, mlbErr := parseByteSize(*maxLiveBytes)
	if mlbErr != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", mlbErr)
		os.Exit(1)
	}

	// Extract all flag values once for performance and consistency
	flags := extractAllFlags(flagPointers{
		// Boolean flags
		webMode:              webMode,
		quiet:                quiet,
		debug:                debug,
		noColor:              noColor,
		verbose:              verbose,
		recursive:            recursive,
		enablePreprocessors:  enablePreprocessors,
		preprocessOnly:       preprocessOnly,
		preprocessOnlyShort:  preprocessOnlyShort,
		precommitMode:        precommitMode,
		showMatch:            showMatch,
		showSuppressed:       showSuppressed,
		generateSuppressions: generateSuppressions,
		failOnIncomplete:     failOnIncomplete,
		enableRedaction:      enableRedaction,
		listProfiles:         listProfiles,
		respectGitignore:     respectGitignore,

		// String flags
		webPort:            webPort,
		webBind:            webBind,
		inputFile:          inputFile,
		configFile:         configFile,
		profileName:        profileName,
		outputFormat:       outputFormat,
		confidenceLevels:   confidenceLevels,
		checksToRun:        checksToRun,
		redactionOutputDir: redactionOutputDir,
		redactionStrategy:  redactionStrategy,
		redactionAuditLog:  redactionAuditLog,
		outputFile:         outputFile,
		suppressionFile:    suppressionFile,
		excludePatterns:    excludePatterns,
		disableIPTypes:     disableIPTypes,
	})

	// Handle web mode early - validate flags and start web server if requested
	if flags.webMode {
		if err := handleWebMode(flags.webPort, flags.webBind, flag.Args(), flags.inputFile, flags.configFile, flags.suppressionFile, flags.excludePatterns); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		// Web server will run indefinitely, so this should not be reached
		return
	}

	// Handle stdin mode early - bypasses file discovery entirely.
	// --stdin or --file - both trigger this path. Mutual-exclusion checks
	// live inside runStdinScan to keep main.go's flag parsing flat.
	// --help and --version always fall through to their dedicated handlers
	// below regardless of --stdin, so users can inspect the CLI surface
	// without piping anything.
	stdinFromFile := flags.inputFile == "-"
	if (*stdinMode || stdinFromFile) && !*showHelp && !*showVersion {
		exitCode := runStdinScan(stdinScanInputs{
			flags:            flags,
			positionalArgs:   flag.Args(),
			stdinName:        *stdinName,
			outputFile:       *outputFile,
			explain:          *explainFindings,
			validatorBudgets: validatorBudgets,
			limit:            *limitFlag,
		})
		os.Exit(exitCode)
	}

	// Auto-detect non-interactive environment
	isInteractive := isTerminal(os.Stderr)
	if !isInteractive || flags.quiet || os.Getenv("CI") != "" {
		setBoolFlag(noColor, true)
	}

	// Create debug observer early for configuration logging
	var mainDebugObs *observability.DebugObserver
	if flags.debug {
		mainDebugObs = observability.NewDebugObserver(os.Stderr)
		mainDebugObs.LogDetail("main", fmt.Sprintf("Command line arguments: %v", os.Args))
		if flags.inputFile != "" {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Parsed --file flag: %s", flags.inputFile))
		}
	}

	// Load configuration
	cfg := loadConfiguration(flags.configFile)

	// Initialize pre-commit detector early to check for automatic profile selection
	precommitDetector := precommit.NewPrecommitDetectorWithFlag(flags.precommitMode)
	var precommitConfig *precommit.PrecommitConfig

	// Apply pre-commit optimizations if detected or explicitly enabled
	if precommitDetector.IsPrecommitEnvironment() {
		precommitConfig = precommitDetector.GetOptimizedConfig()
	}

	// Determine profile name - use pre-commit profile automatically if in pre-commit environment and no explicit profile
	effectiveProfileName := flags.profileName
	if effectiveProfileName == "" && precommitDetector.IsPrecommitEnvironment() {
		suggestedProfile := precommitDetector.GetSuggestedProfile()
		if suggestedProfile != "" && cfg != nil && cfg.GetProfile(suggestedProfile) != nil {
			effectiveProfileName = suggestedProfile
		}
	}

	// Handle profile operations
	activeProfile := handleProfiles(cfg, flags.listProfiles, effectiveProfileName, flags.configFile, precommitConfig)

	// Resolve final configuration values using extracted flags
	finalConfig := resolveConfiguration(cfg, activeProfile, &configFlags{
		outputFormat:        flags.outputFormat,
		confidenceLevels:    flags.confidenceLevels,
		checksToRun:         flags.checksToRun,
		verbose:             flags.verbose,
		debug:               flags.debug,
		noColor:             flags.noColor,
		recursive:           flags.recursive,
		enablePreprocessors: flags.enablePreprocessors,
		preprocessOnly:      flags.preprocessOnly,
		precommitMode:       flags.precommitMode,
		// Redaction flags
		enableRedaction:      flags.enableRedaction,
		redactionOutputDir:   flags.redactionOutputDir,
		redactionStrategy:    flags.redactionStrategy,
		redactionAuditLog:    flags.redactionAuditLog,
		excludePatterns:      flags.excludePatterns,
		respectGitignore:     flags.respectGitignore,
		showMatch:            flags.showMatch,
		quiet:                flags.quiet,
		showSuppressed:       flags.showSuppressed,
		generateSuppressions: flags.generateSuppressions,
		failOnIncomplete:     flags.failOnIncomplete,
		suppressionFile:      flags.suppressionFile,
		disableIPTypes:       flags.disableIPTypes,
	})

	// Use the pre-commit detector initialized earlier (no need to reinitialize)
	// precommitConfig is already initialized above

	// Apply additional pre-commit optimizations to final config
	if precommitConfig != nil {

		// Override configuration with pre-commit optimizations
		if precommitConfig.QuietMode {
			setBoolFlag(quiet, true)
		}
		if precommitConfig.NoColor {
			finalConfig.noColor = true
		}
		if precommitConfig.Format != "" {
			finalConfig.format = precommitConfig.Format
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("precommit", "Pre-commit environment detected, applying optimizations")
			mainDebugObs.LogDetail("precommit", fmt.Sprintf("Quiet mode: %v, No color: %v, Format: %s",
				precommitConfig.QuietMode, precommitConfig.NoColor, precommitConfig.Format))
		}
	}

	// Check if FERRET_DEBUG environment variable is set
	if os.Getenv("FERRET_DEBUG") != "" {
		finalConfig.debug = true
	}

	// Set environment variable for validators to detect debug mode
	if finalConfig.debug {
		os.Setenv("FERRET_DEBUG", "1")
	}

	// Validate flag combinations
	if finalConfig.preprocessOnly {
		// Check for incompatible flags with preprocess-only mode
		if finalConfig.enableRedaction {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --enable-redaction\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode outputs text content and exits before redaction phase.\n")
			os.Exit(1)
		}

		// Check if output format flags are used (they don't make sense with preprocess-only)
		if flags.outputFile != "" {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --output\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode outputs directly to stdout.\n")
			os.Exit(1)
		}

		// Check if validation-specific flags are used
		if finalConfig.showMatch {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --show-match\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		if finalConfig.generateSuppressions {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --generate-suppressions\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation or generate findings.\n")
			os.Exit(1)
		}

		if flags.suppressionFile != "" {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --suppression-file\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		if finalConfig.showSuppressed {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --show-suppressed\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation.\n")
			os.Exit(1)
		}

		// --fail-on-incomplete gates on validator COVERAGE, which preprocess-only
		// never produces (it exits before validation). Only reject when the flag
		// was passed EXPLICITLY — a global config/profile default (fail_on_incomplete:
		// true) must not break every --preprocess-only run.
		if isFlagSet("fail-on-incomplete") {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --fail-on-incomplete\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not perform validation, so coverage is never incomplete.\n")
			os.Exit(1)
		}

		// --validator-budget and --max-live-bytes bound validator execution and
		// the concurrent-content memory envelope respectively; preprocess-only
		// exits before any validation or worker-pool fan-out, so both are no-ops
		// there. Reject them when passed EXPLICITLY (a config/profile default must
		// not break preprocess-only) so the behavior matches the documented
		// "not valid with --preprocess-only" contract instead of silently ignoring.
		if isFlagSet("validator-budget") {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --validator-budget\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not run validators, so per-validator budgets do not apply.\n")
			os.Exit(1)
		}

		if isFlagSet("max-live-bytes") {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only cannot be used with --max-live-bytes\n")
			fmt.Fprintf(os.Stderr, "Preprocess-only mode does not fan out across the worker pool, so the live-bytes cap does not apply.\n")
			os.Exit(1)
		}

		// Warn about format flags that will be ignored
		if finalConfig.format != "text" && isFlagSet("format") {
			fmt.Fprintf(os.Stderr, "Warning: --format flag is ignored in preprocess-only mode\n")
		}

		if finalConfig.confidenceLevels != "all" && isFlagSet("confidence") {
			fmt.Fprintf(os.Stderr, "Warning: --confidence flag is ignored in preprocess-only mode\n")
		}

		if finalConfig.checksToRun != "all" && isFlagSet("checks") {
			fmt.Fprintf(os.Stderr, "Warning: --checks flag is ignored in preprocess-only mode\n")
		}

		// Check if preprocessors are disabled
		if !finalConfig.enablePreprocessors {
			fmt.Fprintf(os.Stderr, "Error: --preprocess-only requires preprocessors to be enabled\n")
			fmt.Fprintf(os.Stderr, "Remove --enable-preprocessors=false or use --enable-preprocessors=true\n")
			os.Exit(1)
		}
	}

	// Context analyzer is now integrated into the enhanced validator pipeline

	// Context-aware dual-path validation, optimized for CLI.

	// Parse which checks should be run based on --checks parameter
	enabledChecks := parseChecksToRun(finalConfig.checksToRun)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("config", fmt.Sprintf("Enabled checks: %v", enabledChecks))
	}

	// Build the filtered validator set via the shared factory
	// Inject --disable-ip-types CLI flag into config so Configure() picks it up
	if finalConfig.disableIPTypes != "" {
		if cfg == nil {
			cfg = &config.Config{}
		}
		if cfg.Validators == nil {
			cfg.Validators = make(map[string]map[string]interface{})
		}
		if cfg.Validators["intellectual_property"] == nil {
			cfg.Validators["intellectual_property"] = make(map[string]interface{})
		}
		// Parse comma-separated types into a []any for YAML-compatible config
		var types []any
		for _, t := range strings.Split(finalConfig.disableIPTypes, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				types = append(types, trimmed)
			}
		}
		cfg.Validators["intellectual_property"]["disabled_types"] = types

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("config", fmt.Sprintf("CLI --disable-ip-types: %v", types))
		}
	}

	standardValidators := core.BuildValidatorSet(enabledChecks, cfg, activeProfile)

	// Set up dual path validation integration
	var dualPathObserver *observability.StandardObserver
	if mainDebugObs != nil {
		dualPathObserver = mainDebugObs.StandardObserver
		dualPathObserver.DebugObserver = mainDebugObs
	} else {
		dualPathObserver = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
	}

	detectorFacade := validators.NewDetector(dualPathObserver)
	err := detectorFacade.SetupValidators(standardValidators)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to setup dual path validation: %v\n", err)
	} else if mainDebugObs != nil {
		mainDebugObs.LogDetail("enhanced", "Set up dual path validation system")
	}

	// Keep reference to standard validators for backward compatibility (e.g. help system)
	allValidators := standardValidators

	// The detection facade is the single validator handed to the runner; it
	// fans out to the document/metadata bridges internally.
	validatorsList := []detector.Validator{detectorFacade}

	// Handle version command
	if *showVersion {
		fmt.Println(version.Info())
		return
	}

	// Handle help commands
	if *showHelp {
		helpSystem := help.NewSystem(finalConfig.noColor)

		// Register ALL validators as help providers (not just filtered ones)
		for _, validator := range allValidators {
			if provider, ok := validator.(help.Provider); ok {
				helpSystem.RegisterProvider(provider)
			}
		}

		// Process help command
		args := flag.Args()
		if len(args) == 0 {
			// Show general help
			helpSystem.ShowGeneralHelp()
			return
		} else if len(args) == 1 {
			if strings.ToLower(args[0]) == "checks" {
				// Show list of all checks
				helpSystem.ShowChecksHelp()
				return
			}
			// Show help for specific check
			if helpSystem.ShowCheckHelp(args[0]) {
				return
			}
			os.Exit(1)
		} else {
			fmt.Println("Error: Too many arguments for help command")
			fmt.Println("Use 'ferret-scan --help', 'ferret-scan --help checks', or 'ferret-scan --help <check>'")
			os.Exit(1)
		}
	}

	// Handle file arguments (files/directories)
	var inputPaths []string
	if *inputFile != "" {
		inputPaths = append(inputPaths, *inputFile)
	}

	// Add any additional arguments as file paths (for shell-expanded globs)
	// Only do this if help is not being requested
	args := flag.Args()
	if len(args) > 0 && !*showHelp {
		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Found %d additional arguments: %v", len(args), args))
		}
		inputPaths = append(inputPaths, args...)
	}

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("Total input paths to process: %d", len(inputPaths)))
		for i, path := range inputPaths {
			mainDebugObs.LogDetail("main", fmt.Sprintf("  %d: %s", i+1, path))
		}
	}

	if len(inputPaths) == 0 {
		printPrecommitError(precommitConfig,
			"Input file or directory is required",
			"Specify a file or directory path to scan")
		os.Exit(1)
	}

	// Get list of files to process (supports glob patterns like *.pdf)
	var allFilesToProcess []string
	var totalSkipped int

	// discoveryUnexamined holds coverage losses found while DISCOVERING files, as
	// distinct from the ones found while scanning them. Both must reach the same report:
	// a file the walk refused is exactly as unscanned as one the parser choked on, and
	// before #326 the discovery-time ones reached no counter at all.
	var discoveryUnexamined []SkippedFile

	for i, inputPath := range inputPaths {
		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("Processing input path %d: %s", i+1, inputPath))
		}
		// Validate and sanitize the input path
		cleanPath := filepath.Clean(inputPath)
		abs, err := filepath.Abs(cleanPath)
		if err != nil {
			fmt.Printf("Error: Invalid input path: %s\n", inputPath)
			continue
		}
		// Check for path traversal attempts - handle as skipped instead of error
		if strings.Contains(inputPath, "..") || strings.Contains(cleanPath, "..") {
			totalSkipped++
			// Don't show warning for path traversal attempts - they're security-related
			continue
		}
		cleanPath = abs

		// Build a gitignore matcher rooted at this input path, if enabled.
		// Matcher is per-input-path so each scan target picks up its own
		// .gitignore hierarchy.
		var ignoreMatcher *gitignore.Matcher
		if finalConfig.respectGitignore {
			m, err := gitignore.New(cleanPath, gitignore.WithGlobalExcludes())
			if err == nil {
				ignoreMatcher = m
			} else if mainDebugObs != nil {
				mainDebugObs.LogDetail("main", fmt.Sprintf("  gitignore matcher init failed: %v", err))
			}
		}

		result, err := getFilesToProcess(cleanPath, finalConfig.recursive, finalConfig.excludePatterns, ignoreMatcher, finalConfig.enablePreprocessors)
		if err != nil {
			// stderr, not stdout: this is on the scan path, and a caller redirecting
			// stdout to a machine artifact (--format json > report.json) would
			// otherwise get a diagnostic spliced into the middle of the document,
			// leaving an unparseable file at exit 0. Same defect class as the
			// media-error write already moved off stdout.
			fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", inputPath, err)
			continue
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", fmt.Sprintf("  Found %d files from this path", len(result.FilesToProcess)))
		}

		allFilesToProcess = append(allFilesToProcess, result.FilesToProcess...)

		// Handle skipped files
		for _, skipped := range result.SkippedFiles {
			totalSkipped++
			if !skipped.Silent {
				fmt.Fprintf(os.Stderr, "Warning: Skipping %s: %s\n", skipped.Path, skipped.Reason)
			}
		}

		// Entries the scanner could not examine. Carried to the not-examined report
		// rather than printed here: a per-file stderr line at discovery time is the
		// pattern that produced unreadable console output, and the report already
		// groups by cause, caps its output, and feeds --fail-on-incomplete.
		discoveryUnexamined = append(discoveryUnexamined, result.UnexaminedFiles...)
	}

	filesToProcess := allFilesToProcess

	if len(filesToProcess) == 0 {
		if finalConfig.preprocessOnly {
			if totalSkipped > 0 {
				printPrecommitError(precommitConfig,
					fmt.Sprintf("No files to preprocess - all %d files were skipped", totalSkipped),
					"Check file types, permissions, or size limits")
			} else {
				printPrecommitError(precommitConfig,
					"No files found to preprocess",
					"Verify path exists and contains supported file types")
			}
			os.Exit(2) // Use exit code 2 for no files to process as per design
		} else {
			// Disclose discovery-time coverage losses BEFORE exiting.
			//
			// This path used to print "No files to process" and exit 0 unconditionally,
			// which is the exact artifact this report exists to prevent. A single
			// oversize processable file is refused at discovery, so filesToProcess is
			// empty and every disclosure downstream — collectUnscanned, the stats
			// denominator, the NOT FULLY EXAMINED block, and both
			// resolveIncompleteExitCode calls — was skipped. The run reported a clean,
			// complete result for a file it never opened, and --fail-on-incomplete
			// returned 0. It also printed strictly LESS than before this branch, because
			// discovery warnings were deferred to a report that never ran.
			//
			// Same shape for a directory or glob whose inputs are ALL refused.
			if len(discoveryUnexamined) > 0 {
				entries := make([]unscannedEntry, 0, len(discoveryUnexamined))
				for _, u := range discoveryUnexamined {
					entries = append(entries, unscannedEntry{Path: u.Path, Cause: u.Cause, Detail: u.Reason})
				}
				var report strings.Builder
				if writeUnscannedReport(&report, entries, len(entries), *failOnIncomplete, finalConfig.debug) {
					fmt.Fprint(os.Stderr, report.String())
				}
				fmt.Println("No files to process")
				// Honour the flag: these files were expected to produce results and did
				// not, which is precisely what code 3 means.
				os.Exit(resolveIncompleteExitCode(0, finalConfig.failOnIncomplete, len(entries)))
			}
			fmt.Println("No files to process")
			os.Exit(0)
		}
	}

	// Initialize suppression manager. The path comes from resolveConfiguration so
	// that suppressions.file in the config file is honored, not just the flag.
	suppressionManager := suppressions.NewSuppressionManager(finalConfig.suppressionFile)
	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Suppression manager initialized")
	}

	// Parse confidence levels
	confidenceFilter := parseConfidenceLevels(finalConfig.confidenceLevels)

	// Initialize file router with observability
	fileRouter := router.NewFileRouter(finalConfig.debug)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Registering default preprocessors...")
	}
	router.RegisterDefaultPreprocessors(fileRouter)

	// Router configuration: pass the redaction setting to preprocessors.
	routerConfig := router.CreateRouterConfig(finalConfig.enableRedaction)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Initializing preprocessors...")
	}
	fileRouter.InitializePreprocessors(routerConfig)

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("File router initialized with %d preprocessors", fileRouter.GetPreprocessorCount()))
	}

	// Connect FileRouter to the detection facade for metadata capability detection
	detectorFacade.SetFileRouter(fileRouter)
	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", "Connected FileRouter to detection facade for metadata filtering")
	}

	// Initialize redaction manager if redaction is enabled
	var redactionManager *redactors.RedactionManager
	if finalConfig.enableRedaction {
		var redactionObserver *observability.StandardObserver
		if finalConfig.debug {
			debugObs := observability.NewDebugObserver(os.Stderr)
			redactionObserver = debugObs.StandardObserver
			redactionObserver.DebugObserver = debugObs
		} else {
			redactionObserver = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
		}

		// Build the redaction manager with all default redactors via the shared
		// core factory (single source of truth, also used by core.RedactFile).
		strategy := redactors.ParseRedactionStrategy(finalConfig.redactionStrategy)
		var mgrErr error
		redactionManager, _, mgrErr = core.NewDefaultRedactionManager(
			finalConfig.redactionOutputDir, strategy, redactionObserver)
		if mgrErr != nil {
			fmt.Fprintf(os.Stderr, "Error creating redaction manager: %v\n", mgrErr)
			os.Exit(1)
		}

		if mainDebugObs != nil {
			mainDebugObs.LogDetail("main", "Redaction manager initialized with default redactors")
		}
	}

	// Set up observability for all components
	for _, validator := range allValidators {
		if observableValidator, ok := validator.(interface {
			SetObserver(observer observability.Observer)
		}); ok {
			var observer *observability.StandardObserver
			if finalConfig.debug {
				debugObs := observability.NewDebugObserver(os.Stderr)
				observer = debugObs.StandardObserver
				// Store the debug observer in the standard observer for access
				observer.DebugObserver = debugObs
			} else {
				observer = observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr)
			}
			observableValidator.SetObserver(observer)
		}
	}

	if mainDebugObs != nil {
		mainDebugObs.LogDetail("main", fmt.Sprintf("File router initialized with %d preprocessors", fileRouter.GetPreprocessorCount()))
	}

	if mainDebugObs != nil {
		finishConfigStep := mainDebugObs.StartStep("main", "configuration_summary", "")
		mainDebugObs.LogDetail("config", fmt.Sprintf("Preprocessors enabled: %v", finalConfig.enablePreprocessors))
		if cfg != nil {
			mainDebugObs.LogDetail("config", fmt.Sprintf("Text extraction enabled: %v", cfg.Preprocessors.TextExtraction.Enabled))
		} else {
			mainDebugObs.LogDetail("config", "Text extraction enabled: true (default)")
		}
		mainDebugObs.LogDetail("config", fmt.Sprintf("Validators to run: %v", finalConfig.checksToRun))
		mainDebugObs.LogDetail("config", fmt.Sprintf("Recursive scan: %v", finalConfig.recursive))
		mainDebugObs.LogDetail("config", fmt.Sprintf("Confidence levels: %v", finalConfig.confidenceLevels))
		mainDebugObs.LogMetric("config", "files_to_process", len(filesToProcess))
		finishConfigStep(true, "Configuration validated")
	}

	// Get the appropriate formatter with error handling
	formatter, exists := formatters.Get(finalConfig.format)
	if !exists {
		availableFormats := formatters.List()
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Unsupported output format '%s'", finalConfig.format),
			fmt.Sprintf("Use one of: %s", strings.Join(availableFormats, ", ")))
		os.Exit(1)
	}

	// Create formatter options
	formatterOptions := formatters.FormatterOptions{
		ConfidenceLevel: confidenceFilter,
		Verbose:         finalConfig.verbose,
		NoColor:         finalConfig.noColor,
		ShowMatch:       finalConfig.showMatch,
		PrecommitMode:   precommitConfig != nil && precommitConfig.QuietMode,
		Limit:           *limitFlag,
	}

	// Process all files using parallel processing
	var allMatches []detector.Match
	processedFiles := 0
	skippedFiles := 0
	// incompleteFiles captures files whose validator coverage was cut short (a
	// per-file/per-validator timeout, cancellation, or match budget — v2 Phase 4).
	// Populated from ProcessingStats.IncompleteFiles below and surfaced as a
	// stderr warning so a partially-scanned run is never silently reported clean.
	var incompleteFiles []parallel.FileDiagnostic
	// unredactedFiles captures files that HAVE findings but for which no redacted
	// copy could be written (no registered redactor for the extension, or a write
	// failure). Only ever non-empty with --enable-redaction. Surfaced as its own
	// stderr warning: the findings are still reported, but the sensitive values
	// remain in cleartext at the original path with no shareable artifact.
	var unredactedFiles []parallel.FileDiagnostic
	// emptyExtractionFiles captures files whose extraction succeeded but produced
	// no document text, for a file type that carries some. Surfaced as its own
	// stderr warning and counted as a coverage gap: nothing was extracted, so no
	// validator saw anything, so the file reported clean.
	var emptyExtractionFiles []parallel.FileDiagnostic
	// failedProcessingFiles captures files whose processing errored, so they were
	// never scanned at all. Without this they were counted as neither processed
	// nor skipped and vanished from the run entirely. Named distinctly from the
	// local failedFiles int below, which means "processed but produced no
	// findings" — a different and far less serious thing.
	var failedProcessingFiles []parallel.FileDiagnostic

	// Report config keys the schema does not recognize. Gated only on pre-commit
	// mode, NOT on quiet/non-interactive — the same rule as the
	// incomplete-coverage warning below, and for the same reason: CI is exactly
	// where a config that silently fails to apply is most dangerous, and CI is
	// never interactive. --quiet documents suppressing *progress* output, which
	// this is not. It writes to stderr, so scripts parsing results on stdout are
	// unaffected, and it never changes the exit code.
	if precommitConfig == nil {
		warnUnknownConfigKeys(os.Stderr, cfg)
		reportConfigProvenance(os.Stderr, cfg, flags.configFile)
	}

	// Suppress progress messages in pre-commit mode or quiet mode
	if !shouldSuppressProgressOutput(finalConfig, precommitConfig, isInteractive) {
		fmt.Fprintf(os.Stderr, "Starting scan of %d files...\n", len(filesToProcess))

		// Show filtering info if files were filtered out
		if totalSkipped > 0 {
			fmt.Fprintf(os.Stderr, "Filtered out %d unsupported files\n", totalSkipped)
		}
	}

	// Progress bar function with ETA
	progressStart := time.Now()
	updateProgress := func(current, total, skipped int, currentFile string) {
		if shouldSuppressProgressOutput(finalConfig, precommitConfig, isInteractive) {
			return // Don't show progress bar in debug mode, quiet mode, pre-commit mode, or non-interactive environments
		}
		percent := float64(current) / float64(total) * 100
		barWidth := 40
		filledWidth := int(float64(barWidth) * float64(current) / float64(total))
		bar := strings.Repeat("█", filledWidth) + strings.Repeat("░", barWidth-filledWidth)

		// Calculate ETA
		var etaStr string
		if current > 0 {
			elapsed := time.Since(progressStart)
			avgTime := elapsed / time.Duration(current)
			remaining := time.Duration(total-current) * avgTime
			etaStr = fmt.Sprintf(" ETA: %s", remaining.Round(time.Second))
		}

		// Prepare filename display
		filenameDisplay := ""
		if currentFile != "" && current < total {
			// Extract just the filename from the full path
			filename := filepath.Base(currentFile)
			if len(filename) > 30 {
				filename = "..." + filename[len(filename)-27:]
			}
			filenameDisplay = fmt.Sprintf(" | %s", filename)
		}

		// Display progress bar with filename and clear to end of line
		fmt.Fprintf(os.Stderr, "\r[%s] %d/%d files (%.1f%%) - %d skipped%s%s\033[K",
			bar, current, total, percent, skipped, etaStr, filenameDisplay)

		if current == total {
			fmt.Fprintf(os.Stderr, "\n")
		}
	}

	// Use parallel processing for all files (single or multiple)
	parallelProcessor := parallel.NewParallelProcessor(observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr))

	// Filter supported files.
	//
	// Unreadable files are counted separately from unsupported ones. Collapsing the
	// two made a permission-denied .txt report as "1 files skipped (1 unsupported
	// types)" — a supported extension described as an unrecognized format — and gave
	// the user no reason to look again at a file that was never scanned.
	var supportedFiles []string
	var unreadableFiles []string
	unreadableCount := 0

	// scanMalfunction records that the SCANNER failed, not that an input was bad.
	// Exit code 2 means "the tool did not work"; a file it could not read is a
	// coverage gap (code 3), which is the distinction the old failedFiles counter
	// blurred.
	scanMalfunction := false
	for _, filePath := range filesToProcess {
		canProcess, reason := fileRouter.CanProcessFile(filePath, finalConfig.enablePreprocessors)
		if canProcess {
			supportedFiles = append(supportedFiles, filePath)
			continue
		}
		if strings.HasPrefix(reason, router.ReasonUnreadable) {
			unreadableFiles = append(unreadableFiles, fmt.Sprintf("%s: %s", filePath, reason))
			// Counted as unreadable AND as not-processed. The `continue` here used to
			// skip the increment below, so an unreadable file landed in NO counter at
			// all: two permission-denied files produced "0 skipped" in the summary
			// while the warning above said two files were never opened. Separating the
			// two categories was right; dropping the count was not.
			unreadableCount++
			continue
		}
		skippedFiles++
	}

	// Handle preprocess-only mode - exit early after preprocessing
	if finalConfig.preprocessOnly {
		err := processPreprocessOnly(supportedFiles, fileRouter, finalConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error in preprocess-only mode: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Calculate progress based on supported files only
	totalFilesForProgress := len(supportedFiles)

	// Show additional filtering info if more files were filtered out
	if skippedFiles > 0 && !shouldSuppressProgressOutput(finalConfig, precommitConfig, isInteractive) {
		fmt.Fprintf(os.Stderr, "Filtered out %d unsupported file types\n", skippedFiles)
	}

	if len(supportedFiles) > 0 {
		// PHASE 1 IMPLEMENTATION: Context analysis is now integrated into the parallel processing pipeline
		// to avoid duplicate file processing and improve performance

		jobConfig := &parallel.JobConfig{
			Debug:              finalConfig.debug,
			EnableRedaction:    finalConfig.enableRedaction,
			RedactionStrategy:  finalConfig.redactionStrategy,
			RedactionOutputDir: finalConfig.redactionOutputDir,
			ValidatorBudgets:   validatorBudgets,
			MaxLiveBytes:       maxLiveBytesVal,
		}

		// Show initial progress
		if !finalConfig.debug {
			updateProgress(0, totalFilesForProgress, 0, "")
		}

		// Create progress callback that updates the progress bar
		var progressCallback func(completed, total int, currentFile string)
		if !shouldSuppressProgressOutput(finalConfig, precommitConfig, isInteractive) {
			progressCallback = func(completed, total int, currentFile string) {
				// Update progress based on completed supported files
				updateProgress(completed, totalFilesForProgress, 0, currentFile)
			}
		}

		parallelMatches, stats, err := parallelProcessor.ProcessFilesWithProgress(supportedFiles, validatorsList, fileRouter, jobConfig, redactionManager, progressCallback)
		if err == nil {

			allMatches = append(allMatches, parallelMatches...)
			processedFiles = stats.ProcessedFiles
			incompleteFiles = stats.IncompleteFiles
			unredactedFiles = stats.UnredactedFiles
			emptyExtractionFiles = stats.EmptyExtractionFiles
			failedProcessingFiles = stats.FailedFiles

			// Handle inline redaction results if redaction was enabled
			if finalConfig.enableRedaction && redactionManager != nil {
				// Note: Redaction results are now handled inline during parallel processing
				// The redaction index and results are managed by the redaction manager
				// during the job processing phase

				if mainDebugObs != nil {
					mainDebugObs.LogDetail("main", "Redaction completed inline during parallel processing")
				}

				// Export redaction audit log if specified
				if finalConfig.redactionAuditLog != "" {
					if err := redactionManager.ExportAuditLog(finalConfig.redactionAuditLog); err != nil {
						fmt.Fprintf(os.Stderr, "Warning: Failed to export redaction audit log: %v\n", err)
					} else if !finalConfig.quiet {
						fmt.Fprintf(os.Stderr, "Redaction audit log exported to: %s\n", finalConfig.redactionAuditLog)
					}
				}
			}

			// Final progress is already updated by the progress callback

			if finalConfig.debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Parallel processing: %d files, %d matches, %d workers, %dms\n",
					stats.ProcessedFiles, stats.TotalMatches, stats.WorkerCount, stats.TotalDuration.Milliseconds())
			}
		} else {
			// A genuine tool malfunction, as opposed to an input the tool could not
			// read. This is what exit code 2 is for, so record it rather than only
			// printing it.
			fmt.Fprintf(os.Stderr, "Parallel processing failed: %v\n", err)
			scanMalfunction = true
		}
	}

	elapsed := time.Since(progressStart)
	finalSkippedCount := totalSkipped + skippedFiles

	if !shouldSuppressProgressOutput(finalConfig, precommitConfig, isInteractive) {
		// Report only what this line uniquely owns: how many files were scanned, how
		// many were an unsupported type the user did not expect a result for, and how
		// long it took. Files that FAILED to parse are deliberately NOT mentioned here
		// as "had no results" — that phrasing conflated a clean scan (findings=0) with
		// a file that was never read, and the not-examined report below now owns that
		// category in full. Reporting it in both places produced two different numbers
		// for the same files (a 23-vs-24 split a reader had to reconcile).
		fmt.Fprintf(os.Stderr, "Scan complete: %d files scanned", processedFiles)
		if finalSkippedCount > 0 {
			fmt.Fprintf(os.Stderr, ", %d skipped (unsupported type)", finalSkippedCount)
		}
		// Trailing blank line so the progress block (spinner, bar, this line) is
		// visually separated from the findings table that follows it. Without it the
		// table header butts directly against the progress output and the two read as
		// one wall of text.
		fmt.Fprintf(os.Stderr, " in %s\n\n", elapsed.Round(time.Millisecond))
	}

	// Incomplete-coverage warning (v2 Phase 4): a file whose validator coverage
	// was cut short (per-file/per-validator timeout, cancellation, or match
	// budget) means findings may be MISSING — the run must not be reported as a
	// clean, complete scan. Suppressed only in pre-commit mode, which owns a
	// strict machine-readable output contract. Exit code is deliberately
	// unchanged (default still 0) — this is an advisory warning.
	// Collected once, so the summary count and the detail report can never disagree:
	// they are derived from the same slice rather than counted twice.
	// Discovery-time refusals get their OWN cause rather than being folded into the
	// unreadable channel. Filing "resolves outside the scanned directory" under "cannot
	// read" would assert a failure that never happened — the file is readable, the tool
	// declined — and the operator's remedy differs.
	// Each discovery refusal carries the cause its producer assigned, rather than all
	// of them being labelled the same. Discovery is the only place that knows why it
	// declined: a symlink out of the tree and a 105MB document are both unexamined,
	// but the operator's remedy differs and so does the wording.
	discoveryEntries := make([]unscannedEntry, 0, len(discoveryUnexamined))
	for _, u := range discoveryUnexamined {
		discoveryEntries = append(discoveryEntries, unscannedEntry{
			Path:   u.Path,
			Cause:  u.Cause,
			Detail: u.Reason,
		})
		// Counted as not-processed for the same reason an unreadable file is: it was
		// considered and produced nothing, so leaving it out of every counter is what
		// made the loss invisible.
		unreadableCount++
	}

	unscannedEntries := collectUnscanned(unreadableFiles, emptyExtractionFiles, failedProcessingFiles, incompleteFiles, discoveryEntries)

	if precommitConfig == nil {
		// The unredacted warning stays here; the not-examined report is emitted AFTER
		// the findings table (search writeUnscannedReport below), so it reads as a
		// caveat about the result rather than a banner before it.
		writeUnredactedFilesWarning(os.Stderr, unredactedFiles, len(supportedFiles))
	}

	// Advisory explanation pass (opt-in via --explain). Annotate the full
	// match set BEFORE the suppression split so the drafted per-finding
	// suppression reasons are available both to --generate-suppressions (which
	// operates on allMatches) and to the formatters (which receive the
	// unsuppressed subset). Annotate never mutates Confidence, so the
	// suppression hash — and thus every finding's suppression identity — is
	// unaffected. Fully offline.
	if *explainFindings {
		explain.Annotate(allMatches, explain.NewSignalSynthesizer())
	}

	// Apply suppressions
	var unsuppressedMatches []detector.Match
	var suppressedMatches []detector.SuppressedMatch
	suppressedCount := 0
	for _, match := range allMatches {
		if suppressed, rule := suppressionManager.IsSuppressed(match); suppressed {
			suppressedCount++
			if finalConfig.debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Suppressed finding: %s (Rule: %s, Reason: %s)\n",
					match.Type, rule.ID, rule.Reason)
			}
			// Collect suppressed findings if requested
			if finalConfig.showSuppressed {
				// Check if rule is expired
				expired := rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt)

				suppressedMatches = append(suppressedMatches, detector.SuppressedMatch{
					Match:        match,
					SuppressedBy: rule.ID,
					RuleReason:   rule.Reason,
					ExpiresAt:    rule.ExpiresAt,
					Expired:      expired,
				})
			}
		} else {
			unsuppressedMatches = append(unsuppressedMatches, match)
		}
	}

	if suppressedCount > 0 {
		if flags.noColor {
			if finalConfig.showSuppressed {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (shown below with [SUPP] label)\n", suppressedCount)
			} else {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (use --show-suppressed to see them)\n", suppressedCount)
			}
		} else {
			if finalConfig.showSuppressed {
				fmt.Fprintf(os.Stderr, "\033[33mSuppressed\033[0m \033[31m%d\033[0m \033[33mfindings\033[0m based on suppression rules (shown below with \033[37m[SUPP]\033[0m label)\n", suppressedCount)
			} else {
				fmt.Fprintf(os.Stderr, "\033[33mSuppressed\033[0m \033[31m%d\033[0m \033[33mfindings\033[0m based on suppression rules (use \033[36m--show-suppressed\033[0m to see them)\n", suppressedCount)
			}
		}
	}

	// Generate suppression rules if requested
	if finalConfig.generateSuppressions {
		if len(allMatches) > 0 {
			reason := "Auto-generated suppression rule (disabled by default)"
			err := suppressionManager.GenerateSuppressionRules(allMatches, reason, false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to generate suppression rules: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "Updated suppression rules: existing rules had last_seen_at updated, new rules added (disabled by default)\n")
				fmt.Fprintf(os.Stderr, "Edit the suppression file to enable specific rules by setting 'enabled: true'\n")
			}
		} else {
			fmt.Fprintf(os.Stderr, "No findings to generate suppression rules for\n")
		}
	}

	// Populate scan stats for summary rendering
	var highCount, mediumCount, lowCount int
	for _, m := range unsuppressedMatches {
		switch {
		case m.Confidence >= 90:
			highCount++
		case m.Confidence >= 60:
			mediumCount++
		default:
			lowCount++
		}
	}
	// scanned and NOT-examined must not overlap, or the two numbers do not add up to
	// the file count and a reader has to reconcile them.
	//
	// An empty-extraction file (opened fine, no readable text) is counted by the
	// worker pool as PROCESSED and also appears in unscannedEntries, because both
	// statements are true from their own vantage point. Printed side by side they
	// double-count it: measured on 2 files where one was a valid but empty .docx,
	// the summary read "2 scanned, 1 NOT examined" — 3 of 2. On a 301-file run that
	// surfaced as 278 + 24 = 302.
	//
	// The summary resolves it in favour of NOT-examined, because that is the number
	// an operator must act on: a file whose contents were never read is not covered,
	// whatever the worker pool managed to do with it.
	//
	// Only the EMPTY-EXTRACTION count is subtracted. processedFiles already excludes
	// unreadable and unparseable files — they never reach the worker pool's success
	// path — so subtracting the whole unscanned set double-corrects and reported
	// "0 scanned" on a directory whose two good CSVs both produced findings.
	// Clamped at zero so a future counter change cannot render a negative.
	// Subtract only the empty-extraction files that produced NOTHING at all.
	//
	// The plain subtraction was still wrong for one case: a body-empty .docx whose
	// METADATA carries PII is an empty-extraction file, but it was scanned and it
	// produced findings — measured, 4 of them. Subtracting it reported "0 scanned"
	// on a run that reported 4 findings from that very file, which is a contradiction
	// the reader cannot resolve.
	//
	// A file that yielded any finding was, by construction, examined through some
	// channel. Those stay counted as scanned; only the genuinely silent ones are
	// removed, which is what keeps scanned + not-examined from double-counting.
	filesWithFindings := make(map[string]bool, len(unsuppressedMatches))
	for _, m := range unsuppressedMatches {
		filesWithFindings[m.Filename] = true
	}
	silentEmpty := 0
	for _, fd := range emptyExtractionFiles {
		if !filesWithFindings[fd.FilePath] {
			silentEmpty++
		}
	}

	scannedFiles := processedFiles - silentEmpty
	if scannedFiles < 0 {
		scannedFiles = 0
	}

	// consideredFiles is every entry this run took responsibility for: the files it
	// queued to scan PLUS the ones discovery refused. The denominator has to include
	// both, or the report reads "2 of 1 file" — the refused entries appear in the
	// numerator while being absent from the total they are counted against.
	//
	// Derived once and used by the stats block AND the not-examined report below, for
	// the same reason the entries themselves are collected once: two independent counts
	// of the same thing eventually disagree.
	consideredFiles := len(filesToProcess) + len(discoveryUnexamined)

	formatterOptions.Stats = &formatters.ScanStats{
		TotalFiles:       consideredFiles,
		FilesProcessed:   scannedFiles,
		FilesSkipped:     finalSkippedCount,
		FilesNotExamined: len(unscannedEntries),
		TotalFindings:    len(unsuppressedMatches),
		High:             highCount,
		Medium:           mediumCount,
		Low:              lowCount,
		Suppressed:       suppressedCount,
		Duration:         elapsed.Seconds(),
	}

	// The same disclosure, in structured form, for formats that cannot carry prose.
	//
	// Set unconditionally beside Stats and from the SAME slice, so the count in
	// stats.files_not_examined and the per-file entries can never disagree. Deriving
	// them independently is how a report comes to say "2 not examined" and then list
	// three files.
	//
	// Note this is set BEFORE the text footer is built below: the machine formats
	// must disclose even when the text renderer declines to (it is skipped entirely
	// in pre-commit mode).
	formatterOptions.NotExamined = toFormatterNotExamined(unscannedEntries)

	// The JUnit formatter reads this to decide the VALENCE of the not-examined
	// entries (<skipped> vs <error>), so one flag governs both the XML verdict and
	// the exit code instead of the two disagreeing.
	formatterOptions.FailOnIncomplete = *failOnIncomplete

	// Render the not-examined detail into the summary block rather than printing it
	// separately. Text format only: structured formats carry the same facts as data,
	// and pre-commit owns a strict output contract. Building it here means the whole
	// footer lands on ONE stream, so a piped stdout is not left with a frame whose
	// closing rule went to the terminal.
	if precommitConfig == nil && len(unscannedEntries) > 0 {
		var report strings.Builder
		if writeUnscannedReport(&report, unscannedEntries, consideredFiles, *failOnIncomplete, finalConfig.debug) {
			if finalConfig.format == "text" {
				// Text renders it INSIDE the summary block, so the whole footer lands on
				// one stream and a piped report is not left with an unclosed frame.
				formatterOptions.NotExaminedFooter = report.String()
			} else {
				// Every other format gets it on stderr.
				//
				// Without this branch the report was text-only, and `--format json` on an
				// unreadable file emitted `[]` with ZERO bytes of stderr — a REGRESSION
				// against main, which warns (220 bytes). A JSON consumer could not tell
				// "nothing found" from "never looked", which is the exact failure this
				// change exists to fix, reintroduced for six of seven formats.
				//
				// Caught by TestUnscannedFilesAreNotReportedCleanByTheCLI when the two
				// branches were merged together: each was green alone.
				//
				// stderr, not stdout, so a redirected report stays a clean parseable
				// artifact. Machine formats will carry this as DATA in a follow-up; until
				// then stderr is the honest channel rather than silence.
				fmt.Fprint(os.Stderr, report.String())
			}
		}
	}

	// Pre-commit mode owns a deliberately terse output contract, but "terse" must not
	// mean silent about files that were never read.
	//
	// Measured before this: `PRE_COMMIT=1` on a directory whose only file was
	// chmod-000 produced ZERO bytes on stdout AND stderr with rc=0 — byte-identical
	// to a clean pass, on a file that may be full of PII. A developer's commit is let
	// through and nothing anywhere says why. That is the #193 shape: a hook decision
	// with no stated reason.
	//
	// One line, no frame, no per-file list: pre-commit output is read in a terminal
	// mid-commit, so it states the count and how to see the rest.
	if precommitConfig != nil && len(unscannedEntries) > 0 {
		noun := "files"
		if len(unscannedEntries) == 1 {
			noun = "file"
		}
		fmt.Fprintf(os.Stderr,
			"ferret-scan: %d %s NOT examined (contents unreadable) — findings may be missing. "+
				"Re-run without --pre-commit for detail.\n",
			len(unscannedEntries), noun)
	}

	// Enable streaming for text format writing to stdout (no output file).
	// The text formatter writes directly to os.Stdout, avoiding a multi-GB
	// string buffer for large result sets.
	if finalConfig.format == "text" && *outputFile == "" {
		formatterOptions.StreamWriter = os.Stdout
	}

	// Format and display results
	var result string
	if finalConfig.showSuppressed {
		result, err = formatter.Format(unsuppressedMatches, suppressedMatches, formatterOptions)
	} else {
		result, err = formatter.Format(unsuppressedMatches, nil, formatterOptions)
	}
	if err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error formatting results: %v", err),
			"Check output format and file permissions")
		os.Exit(1)
	}

	// Clear sensitive data from memory
	for i := range allMatches {
		allMatches[i].Clear()
	}
	allMatches = nil

	// Output results
	if *outputFile != "" {
		// Validate and sanitize output file path
		cleanOutputPath := filepath.Clean(*outputFile)
		abs, err := filepath.Abs(cleanOutputPath)
		if err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Invalid output file path: %s", *outputFile),
				"Check that the path is valid and accessible")
			os.Exit(1)
		}
		// Check for path traversal attempts
		if strings.Contains(*outputFile, "..") || strings.Contains(cleanOutputPath, "..") {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Path traversal not allowed in output path: %s", *outputFile),
				"Use absolute paths or paths without '..' components")
			os.Exit(1)
		}
		cleanOutputPath = abs
		// Ensure output directory exists with secure permissions (owner only)
		outputDir := filepath.Dir(cleanOutputPath)
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Error creating output directory: %v", err),
				"Check directory permissions and available disk space")
			os.Exit(1)
		}
		// Use more restrictive permissions (0600) for files that might contain sensitive data
		err = os.WriteFile(cleanOutputPath, []byte(result), 0600)
		if err != nil {
			printPrecommitError(precommitConfig,
				fmt.Sprintf("Error writing to output file: %v", err),
				"Check file permissions and available disk space")
			os.Exit(1)
		}
	} else if result != "" {
		// A streaming formatter signals "already written to StreamWriter" by
		// returning "", so an empty result means there is nothing left to print.
		// Keying on the result rather than on whether streaming was *requested*
		// matters because Format has several early returns that produce a string
		// and never touch StreamWriter: "No matches found.", "No matches found
		// at the specified confidence levels.", the suppressed-only report, and
		// pre-commit output. Suppressing those unconditionally meant a text scan
		// to stdout printed zero bytes — including a pre-commit run that found
		// blocking secrets and exited 1 with no explanation.
		fmt.Println(result)
	}

	if note := truncationNote(unsuppressedMatches, formatterOptions, *limitFlag, finalConfig.format); note != "" {
		fmt.Fprint(os.Stderr, note)
	}

	// Determine appropriate exit code based on findings and pre-commit configuration
	hasFindings := len(unsuppressedMatches) > 0

	// hasErrors is deliberately NOT the old `failedFiles > 0`.
	//
	// failedFiles was len(supportedFiles) - processedFiles, and an UNREADABLE file
	// never enters supportedFiles at all — so it was invisible here. Measured in
	// pre-commit mode: a corrupt .docx exited 2 while a chmod-000 .txt exited 0,
	// even though both mean exactly the same thing (the contents were never seen).
	// Nobody chose that split; it fell out of the counter, the same way the summary's
	// "0 skipped" did.
	//
	// hasErrors now means what exit code 2 is documented to mean — the tool itself
	// failed. An input it could not read is a coverage gap, handled by coverageGaps
	// and exit code 3 below, so the two categories no longer contend for one code.
	hasErrors := scanMalfunction

	// Determine the highest confidence level of findings
	highestConfidence := ""
	for _, match := range unsuppressedMatches {
		var currentLevel string
		if match.Confidence >= 90 {
			currentLevel = "high"
		} else if match.Confidence >= 60 {
			currentLevel = "medium"
		} else {
			currentLevel = "low"
		}

		// Update highest confidence level
		if currentLevel == "high" {
			highestConfidence = "high"
		} else if currentLevel == "medium" && highestConfidence != "high" {
			highestConfidence = "medium"
		} else if currentLevel == "low" && highestConfidence != "high" && highestConfidence != "medium" {
			highestConfidence = "low"
		}
	}

	// Use pre-commit exit code logic if in pre-commit mode. --fail-on-incomplete
	// (flag OR config/profile default) then escalates a clean result to the
	// incomplete-coverage code without downgrading a findings/error verdict.
	//
	// A file that could not be OPENED counts as incomplete coverage too, and is the
	// more severe case: a cut-short scan looked at part of the file, an unreadable
	// one was never looked at. Both mean findings may be missing, so both feed the
	// same opt-in escalation.
	//
	// A file that was opened and extracted to NOTHING is the third member of that
	// set and the hardest to notice without help: unlike the other two it produces
	// no error anywhere, just an empty document body and a clean report.
	coverageGaps := len(unscannedEntries)
	if precommitConfig != nil {
		exitCode := precommit.GetExitCode(hasFindings, hasErrors, highestConfidence, precommitConfig)
		os.Exit(resolveIncompleteExitCode(exitCode, finalConfig.failOnIncomplete, coverageGaps))
	}

	// Default behavior: exit 0 (findings are reported in output, not via exit code)
	// unless --fail-on-incomplete escalates a cut-short scan to code 3. Distinct
	// code lets CI tell "incomplete coverage" apart from clean (0), error (1), and
	// no-files (2). Settable via --fail-on-incomplete or config fail_on_incomplete.
	os.Exit(resolveIncompleteExitCode(0, finalConfig.failOnIncomplete, coverageGaps))
}

// parseConfidenceLevels delegates to core.ParseConfidenceLevels to avoid code duplication between CLI and web modes.
// Converts a comma-separated string of confidence levels (e.g., "high,medium" or "all")
// into a map of confidence level thresholds for filtering scan results.
func parseConfidenceLevels(levels string) map[string]bool {
	return core.ParseConfidenceLevels(levels)
}

// ProcessingResult holds the result of file processing discovery
type ProcessingResult struct {
	FilesToProcess []string
	SkippedFiles   []SkippedFile

	// UnexaminedFiles are entries the scanner encountered and could NOT examine, as
	// opposed to SkippedFiles which the user asked to leave out (--exclude, .gitignore)
	// or which are an unsupported type nobody expected a result for.
	//
	// The distinction is the one ScanStats already draws: a skipped file is expected to
	// produce nothing, an unexamined one was expected to produce something and did not.
	// These flow into files_not_examined, the NOT FULLY EXAMINED block, and
	// --fail-on-incomplete, so a coverage loss found at DISCOVERY time is disclosed the
	// same way one found during scanning is. Before this, discovery-time losses reached
	// no counter at all. See #326.
	UnexaminedFiles []SkippedFile
}

// SkippedFile represents a file that was skipped during processing
type SkippedFile struct {
	Path   string
	Reason string
	Silent bool // true = don't show to user, false = show as warning

	// Cause classifies an entry carried in ProcessingResult.UnexaminedFiles, so the
	// report can say WHY discovery declined. It is unused for SkippedFiles, which are
	// by definition entries nobody expected a result from.
	//
	// Every UnexaminedFiles producer must set it. The zero value is causeUnreadable,
	// which would claim the file could not be opened — a failure that did not happen
	// for anything discovery declines on purpose.
	Cause unscannedCause
}

// isExcluded checks if a file path matches any of the exclusion patterns
func isExcluded(filePath string, excludePatterns []string) bool {
	if len(excludePatterns) == 0 {
		return false
	}

	// Clean the file path for consistent matching
	cleanPath := filepath.Clean(filePath)
	fileName := filepath.Base(cleanPath)

	for _, pattern := range excludePatterns {
		// Try matching against the full path
		if matched, _ := filepath.Match(pattern, cleanPath); matched {
			return true
		}

		// Try matching against just the filename
		if matched, _ := filepath.Match(pattern, fileName); matched {
			return true
		}

		// Try matching against directory names in the path
		if strings.Contains(cleanPath, pattern) {
			return true
		}

		// Handle patterns that end with / as directory exclusions
		if strings.HasSuffix(pattern, "/") {
			dirPattern := strings.TrimSuffix(pattern, "/")
			pathParts := strings.Split(cleanPath, string(filepath.Separator))
			for _, part := range pathParts {
				if matched, _ := filepath.Match(dirPattern, part); matched {
					return true
				}
			}
		}
	}

	return false
}

// getFilesToProcess returns a list of files to process based on the input path
// Supports glob patterns like *.pdf, files, and directories
// enablePreprocessors is needed to answer whether a size-refused file's TYPE was one
// the tool could have processed: without preprocessors a .docx is not processable, so
// refusing it for size loses nothing the run was going to find anyway.
func getFilesToProcess(inputPath string, recursive bool, excludePatterns []string, ignoreMatcher *gitignore.Matcher, enablePreprocessors bool) (*ProcessingResult, error) {
	result := &ProcessingResult{
		FilesToProcess:  []string{},
		SkippedFiles:    []SkippedFile{},
		UnexaminedFiles: []SkippedFile{},
	}
	// Validate input path before any file operations
	if strings.Contains(inputPath, "..") {
		return nil, fmt.Errorf("path traversal not allowed: %s", inputPath)
	}

	// Check if input contains glob patterns (but first check if file exists as-is)
	if _, err := os.Stat(inputPath); err == nil {
		// File exists as-is, treat as literal filename even if it contains glob chars
		info, err := os.Stat(inputPath)
		if err != nil {
			return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
		}
		if info.Mode().IsRegular() {
			ext := strings.ToLower(filepath.Ext(inputPath))
			audioTypes := map[string]bool{
				".mp3": true, ".wav": true, ".m4a": true, ".flac": true,
			}

			var sizeLimit int64 = 100 * 1024 * 1024 // 100MB default
			if audioTypes[ext] {
				sizeLimit = 500 * 1024 * 1024 // 500MB for audio files
			}

			if info.Size() <= sizeLimit {
				// Check if file is excluded
				if isExcluded(inputPath, excludePatterns) {
					result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
						Path:   inputPath,
						Reason: "excluded by --exclude pattern",
						Silent: false,
					})
					return result, nil
				}
				if ignoreMatcher.Match(inputPath) {
					result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
						Path:   inputPath,
						Reason: "excluded by .gitignore",
						Silent: false,
					})
					return result, nil
				}
				result.FilesToProcess = append(result.FilesToProcess, inputPath)
				return result, nil
			}
			// A file refused for size. Whether that is a coverage LOSS depends on
			// whether the tool could have processed its type at all — see
			// router.CanProcessType. An unprocessable type is a genuine skip; a
			// processable one was expected to produce a result and did not.
			limitMB := sizeLimit / (1024 * 1024)
			reason := fmt.Sprintf("file too large (max size: %dMB)", limitMB)
			if router.CanProcessType(inputPath, enablePreprocessors) {
				result.UnexaminedFiles = append(result.UnexaminedFiles, SkippedFile{
					Path:   inputPath,
					Reason: reason,
					Cause:  causeTooLarge,
				})
				return result, nil
			}
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   inputPath,
				Reason: reason,
				Silent: true,
			})
			return result, nil
		}
	} else if strings.ContainsAny(inputPath, "*?") || (strings.Contains(inputPath, "[") && strings.Contains(inputPath, "]")) {
		// Expand home directory if present
		expandedPath := inputPath
		if strings.HasPrefix(inputPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err == nil {
				expandedPath = filepath.Join(homeDir, inputPath[2:])
			}
		}

		// Handle glob pattern
		matches, err := filepath.Glob(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern: %w", err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("no files match pattern: %s", inputPath)
		}

		// Filter out directories and check file sizes
		var filesToProcess []string
		for _, match := range matches {
			// Validate each match for path traversal
			cleanMatch := filepath.Clean(match)
			if strings.Contains(match, "..") || strings.Contains(cleanMatch, "..") {
				continue
			}
			// Additional validation before file access
			if strings.Contains(cleanMatch, "..") {
				continue
			}
			info, err := os.Stat(cleanMatch)
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() {
				// Check if file is excluded
				if isExcluded(cleanMatch, excludePatterns) {
					continue // Skip excluded files
				}
				if ignoreMatcher.Match(cleanMatch) {
					continue // Skip gitignored files
				}

				if info.Size() <= 100*1024*1024 {
					filesToProcess = append(filesToProcess, cleanMatch)
				} else if router.CanProcessType(cleanMatch, enablePreprocessors) {
					// A processable type refused for size is a coverage LOSS, so it has
					// to reach a counter. Previously this branch wrote a bare stderr
					// warning and recorded the file nowhere: absent from total_files,
					// from files_skipped and from files_not_examined, so the machine
					// artifact described a complete clean scan and --fail-on-incomplete
					// exited 0. The warning was the only trace, and it is exactly what
					// CI discards.
					result.UnexaminedFiles = append(result.UnexaminedFiles, SkippedFile{
						Path:   cleanMatch,
						Reason: "file too large (max size: 100MB)",
						Cause:  causeTooLarge,
					})
				} else {
					// Unprocessable at any size: a genuine skip, nobody expected a
					// finding. Recorded rather than dropped so it stays in the
					// denominator.
					result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
						Path:   cleanMatch,
						Reason: "file too large (max size: 100MB)",
						Silent: true,
					})
				}
			}
		}
		result.FilesToProcess = filesToProcess
		return result, nil
	}

	// Clean the path to resolve any ".." components
	cleanPath := filepath.Clean(inputPath)

	// Additional validation after cleaning
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("path traversal not allowed after cleaning: %s", inputPath)
	}

	// Check if the path exists
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("path does not exist or is not accessible: %w", err)
	}

	var filesToProcess []string
	var skippedFiles []string

	// If it's a regular file, just process it
	if fileInfo.Mode().IsRegular() {
		// A file refused for size — see the identical decision on the glob path above
		// and router.CanProcessType.
		if fileInfo.Size() > 100*1024*1024 { // 100MB limit
			const reason = "file too large (max size: 100MB)"
			if router.CanProcessType(inputPath, enablePreprocessors) {
				result.UnexaminedFiles = append(result.UnexaminedFiles, SkippedFile{
					Path:   inputPath,
					Reason: reason,
					Cause:  causeTooLarge,
				})
				return result, nil
			}
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   inputPath,
				Reason: reason,
				Silent: true,
			})
			return result, nil
		}
		// Check if file is excluded
		if isExcluded(cleanPath, excludePatterns) {
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   cleanPath,
				Reason: "excluded by --exclude pattern",
				Silent: false,
			})
			return result, nil
		}
		if ignoreMatcher.Match(cleanPath) {
			result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
				Path:   cleanPath,
				Reason: "excluded by .gitignore",
				Silent: false,
			})
			return result, nil
		}
		result.FilesToProcess = append(result.FilesToProcess, cleanPath)
		return result, nil
	}

	// If it's a directory, get all files
	if fileInfo.IsDir() {
		// symlinkCands holds links seen during the walk; they are resolved after it
		// finishes so the outcome cannot depend on directory iteration order.
		var symlinkCands []symlinkCandidate

		err := filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
			// Validate path for traversal attempts
			cleanWalkPath := filepath.Clean(path)
			if strings.Contains(path, "..") || strings.Contains(cleanWalkPath, "..") {
				return nil // Skip paths with traversal attempts
			}

			// Handle errors accessing a path
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Skipping %s: %v\n", path, err)
				skippedFiles = append(skippedFiles, path)
				return nil // Continue walking despite the error
			}

			// Skip directories if not recursive
			if !recursive && info.IsDir() && path != cleanPath {
				return filepath.SkipDir
			}

			// Check if path is excluded (for both files and directories)
			if isExcluded(cleanWalkPath, excludePatterns) {
				if info.IsDir() {
					return filepath.SkipDir // Skip entire directory
				}
				return nil // Skip file
			}
			if ignoreMatcher.Match(cleanWalkPath) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// Only add regular files
			if info.Mode().IsRegular() {
				// Check file size
				if info.Size() <= 100*1024*1024 { // 100MB limit
					filesToProcess = append(filesToProcess, cleanWalkPath)
				} else if router.CanProcessType(cleanWalkPath, enablePreprocessors) {
					// Processable type refused for size: a coverage loss, so it must reach
					// files_not_examined and --fail-on-incomplete rather than only a
					// stderr line that CI discards. See the glob path above.
					result.UnexaminedFiles = append(result.UnexaminedFiles, SkippedFile{
						Path:   cleanWalkPath,
						Reason: "file too large (max size: 100MB)",
						Cause:  causeTooLarge,
					})
				} else {
					// Unprocessable at any size: a genuine skip.
					result.SkippedFiles = append(result.SkippedFiles, SkippedFile{
						Path:   cleanWalkPath,
						Reason: "file too large (max size: 100MB)",
						Silent: true,
					})
				}
				// Deliberately NOT added to the walk's local skippedFiles slice, which
				// feeds only "Skipped N files or directories due to errors". A size
				// refusal is not a walk error, and both branches above now record the
				// file in a real counter — so appending there both mislabelled it and
				// reported the same file twice, once as an error and once in the
				// NOT FULLY EXAMINED block.
			} else if info.Mode()&os.ModeSymlink != 0 {
				// A symlink. filepath.Walk hands us Lstat info, so a link is never
				// ModeRegular and used to fall past the branch above with NO else —
				// dropped from filesToProcess, from SkippedFiles, and from every
				// counter, with nothing printed. Measured: a symlink to a file holding
				// a card number was neither scanned nor disclosed, while the SAME link
				// named directly on the command line was scanned and the card found.
				// See #326 and cmd/symlink_walk.go for the policy.
				//
				// Collected rather than decided here: whether to follow depends on
				// whether the target is also reachable as a real file in this same
				// walk, which is not known until the walk ends.
				d, resolved, reason := classifySymlink(cleanWalkPath, cleanPath, 100*1024*1024)
				symlinkCands = append(symlinkCands, symlinkCandidate{
					linkPath: cleanWalkPath,
					resolved: resolved,
					reason:   reason,
					disp:     d,
				})
			}

			return nil
		})

		// Only return an error if we couldn't even start the walk
		if err != nil {
			return nil, fmt.Errorf("error accessing directory: %w", err)
		}

		// Resolve the symlinks now that every regular file is known, so a link whose
		// target is already queued under its real name is recognised as duplicate
		// content rather than scanned twice (which would manufacture the
		// identical-looking findings of #321).
		follow, disclose := resolveSymlinkCandidates(symlinkCands, filesToProcess)
		filesToProcess = append(filesToProcess, follow...)
		result.UnexaminedFiles = append(result.UnexaminedFiles, disclose...)

		// Print summary of skipped files
		if len(skippedFiles) > 0 {
			fmt.Fprintf(os.Stderr, "Skipped %d files or directories due to errors\n", len(skippedFiles))
		}

		result.FilesToProcess = filesToProcess
		return result, nil
	}

	return nil, fmt.Errorf("path is neither a regular file nor a directory")
}

// isFlagSet checks if a flag was explicitly set on the command line
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// normalizeChecksArg turns the raw --checks value into the canonical check names,
// or returns an error naming the first unrecognized one.
//
// This is the ONE place the flag's vocabulary is decided, because it previously had
// two and they disagreed. File mode validated and upper-cased here; stdin mode used
// cmd/stdin.go's parseChecksList, which did neither and handed the raw strings to
// core.ParseChecksToRun — whose loop silently drops any name it does not recognise.
// So the same flag, in the same binary, behaved differently by input source:
//
//	--checks ssn --file fx.txt   -> 1 finding   (upper-cased here)
//	--checks ssn --stdin         -> 0 findings, rc 0, nothing on stderr
//	--checks BOGUS --file fx.txt -> rc 1, "Unknown check type"
//	--checks BOGUS --stdin       -> 0 findings, rc 0, silent
//
// Silently running zero validators is the worst available outcome for a scanner: it
// reports clean. With --stdin --enable-redaction it also emitted the input back
// BYTE-IDENTICAL at rc 0, so the documented streaming-gateway pattern passed
// cleartext through while looking like it had redacted.
//
// Returning ([]string, error) rather than exiting keeps this usable from both call
// sites — the CLI boundary decides how to report, and neither path can quietly skip
// the check.
//
// A nil slice means "every check", which is what core.ParseChecksToRun treats an
// empty list as.
func normalizeChecksArg(checks string) ([]string, error) {
	// Available checks come from the single source of truth (core.CheckNames,
	// derived from validatorConstructors) so this list cannot drift from the
	// validators that actually exist.
	valid := make(map[string]bool, len(core.CheckNames()))
	for _, c := range core.CheckNames() {
		valid[c] = true
	}

	trimmed := strings.TrimSpace(checks)
	if trimmed == "" {
		return nil, nil
	}
	// The "all" sentinel, case-insensitively. core.ParseChecksToRun only honours a
	// lowercase, single-element "all", so "ALL" reached it as an unknown name and
	// selected NOTHING. Normalising here means the sentinel behaves the way every
	// other check name does.
	if strings.EqualFold(trimmed, "all") {
		return nil, nil
	}

	var out []string
	for _, check := range strings.Split(trimmed, ",") {
		checkStr := strings.ToUpper(strings.TrimSpace(check))
		if checkStr == "" {
			continue
		}
		// "all" mixed with other names is rejected rather than silently winning or
		// silently losing. core.ParseChecksToRun's sentinel requires a single-element
		// list, so "all,SSN" previously selected only SSN — a reasonable reader
		// expects the opposite, and guessing either way is worse than saying so.
		if checkStr == "ALL" {
			return nil, fmt.Errorf("'all' cannot be combined with other check names (got %q)", checks)
		}
		if !valid[checkStr] {
			return nil, fmt.Errorf("unknown check type '%s'\nAvailable checks: %s",
				checkStr, strings.Join(core.CheckNames(), ", "))
		}
		out = append(out, checkStr)
	}
	return out, nil
}

// parseChecksToRun converts a comma-separated string of check names
// into a map of enabled checks
func parseChecksToRun(checks string) map[string]bool {
	result := make(map[string]bool)
	for _, check := range core.CheckNames() {
		result[check] = false
	}

	selected, err := normalizeChecksArg(checks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	// nil means "every check".
	if selected == nil {
		for key := range result {
			result[key] = true
		}
		return result
	}
	for _, c := range selected {
		result[c] = true
	}
	return result
}

// handleWebMode validates web mode flags and starts the web server
func handleWebMode(port, bindFlag string, args []string, inputFile, configFile, suppressionFile string, excludePatterns []string) error {
	// Validate that no file arguments are provided with web mode
	if len(args) > 0 {
		return fmt.Errorf("--web flag cannot be used with file arguments\n"+
			"Web mode starts a server - use the web interface to upload files\n"+
			"Troubleshooting: Remove file arguments and access http://localhost:%s after startup", port)
	}

	// Validate that --file flag is not used with web mode
	if inputFile != "" {
		return fmt.Errorf("--web flag cannot be used with --file flag\n"+
			"Web mode starts a server - use the web interface to upload files\n"+
			"Troubleshooting: Remove --file flag and access http://localhost:%s after startup", port)
	}

	// Validate incompatible flags with web mode
	if err := validateWebModeFlags(); err != nil {
		return err
	}

	// Validate and find available port
	finalPort, err := findAvailablePort(port)
	if err != nil {
		return fmt.Errorf("port validation failed: %w\n"+
			"Troubleshooting: Try a different port with --port <number> or ensure no other services are using ports 8080-8089", err)
	}

	// Resolve bind address now (after port resolution) so the startup banner
	// reflects what we actually used. The web package owns the resolution
	// rules so the policy stays in one place.
	bindAddr, _ := web.ResolveBindAddress(bindFlag)

	// Start web server
	return startWebServer(finalPort, bindAddr, configFile, suppressionFile, excludePatterns)
}

// validateWebModeFlags validates that incompatible flags are not used with --web
func validateWebModeFlags() error {
	var incompatibleFlags []string
	var troubleshooting []string

	// Check for output-related flags
	if isFlagSet("output") {
		incompatibleFlags = append(incompatibleFlags, "--output")
		troubleshooting = append(troubleshooting, "Web mode provides its own output interface")
	}

	if isFlagSet("format") {
		incompatibleFlags = append(incompatibleFlags, "--format")
		troubleshooting = append(troubleshooting, "Web mode handles output formatting automatically")
	}

	// Check for CLI-specific display flags
	if isFlagSet("show-match") {
		incompatibleFlags = append(incompatibleFlags, "--show-match")
		troubleshooting = append(troubleshooting, "Web mode has its own match display controls")
	}

	if isFlagSet("no-color") {
		incompatibleFlags = append(incompatibleFlags, "--no-color")
		troubleshooting = append(troubleshooting, "Web mode uses its own color scheme")
	}

	if isFlagSet("quiet") {
		incompatibleFlags = append(incompatibleFlags, "--quiet")
		troubleshooting = append(troubleshooting, "Web mode provides its own progress indicators")
	}

	// Check for processing mode flags
	if isFlagSet("preprocess-only") || isFlagSet("p") {
		if isFlagSet("preprocess-only") {
			incompatibleFlags = append(incompatibleFlags, "--preprocess-only")
		}
		if isFlagSet("p") {
			incompatibleFlags = append(incompatibleFlags, "-p")
		}
		troubleshooting = append(troubleshooting, "Web mode does not support preprocess-only mode")
	}

	// Check for redaction flags
	if isFlagSet("enable-redaction") {
		incompatibleFlags = append(incompatibleFlags, "--enable-redaction")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-output-dir") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-output-dir")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-strategy") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-strategy")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	if isFlagSet("redaction-audit-log") {
		incompatibleFlags = append(incompatibleFlags, "--redaction-audit-log")
		troubleshooting = append(troubleshooting, "Web mode does not support redaction features")
	}

	// Check for CLI help/info flags
	if isFlagSet("help") {
		incompatibleFlags = append(incompatibleFlags, "--help")
		troubleshooting = append(troubleshooting, "Web mode has built-in help - access it through the web interface")
	}

	if isFlagSet("version") {
		incompatibleFlags = append(incompatibleFlags, "--version")
		troubleshooting = append(troubleshooting, "Web mode displays version info in the top-right corner")
	}

	if isFlagSet("list-profiles") {
		incompatibleFlags = append(incompatibleFlags, "--list-profiles")
		troubleshooting = append(troubleshooting, "Web mode does not currently support configuration profiles")
	}

	// --fail-on-incomplete controls the CLI process exit code; the web server is a
	// long-running process with no scan-level exit code to influence (it reports
	// incomplete coverage per-scan in the response instead).
	if isFlagSet("fail-on-incomplete") {
		incompatibleFlags = append(incompatibleFlags, "--fail-on-incomplete")
		troubleshooting = append(troubleshooting, "Web mode reports incomplete coverage per scan in its response, not via a process exit code")
	}

	// Check for CLI-specific suppression flags
	if isFlagSet("generate-suppressions") {
		incompatibleFlags = append(incompatibleFlags, "--generate-suppressions")
		troubleshooting = append(troubleshooting, "Web mode has its own suppression management interface")
	}

	if isFlagSet("show-suppressed") {
		incompatibleFlags = append(incompatibleFlags, "--show-suppressed")
		troubleshooting = append(troubleshooting, "Web mode has its own suppressed findings display")
	}

	if isFlagSet("validator-budget") {
		incompatibleFlags = append(incompatibleFlags, "--validator-budget")
		troubleshooting = append(troubleshooting, "Web mode does not apply per-validator CLI budgets; it runs with the default per-file timeout")
	}

	if isFlagSet("max-live-bytes") {
		incompatibleFlags = append(incompatibleFlags, "--max-live-bytes")
		troubleshooting = append(troubleshooting, "Web mode does not apply the CLI live-bytes memory cap")
	}

	// If any incompatible flags were found, return an error
	if len(incompatibleFlags) > 0 {
		errorMsg := fmt.Sprintf("--web flag cannot be used with the following flags: %s\n\n", strings.Join(incompatibleFlags, ", "))
		errorMsg += "Troubleshooting:\n"
		for i, tip := range troubleshooting {
			errorMsg += fmt.Sprintf("  %d. %s\n", i+1, tip)
		}
		errorMsg += "\nRemove the incompatible flags and try again."
		return fmt.Errorf("%s", errorMsg)
	}

	return nil
}

// findAvailablePort validates the requested port and finds an available port
func findAvailablePort(requestedPort string) (string, error) {
	// Validate port format and range
	port, err := validatePort(requestedPort)
	if err != nil {
		return "", err
	}

	// Check if requested port is available
	if isPortAvailable(port) {
		return port, nil
	}

	// If requested port is not available, try alternatives in range 8080-8089
	basePort := 8080
	for i := 0; i < 10; i++ {
		alternativePort := fmt.Sprintf("%d", basePort+i)
		if isPortAvailable(alternativePort) {
			fmt.Fprintf(os.Stderr, "Warning: Port %s is not available, using port %s instead\n", requestedPort, alternativePort)
			return alternativePort, nil
		}
	}

	return "", fmt.Errorf("no available ports found in range 8080-8089")
}

// validatePort validates that the port string is a valid port number
func validatePort(portStr string) (string, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port format '%s': must be a number", portStr)
	}

	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}

	if port < 1024 && os.Geteuid() != 0 {
		return "", fmt.Errorf("port %d requires root privileges (ports below 1024 are privileged)", port)
	}

	return portStr, nil
}

// printPrecommitError prints error messages optimized for pre-commit workflows
func printPrecommitError(precommitConfig *precommit.PrecommitConfig, errorMsg string, resolutionGuidance ...string) {
	if precommitConfig != nil && precommitConfig.QuietMode {
		// In pre-commit mode, provide concise, actionable error messages
		fmt.Fprintf(os.Stderr, "ferret-scan: %s\n", errorMsg)

		if len(resolutionGuidance) > 0 {
			fmt.Fprintf(os.Stderr, "Resolution: %s\n", resolutionGuidance[0])
		}

		// Add pre-commit specific guidance
		fmt.Fprintf(os.Stderr, "Pre-commit hook failed. Fix the issue above and retry your commit.\n")
	} else {
		// In normal mode, provide detailed error messages
		fmt.Fprintf(os.Stderr, "Error: %s\n", errorMsg)

		for _, guidance := range resolutionGuidance {
			fmt.Fprintf(os.Stderr, "%s\n", guidance)
		}
	}
}

// isPortAvailable checks if a port is available for binding
func isPortAvailable(port string) bool {
	address := fmt.Sprintf(":%s", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// startWebServer starts the web server on the specified port + bind address
// with timeout and resilience.
func startWebServer(port, bindAddr, configFile, suppressionFile string, excludePatterns []string) error {
	// Import web server package
	webServer := web.NewWebServerWithOptions(port, bindAddr, configFile, suppressionFile, excludePatterns)

	// Start the web server (this will block)
	return webServer.Start()
}

// isTerminal checks if the file descriptor is a terminal
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
