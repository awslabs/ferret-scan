// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"ferret-scan/internal/config"
	"ferret-scan/internal/core"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
	"ferret-scan/internal/precommit"
	"ferret-scan/internal/redactors"
	plaintextredactor "ferret-scan/internal/redactors/plaintext"
	"ferret-scan/internal/router"
	"ferret-scan/internal/suppressions"
)

// stdinScanInputs collects everything runStdinScan needs from main(). It
// avoids passing 10+ positional arguments and keeps the main() call site
// readable. main() guards entry on --help/--version so this struct does
// not carry those flags.
type stdinScanInputs struct {
	flags          extractedFlags
	positionalArgs []string
	stdinName      string
	outputFile     string
}

// runStdinScan is the entry point for stdin scanning. It mirrors the
// file-mode pipeline's user-visible behavior (suppressions, formatting,
// output, exit codes) but routes content through core.ScanContent instead
// of the path-driven file router.
//
// Returns the process exit code; main() calls os.Exit with the result.
func runStdinScan(in stdinScanInputs) int {
	// Validate incompatible flag combinations up-front so users get a clean
	// error before any stdin reading happens.
	if err := validateStdinFlags(in); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Refuse to block on a TTY — the user almost certainly forgot to pipe.
	if isTerminal(os.Stdin) {
		fmt.Fprintln(os.Stderr, "Error: --stdin requires content to be piped on standard input")
		fmt.Fprintln(os.Stderr, "  Example: echo 'data here' | ferret-scan --stdin")
		return 1
	}

	// Read stdin with a hard cap matching the file-mode size limit. We read
	// MaxFileSize+1 so we can distinguish "exactly at limit" from "over limit".
	limit := router.MaxFileSize
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		return 1
	}
	if int64(len(raw)) > limit {
		fmt.Fprintf(os.Stderr, "Error: stdin content exceeds %d-byte limit; write to a file and scan it instead\n", limit)
		return 1
	}

	// Strip a leading UTF-8 BOM (common when piping from Windows tools) so
	// line numbers and offsets line up with what the user expects.
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})

	// Reject content with embedded NUL bytes — same heuristic the file
	// router uses to classify binary content as unsupported.
	if bytes.IndexByte(raw, 0) >= 0 {
		fmt.Fprintln(os.Stderr, "Error: stdin appears to contain binary content (NUL byte detected); write to a file and scan it instead")
		return 1
	}

	// Coerce to valid UTF-8. Invalid sequences become the replacement rune,
	// matching what plaintext_preprocessor does for files.
	content := string(raw)
	if !utf8.ValidString(content) {
		content = strings.ToValidUTF8(content, "�")
	}

	// Resolve config and pre-commit settings the same way main() does.
	cfg := loadConfiguration(in.flags.configFile)
	precommitDetector := precommit.NewPrecommitDetectorWithFlag(in.flags.precommitMode)
	var precommitConfig *precommit.PrecommitConfig
	if precommitDetector.IsPrecommitEnvironment() {
		precommitConfig = precommitDetector.GetOptimizedConfig()
	}

	effectiveProfileName := in.flags.profileName
	if effectiveProfileName == "" && precommitDetector.IsPrecommitEnvironment() {
		suggestedProfile := precommitDetector.GetSuggestedProfile()
		if suggestedProfile != "" && cfg != nil && cfg.GetProfile(suggestedProfile) != nil {
			effectiveProfileName = suggestedProfile
		}
	}
	var activeProfile *config.Profile
	if effectiveProfileName != "" && cfg != nil {
		activeProfile = cfg.GetProfile(effectiveProfileName)
	}

	finalCfg := resolveConfiguration(cfg, activeProfile, &configFlags{
		outputFormat:         in.flags.outputFormat,
		confidenceLevels:     in.flags.confidenceLevels,
		checksToRun:          in.flags.checksToRun,
		verbose:              in.flags.verbose,
		debug:                in.flags.debug,
		noColor:              in.flags.noColor,
		recursive:            false,
		enablePreprocessors:  in.flags.enablePreprocessors,
		preprocessOnly:       in.flags.preprocessOnly,
		precommitMode:        in.flags.precommitMode,
		quiet:                in.flags.quiet,
		showMatch:            in.flags.showMatch,
		showSuppressed:       in.flags.showSuppressed,
		generateSuppressions: in.flags.generateSuppressions,
		enableRedaction:      in.flags.enableRedaction,
		redactionOutputDir:   "",
		redactionStrategy:    in.flags.redactionStrategy,
		redactionAuditLog:    "",
		respectGitignore:     false,
		excludePatterns:      nil,
		disableIPTypes:       in.flags.disableIPTypes,
	})

	// Apply pre-commit overrides for non-color/format defaults that the
	// main path would normally apply via precommitConfig.
	if precommitConfig != nil {
		if precommitConfig.NoColor {
			finalCfg.noColor = true
		}
		if precommitConfig.QuietMode {
			finalCfg.quiet = true
		}
		if !isFlagSet("format") {
			finalCfg.format = precommitConfig.Format
		}
	}

	// Preprocess-only mode for stdin: emit the buffered content with the
	// same header shape file-mode uses, so downstream tooling that parses
	// preprocess-only output gets a uniform layout.
	if finalCfg.preprocessOnly {
		return runStdinPreprocessOnly(in.stdinName, content)
	}

	// Suppression manager mirrors file mode.
	suppressionManager := suppressions.NewSuppressionManager(in.flags.suppressionFile)

	// Parse checks list into a []string for ScanContent.
	checks := parseChecksList(finalCfg.checksToRun)

	scanCfg := core.ContentScanConfig{
		VirtualPath:        in.stdinName,
		Checks:             checks,
		Debug:              finalCfg.debug,
		Verbose:            finalCfg.verbose,
		Config:             cfg,
		Profile:            activeProfile,
		SuppressionManager: nil, // applied below so we can run --generate-suppressions on raw matches
	}

	start := time.Now()
	result, err := core.ScanContent(content, scanCfg)
	if err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("stdin scan failed: %v", err),
			"Verify input encoding and configuration")
		return 1
	}
	elapsed := time.Since(start)

	allMatches := result.Matches // not yet suppressed since we passed nil manager

	// --generate-suppressions writes against raw matches before suppression.
	if finalCfg.generateSuppressions {
		if len(allMatches) > 0 {
			reason := "Auto-generated suppression rule (disabled by default)"
			if err := suppressionManager.GenerateSuppressionRules(allMatches, reason, false); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to generate suppression rules: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "Updated suppression rules: existing rules had last_seen_at updated, new rules added (disabled by default)")
				fmt.Fprintln(os.Stderr, "Edit the suppression file to enable specific rules by setting 'enabled: true'")
			}
		} else {
			fmt.Fprintln(os.Stderr, "No findings to generate suppression rules for")
		}
	}

	// Apply suppressions in the same shape as file mode.
	var unsuppressedMatches []detector.Match
	var suppressedMatches []detector.SuppressedMatch
	suppressedCount := 0
	for _, m := range allMatches {
		if isSup, rule := suppressionManager.IsSuppressed(m); isSup {
			suppressedCount++
			if finalCfg.showSuppressed {
				expired := rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt)
				suppressedMatches = append(suppressedMatches, detector.SuppressedMatch{
					Match:        m,
					SuppressedBy: rule.ID,
					RuleReason:   rule.Reason,
					ExpiresAt:    rule.ExpiresAt,
					Expired:      expired,
				})
			}
		} else {
			unsuppressedMatches = append(unsuppressedMatches, m)
		}
	}

	if !shouldSuppressStdinProse(finalCfg, precommitConfig, in.outputFile) {
		fmt.Fprintf(os.Stderr, "Scan complete: stdin scanned in %s\n", elapsed.Round(time.Millisecond))
		// Mirror file-mode's suppression notice so users see the same
		// signal regardless of input source.
		if suppressedCount > 0 {
			if finalCfg.showSuppressed {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (shown below with [SUPP] label)\n", suppressedCount)
			} else {
				fmt.Fprintf(os.Stderr, "Suppressed %d findings based on suppression rules (use --show-suppressed to see them)\n", suppressedCount)
			}
		}
	}

	// Redaction path: emit redacted content on stdout (or --output if set)
	// and findings on stderr (or alongside redacted content when --output
	// captures redacted bytes). This is the streaming/lambda use case —
	// the redacted string is the primary output, findings are diagnostic.
	//
	// --redaction-audit-log is intentionally not wired here: the audit log
	// manager requires an OutputStructureManager and on-disk indexing
	// infrastructure that doesn't fit the streaming model. Audit-log support
	// for stdin is tracked as a follow-up; users who need it can scan a file.
	if finalCfg.enableRedaction {
		if in.flags.redactionAuditLog != "" {
			fmt.Fprintln(os.Stderr, "Note: --redaction-audit-log is not supported with --stdin and will be ignored")
		}
		return runStdinRedaction(in, finalCfg, content, unsuppressedMatches, suppressedMatches, precommitConfig)
	}

	// Resolve formatter.
	formatter, exists := formatters.Get(finalCfg.format)
	if !exists {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Unsupported output format '%s'", finalCfg.format),
			fmt.Sprintf("Use one of: %s", strings.Join(formatters.List(), ", ")))
		return 1
	}

	formatterOptions := formatters.FormatterOptions{
		ConfidenceLevel: parseConfidenceLevels(finalCfg.confidenceLevels),
		Verbose:         finalCfg.verbose,
		NoColor:         finalCfg.noColor,
		ShowMatch:       finalCfg.showMatch,
		PrecommitMode:   precommitConfig != nil && precommitConfig.QuietMode,
	}

	var formatted string
	var formatErr error
	if finalCfg.showSuppressed {
		formatted, formatErr = formatter.Format(unsuppressedMatches, suppressedMatches, formatterOptions)
	} else {
		formatted, formatErr = formatter.Format(unsuppressedMatches, nil, formatterOptions)
	}
	if formatErr != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error formatting results: %v", formatErr),
			"Check output format and file permissions")
		return 1
	}

	// Clear sensitive data
	for i := range allMatches {
		allMatches[i].Clear()
	}
	allMatches = nil
	runtime.GC()

	if err := writeStdinOutput(in.outputFile, formatted, precommitConfig); err != nil {
		return 1
	}

	// Exit-code parity with file mode: default mode always 0, pre-commit
	// uses precommit.GetExitCode based on findings/confidence.
	hasFindings := len(unsuppressedMatches) > 0
	if precommitConfig != nil {
		highest := highestConfidenceLevel(unsuppressedMatches)
		return precommit.GetExitCode(hasFindings, false, highest, precommitConfig)
	}
	return 0
}

// runStdinPreprocessOnly emits the stdin buffer in the same format
// processPreprocessOnly uses for files, so downstream tooling sees a
// uniform layout. Returns process exit code.
func runStdinPreprocessOnly(label, content string) int {
	fmt.Printf("=== FILE: %s ===\n", label)
	fmt.Printf("Processor: Plain Text (stdin)\n")
	fmt.Printf("Status: Success\n")
	wordCount := len(strings.Fields(content))
	charCount := utf8.RuneCountInString(content)
	if wordCount > 0 || charCount > 0 {
		fmt.Printf("Content: %d words, %d characters\n", wordCount, charCount)
	}
	fmt.Printf("\n%s\n", content)
	return 0
}

// runStdinRedaction redacts the stdin content using the matches that the
// scanner produced and emits the result.
//
// Output policy (Unix-conventional, composes cleanly with shell pipes):
//   - default:       redacted content → stdout, findings → stderr
//   - --output set:  findings         → file,   redacted content → stdout
//
// Returns the process exit code. Pre-commit exit semantics still apply
// (non-zero on findings) so a redaction gateway can both emit clean output
// AND signal upstream that something was matched.
//
// We run unsuppressed matches through the redactor (suppressed matches are
// excluded by definition — they're false positives or accepted exposures).
// For lambda / gateway callers that want to redact suppressed content too,
// they can simply scan with --show-suppressed=false.
func runStdinRedaction(
	in stdinScanInputs,
	finalCfg *finalConfiguration,
	content string,
	matches []detector.Match,
	suppressedMatches []detector.SuppressedMatch,
	precommitConfig *precommit.PrecommitConfig,
) int {
	strategy := redactors.ParseRedactionStrategy(finalCfg.redactionStrategy)

	// nil output manager + nil observer is fine for in-memory redaction —
	// RedactString uses neither. Position correlation is also unnecessary
	// for plaintext stdin (1:1 mapping by definition), so we disable it
	// to avoid the correlator's added latency on small inputs.
	pr := plaintextredactor.NewPlainTextRedactor(nil, nil)
	pr.SetPositionCorrelationEnabled(false)

	redacted, _, err := pr.RedactString(content, matches, strategy)
	if err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("redaction failed: %v", err),
			"Verify input encoding and configuration")
		return 1
	}

	// When --output is set, findings go to the file and redacted content
	// streams to stdout. This lets a CI step capture a structured report
	// while still piping the cleansed text to the next stage.
	//
	// When --output is NOT set:
	//   - if stdout is NOT a terminal (piped/redirected), findings go to
	//     stderr and redacted content streams to stdout — the canonical
	//     pipe shape for `cat input | ferret-scan --stdin --enable-redaction
	//     > clean.txt` and `... 2> findings.json > clean.txt`
	//   - if stdout IS a terminal (interactive use), findings on stderr
	//     would visually interleave with redacted content on stdout with
	//     no clean separation, producing the messy output users see when
	//     they run the command without redirects. In that case suppress
	//     the findings emit and print a one-line tip pointing at the
	//     pipe shapes that capture them.
	formatted, formatErr := formatStdinFindings(matches, suppressedMatches, finalCfg, precommitConfig)
	if formatErr != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error formatting results: %v", formatErr),
			"Check output format")
		return 1
	}

	hasAnyFindings := len(matches)+len(suppressedMatches) > 0
	stdoutIsTTY := isTerminal(os.Stdout)

	switch {
	case in.outputFile != "":
		if err := writeStdinOutput(in.outputFile, formatted, precommitConfig); err != nil {
			return 1
		}
	case formatted != "" && hasAnyFindings && !stdoutIsTTY:
		// Stdout is piped/redirected — emit findings on stderr so the
		// caller can capture them with `2> findings.json` (or discard
		// with `2>/dev/null`) while still consuming redacted content
		// from stdout.
		fmt.Fprintln(os.Stderr, formatted)
	case hasAnyFindings && stdoutIsTTY:
		// Interactive use. Print a hint instead of dumping findings into
		// the user's terminal alongside the redacted content. The hint
		// itself goes to stderr so it doesn't corrupt anything if the
		// user later pipes the same command.
		fmt.Fprintf(os.Stderr,
			"(%d findings detected and redacted; redirect to capture them: '... 2> findings.txt > clean.txt')\n",
			len(matches)+len(suppressedMatches))
	}

	// Redacted content always goes to stdout. Use Print (not Println) so we
	// don't add a trailing newline that wasn't in the input — important for
	// callers that pipe the redacted bytes verbatim into another tool.
	fmt.Print(redacted)

	hasFindings := len(matches) > 0
	if precommitConfig != nil {
		highest := highestConfidenceLevel(matches)
		return precommit.GetExitCode(hasFindings, false, highest, precommitConfig)
	}
	return 0
}

// formatStdinFindings is a small helper used by runStdinRedaction so the
// formatter logic isn't duplicated. It returns the formatted findings string
// (possibly empty when there are no matches and no suppressed matches).
func formatStdinFindings(
	matches []detector.Match,
	suppressedMatches []detector.SuppressedMatch,
	finalCfg *finalConfiguration,
	precommitConfig *precommit.PrecommitConfig,
) (string, error) {
	formatter, exists := formatters.Get(finalCfg.format)
	if !exists {
		return "", fmt.Errorf("unsupported output format %q", finalCfg.format)
	}
	opts := formatters.FormatterOptions{
		ConfidenceLevel: parseConfidenceLevels(finalCfg.confidenceLevels),
		Verbose:         finalCfg.verbose,
		NoColor:         finalCfg.noColor,
		ShowMatch:       finalCfg.showMatch,
		PrecommitMode:   precommitConfig != nil && precommitConfig.QuietMode,
	}
	if finalCfg.showSuppressed {
		return formatter.Format(matches, suppressedMatches, opts)
	}
	return formatter.Format(matches, nil, opts)
}

// shouldSuppressStdinProse returns true when the human-readable progress
// lines emitted on stderr ("Scan complete: ...", "Suppressed N findings...")
// would corrupt a downstream consumer that expects clean stderr output.
//
// Prose is suppressed when ANY of the following is true:
//   - --quiet is set (explicit user request)
//   - pre-commit mode is active (existing convention)
//   - --enable-redaction is on AND no --output is set (the canonical
//     streaming-redaction shape: redacted content streams to stdout and
//     findings stream to stderr; in that mode anything else on stderr
//     would interleave with the parseable findings document, breaking
//     `2> findings.json`-style redirects)
//
// Keeping the rule in one named function means both emit sites share one
// implementation and reviewers can see the policy in a single place.
func shouldSuppressStdinProse(
	finalCfg *finalConfiguration,
	precommitConfig *precommit.PrecommitConfig,
	outputFile string,
) bool {
	if finalCfg.quiet {
		return true
	}
	if precommitConfig != nil && precommitConfig.QuietMode {
		return true
	}
	if finalCfg.enableRedaction && outputFile == "" {
		return true
	}
	return false
}

// validateStdinFlags rejects flag combinations that don't make sense with
// stdin input. Catches the common mistakes early and explains why.
func validateStdinFlags(in stdinScanInputs) error {
	// --stdin + --file <path> (with --file != "-") is ambiguous.
	if in.flags.inputFile != "" && in.flags.inputFile != "-" {
		return fmt.Errorf("--stdin and --file are mutually exclusive; pass content on stdin or specify a file")
	}
	// Positional file args are also incompatible.
	if len(in.positionalArgs) > 0 {
		return fmt.Errorf("--stdin does not accept positional file arguments; pipe content on stdin instead")
	}
	if in.flags.recursive {
		return fmt.Errorf("--stdin does not support --recursive (no directory to walk)")
	}
	if in.flags.webMode {
		return fmt.Errorf("--stdin and --web are mutually exclusive")
	}
	return nil
}

// writeStdinOutput writes the formatted result to outputFile or stdout,
// reusing the file-mode security checks (path traversal, secure perms).
func writeStdinOutput(outputFile, formatted string, precommitConfig *precommit.PrecommitConfig) error {
	if outputFile == "" {
		fmt.Println(formatted)
		return nil
	}
	cleanOutputPath := filepath.Clean(outputFile)
	abs, err := filepath.Abs(cleanOutputPath)
	if err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Invalid output file path: %s", outputFile),
			"Check that the path is valid and accessible")
		return err
	}
	if strings.Contains(outputFile, "..") || strings.Contains(cleanOutputPath, "..") {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Path traversal not allowed in output path: %s", outputFile),
			"Use absolute paths or paths without '..' components")
		return fmt.Errorf("path traversal")
	}
	cleanOutputPath = abs
	outputDir := filepath.Dir(cleanOutputPath)
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error creating output directory: %v", err),
			"Check directory permissions and available disk space")
		return err
	}
	if err := os.WriteFile(cleanOutputPath, []byte(formatted), 0600); err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Error writing to output file: %v", err),
			"Check file permissions and available disk space")
		return err
	}
	return nil
}

// parseChecksList turns "all" or "CHECK1,CHECK2" into a slice for ScanContent.
func parseChecksList(checks string) []string {
	if checks == "" || checks == "all" {
		return nil // empty means "all" in core.ParseChecksToRun
	}
	parts := strings.Split(checks, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// highestConfidenceLevel returns "high"/"medium"/"low"/"" for use with
// precommit.GetExitCode, mirroring the file-mode computation.
func highestConfidenceLevel(matches []detector.Match) string {
	highest := ""
	for _, m := range matches {
		var level string
		switch {
		case m.Confidence >= 90:
			level = "high"
		case m.Confidence >= 60:
			level = "medium"
		default:
			level = "low"
		}
		switch level {
		case "high":
			highest = "high"
		case "medium":
			if highest != "high" {
				highest = "medium"
			}
		case "low":
			if highest != "high" && highest != "medium" {
				highest = "low"
			}
		}
	}
	return highest
}
