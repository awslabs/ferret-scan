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
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
	"github.com/awslabs/ferret-scan/v2/internal/precommit"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	plaintextredactor "github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
	"github.com/awslabs/ferret-scan/v2/internal/redactverify"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
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
	explain        bool // --explain: attach rationale + verdict annotations to findings
	// validatorBudgets is the parsed --validator-budget map (per-validator time
	// limits), or nil when unset. Applied to the stdin ScanContent config so a
	// runaway validator on piped input is bounded exactly as in file mode.
	validatorBudgets map[string]execguard.ValidatorBudget
	// limit is the --limit value (max findings to display). 0 = unlimited.
	limit int
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

	// The front half --file runs, shared rather than copied, and run before stdin is read so that a
	// refusal (an unknown --profile, an expiry spelling that does not parse) costs the caller nothing
	// and writes nothing to stdout. This path used to resolve its own configuration with a copy of
	// main()'s that skipped four of its steps (#887); see prepareRun.
	var debugObs *observability.DebugObserver
	if in.flags.debug {
		debugObs = observability.NewDebugObserver(os.Stderr)
	}
	run, err := prepareRun(in.flags, stdinRun, debugObs)
	if err != nil {
		return 1
	}
	cfg := run.cfg
	precommitConfig := run.precommitConfig
	effectiveProfileName := run.effectiveProfileName
	activeProfile := run.activeProfile
	finalCfg := run.final

	// Read stdin with a hard cap matching the file-mode size limit. We read
	// MaxFileSize+1 so we can distinguish "exactly at limit" from "over limit".
	//
	// Deliberately the flat ceiling and NOT router.MaxSizeForPath, which raises the limit
	// for a video container (#410). Two reasons, either sufficient: there is no path here
	// to take a type from — --stdin-name is a synthetic label the caller chooses, so
	// honouring it would let `--stdin-name x.mp4` pick the limit — and this path cannot
	// scan a video anyway, because the NUL-byte check below refuses binary content a few
	// lines further on. A raised ceiling here would buy nothing except a larger buffer
	// before the same refusal.
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

	// Decode to UTF-8 for scanning WITHOUT discarding bytes, and remember what the input was
	// so the redacted stream can be written back in it.
	//
	// This used to be a bare strings.ToValidUTF8(content, "\uFFFD"), whose comment claimed it
	// matched "what plaintext_preprocessor does for files". That was true of the code and false
	// of the effect: for a legacy single-byte file — Windows-125x, ISO-8859-x — EVERY non-ASCII
	// byte is invalid UTF-8, so every accented character became U+FFFD. Measured on a 189-byte
	// cp1252 roster, `cat roster.txt | ferret-scan --stdin --enable-redaction` emitted 10
	// replacement runes, lost `café` and `Björn`, and reported 2 findings where the same file
	// scanned by path reports 3 — `José García` did not match PERSON_NAME once its accents were
	// gone. Under the sink rule that missing finding is a cleartext value in the "clean" output.
	//
	// DetectTextEncoding + DecodeToUTF8 is the same pair the file path uses, and for
	// EncodingLegacy8Bit it is a lossless identity mapping, so the bytes survive the round trip.
	// ToValidUTF8 remains the fallback for content no encoding claims: marking a byte is still
	// better than deleting it, and it can no longer be reached by a merely-legacy file.
	//
	// UTF-16 cannot arrive here: the NUL-byte rejection above returns first.
	content := string(raw)
	stdinEncoding := preprocessors.EncodingUTF8
	if !utf8.ValidString(content) {
		if enc := preprocessors.DetectTextEncoding(raw); enc != preprocessors.EncodingUTF8 {
			if decoded, ok := preprocessors.DecodeToUTF8(raw, enc); ok {
				content, stdinEncoding = decoded, enc
			}
		}
		if !utf8.ValidString(content) {
			content = strings.ToValidUTF8(content, "\uFFFD")
		}
	}

	// Apply pre-commit overrides for non-color/format defaults that the
	// main path would normally apply via precommitConfig.
	if precommitConfig != nil {
		if precommitConfig.NoColor {
			finalCfg.noColor = true
		}
		// The file path guards this with !isFlagSet("quiet"); this path did not, which is why
		// --stdin --pre-commit-mode --quiet=false was quiet anyway. effectivePrecommitQuiet is that
		// guard, shared rather than restated.
		if effectivePrecommitQuiet(precommitConfig) {
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
	// Use the resolved path, not the raw flag, so suppressions.file in the config
	// file is honored here too. Reading the flag directly reintroduces exactly the
	// defect this resolution chain exists to prevent.
	//
	// The loader's diagnostics (a file that cannot be parsed, rules refused for unknown keys, #866) go
	// to stderr, which with --enable-redaction and no --output is the findings DOCUMENT: one prose line
	// ahead of the JSON breaks `2> findings.json`. Same mechanical arm as the provenance note below
	// (stdinStderrCarriesFindings), applied for the same reason; every other mode keeps the warnings.
	loaderWarnings := io.Writer(os.Stderr)
	if stdinStderrCarriesFindings(finalCfg, in.outputFile) {
		loaderWarnings = io.Discard
	}
	suppressionManager := suppressions.NewSuppressionManagerWithOptions(finalCfg.suppressionFile,
		suppressions.ManagerOptions{Warnings: loaderWarnings})
	// The lifetime --generate-suppressions gives new rules, from --suppression-expires or
	// suppressions.expires_in. Never applied here before #887, so stdin's generated rules never
	// expired and a spelling the file path refuses was accepted.
	suppressionManager.SetGeneratedExpirySpec(run.generatedExpiry)

	// Parse checks list into a []string for ScanContent.
	//
	// An unrecognized name is a hard error, matching file mode. Failing open here
	// meant running ZERO validators and reporting clean — and under
	// --enable-redaction, streaming the input back byte-identical at rc 0.
	checks, err := parseChecksList(finalCfg.checksToRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	// The checks core.ScanContent will run for these, and the one it cannot run on piped content.
	checksRun, checksNotApplicable := stdinChecksRun(checks)

	scanCfg := core.ContentScanConfig{
		VirtualPath:        in.stdinName,
		Checks:             checks,
		Debug:              finalCfg.debug,
		Verbose:            finalCfg.verbose,
		Explain:            in.explain,
		Config:             cfg,
		Profile:            activeProfile,
		ValidatorOverrides: run.validatorOverrides, // --disable-ip-types, after config and profile (#887)
		SuppressionManager: nil,                    // applied below so we can run --generate-suppressions on raw matches
		ValidatorBudgets:   in.validatorBudgets,
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

	// Incomplete coverage (v2 Phase 4): the stdin scan's coverage was cut short (a
	// per-validator budget or size cap, a timeout, a recovered panic), so findings may
	// be MISSING -- and under --enable-redaction, values may be in the redacted stream
	// in clear. Disclosed on stderr in the same format as the file path (a single
	// virtual "file"), and in pre-commit mode as the one-line notice the file path
	// prints there, which this path used to drop: 0 bytes of disclosure (#770).
	//
	// It also drives the exit code, on BOTH exits below: --fail-on-incomplete escalates
	// a clean result to 3, exactly as for --file. The redaction exit used to return
	// before that resolution and exit 0 whatever the flag said.
	if result.Incomplete {
		if precommitConfig == nil {
			writeIncompleteCoverageWarning(os.Stderr,
				[]parallel.FileDiagnostic{{FilePath: scanCfg.VirtualPath, Reason: result.IncompleteReason}}, 1)
		} else {
			writePrecommitStdinIncompleteNotice(os.Stderr, scanCfg.VirtualPath)
		}
	}
	incompleteCount := 0
	if result.Incomplete {
		incompleteCount = 1
	}

	// --generate-suppressions writes against raw matches before suppression.
	if finalCfg.generateSuppressions {
		if len(allMatches) > 0 {
			reason := "Auto-generated suppression rule (disabled by default)"
			if err := suppressionManager.GenerateSuppressionRules(allMatches, reason, false); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to generate suppression rules: %v\n", err)
			} else {
				suppressions.WriteGenerationReport(os.Stderr, suppressionManager.LastGeneration())
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

	// The enabled rules for this input that matched none of its findings (#885), for the note below and
	// the stats block. Asked once, after matching: this path generates BEFORE it matches, so the manager's
	// ledger already holds whatever generation rewrote (see unmatchedRulesAccount). A cut-short scan
	// names none, since its findings were not all looked for.
	unmatched := newUnmatchedRulesAccount(suppressionManager, stdinRunScope(in.stdinName, result.Incomplete,
		checksRun, checksNotApplicable, result.DisabledDetectionTypes)).report()

	// The config-provenance note is a DISCLOSURE about what governed the scan, not progress output, so
	// it is gated on neither --quiet nor pre-commit mode — the same rule #603 applied to the file path.
	//
	// #603 MISSED THIS CALL SITE, and TM-13's unqualified claim that the note is "gated on neither
	// --quiet, non-interactive, nor pre-commit" was therefore false on the stdin path. Measured at
	// ea4e2f4 with a .ferret-scan.yaml in the working directory disabling copyright and internal_url:
	//
	//	--file, any of the five triggers   109 bytes, note present   (fixed by #603)
	//	--stdin, no trigger                145 bytes, note present
	//	--stdin + PRE_COMMIT=1               0 bytes, note ABSENT
	//	  ... same for _PRE_COMMIT_RUNNING, PRE_COMMIT_HOOK, GIT_HOOK_TYPE,
	//	      --pre-commit-mode and --quiet
	//
	// Which is TB-7 again on a different input path: a pull request that ships a config file silences
	// the gate reviewing it, with nothing on stderr and a clean exit code.
	//
	// It IS still gated on the one arm of shouldSuppressStdinProse that is a real constraint rather
	// than a preference: with --enable-redaction and no --output, stderr carries the findings DOCUMENT,
	// so prose there breaks `2> findings.json`. That arm suppresses a disclosure for a mechanical
	// reason, not because the operator asked for quiet.
	if !stdinStderrCarriesFindings(finalCfg, in.outputFile) {
		reportConfigProvenance(os.Stderr, cfg, in.flags.configFile,
			configChecksNarrowingFor(cfg, effectiveProfileName, checksRun, checksNotApplicable))
		// Same rule for the built-in precommit profile's remaining override (#768).
		reportBuiltinProfileChecks(os.Stderr, cfg, effectiveProfileName)
		// Same rule for detection that config, a profile or --disable-ip-types switched off, and for a
		// disabled_types entry that named nothing: the file path's Note and Warning, from the answer the
		// validators ScanContent built gave. This path printed neither, so a narrowed stdin scan looked
		// complete. With stderr carrying the findings document the narrowing has no channel yet: the
		// document's stats.disabled_detection_types is the remaining half of #887.
		reportDisabledDetectionTypes(os.Stderr, result.DisabledDetectionTypes, result.UnrecognisedDisabledTypes)
		// And for findings an EXPIRED rule would have suppressed (#866). The file path has printed it
		// since #699; here it was never printed, so `--stdin --pre-commit-mode` blocked a commit with 0
		// bytes on stderr and no hint that the operator's own baseline had lapsed. Counted by the
		// IsSuppressed loop above, once per lapsed (rule, finding) pair.
		expiredSkips, oldestExpiry := suppressionManager.ExpiredSkips()
		writeExpiredRulesWarning(os.Stderr, expiredSkips, oldestExpiry)
		// And for a rule that matched nothing, the file path's note (#885). With stderr carrying the
		// findings document the count rides in its stats block instead.
		suppressions.WriteUnmatchedRulesNote(os.Stderr, unmatched)
	}

	if !shouldSuppressStdinProse(finalCfg, precommitConfig, in.outputFile) {
		// Unknown-key warnings DO ride the general gate. That is deliberate and matches the file path:
		// a typo'd key means a setting the operator wrote did not apply, which is a correctness
		// annoyance rather than an attacker's lever, and tests/integration
		// TestUnknownConfigKeysSilentInPrecommit pins it.
		warnUnknownConfigKeys(os.Stderr, cfg)

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

	// What the findings report says about this run beyond the findings, for whichever of the two report
	// sites below writes it. See stdinFormatterOptions.
	report := &stdinReport{
		precommitConfig:        precommitConfig,
		outputToFile:           in.outputFile != "",
		elapsed:                elapsed,
		suppressedCount:        suppressedCount,
		disabledDetectionTypes: result.DisabledDetectionTypes,
		notExamined:            stdinNotExamined(result, scanCfg.VirtualPath),
		scope: scopeInputsFor(checksRun, checksNotApplicable, result.DisabledDetectionTypes,
			run, in.flags, suppressionManager),
		suppressionRulesUnmatched: unmatched.Count(),
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
		// The same notice for the redacted-copy directory, which this path does not use either: the
		// redacted content is the stream on stdout. Before #887 the flag was dropped without a word, so
		// `--redaction-output-dir out` left no out/ and nothing said why. Like the audit-log notice it is
		// printed whatever stderr carries: the operator named a flag that does nothing here, and a loud
		// mismatch is the better failure. Only the flag triggers it; redaction.output_dir in a config
		// file, written for --file runs, does not.
		if isFlagSet("redaction-output-dir") {
			fmt.Fprintln(os.Stderr, "Note: --redaction-output-dir is not supported with --stdin and will be ignored; the redacted content is written to stdout")
		}
		return runStdinRedaction(in, finalCfg, content, unsuppressedMatches, suppressedMatches, precommitConfig, stdinEncoding, incompleteCount, report)
	}

	// Resolve formatter.
	formatter, exists := formatters.Get(finalCfg.format)
	if !exists {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Unsupported output format '%s'", finalCfg.format),
			fmt.Sprintf("Use one of: %s", strings.Join(formatters.List(), ", ")))
		return 1
	}

	// Same treatment as file mode: an unrecognised confidence level is refused rather than turned
	// into a filter that matches nothing. See core.ParseConfidenceLevels (#683).
	confidenceFilter, confErr := parseConfidenceLevels(finalCfg.confidenceLevels)
	if confErr != nil {
		printPrecommitError(precommitConfig, confErr.Error(),
			"Pass one or more of high,medium,low — or \"all\" — separated by commas")
		return 1
	}

	formatterOptions := stdinFormatterOptions(finalCfg, confidenceFilter, in.limit, unsuppressedMatches, report)

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
	// uses precommit.GetExitCode based on findings/confidence. --fail-on-incomplete
	// escalates an otherwise-clean exit to exitCodeIncompleteCoverage (3) when the
	// scan's coverage was cut short, but never downgrades a non-zero verdict.
	if precommitConfig != nil {
		exitCode := precommit.Resolve(unsuppressedMatches, precommitConfig).WithToolError(false).ExitCode
		return resolveIncompleteExitCode(exitCode, finalCfg.failOnIncomplete, incompleteCount)
	}
	return resolveIncompleteExitCode(0, finalCfg.failOnIncomplete, incompleteCount)
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
// AND signal upstream that something was matched, and --fail-on-incomplete
// escalates a cut-short scan to 3 exactly as it does for --file (#770):
// incompleteCount is the caller's count of inputs not fully examined (0 or 1).
// report is what the findings report says about the run; see stdinFormatterOptions.
//
// A cut-short stream is still emitted, as for clean input -- the redacted text
// with whatever WAS found masked -- because --file writes its partial copy too,
// and the two paths share one rule: the output never exceeds --file's, the
// disclosure (stderr) is always made, and the signal is the exit code.
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
	inputEncoding preprocessors.TextEncoding,
	incompleteCount int,
	report *stdinReport,
) int {
	// Parsed and validated by applyRedactionStrategy at the top of runStdin.
	strategy := finalCfg.redactionStrategy

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

	// THE FLOOR, and this is the instance with the least margin for error. The redacted text goes to
	// STDOUT, so it is usually being captured -- `cat sensitive.log | ferret-scan --stdin
	// --enable-redaction > clean.log`. A value the redactor left behind lands in clean.log, the command
	// reports success, and there is no file on disk to inspect afterwards. Nothing verified this before.
	//
	// Refusing means writing NOTHING to stdout: a partial stream is indistinguishable from a complete
	// one to the process on the other end of the pipe. The message goes to stderr, where the findings go
	// in this shape anyway, and the return is non-zero so a shell `&&` chain stops.
	if residual := redactverify.ResidualTypes([]byte(redacted), matches); len(residual) > 0 {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("refusing to emit redacted content: reported value(s) of type %s survive it",
				strings.Join(residual, ", ")),
			"The input is unchanged. Re-run without --enable-redaction to see the findings.")
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
	formatted, formatErr := formatStdinFindings(matches, suppressedMatches, finalCfg, in.limit, report)
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

	// Redacted content always goes to stdout, re-encoded to whatever the input arrived in, so a
	// legacy single-byte file streams back byte-for-byte outside the spans that were redacted.
	// Written as BYTES rather than with fmt.Print for the same reason the comment below gives
	// about newlines: the point is that nothing is added, removed or re-interpreted. For UTF-8
	// input EncodeFromUTF8 is the identity, so this is a no-op on the common path.
	//
	// Use Write (not Println) so we don't add a trailing newline that wasn't in the input —
	// important for callers that pipe the redacted bytes verbatim into another tool.
	if _, err := os.Stdout.Write(preprocessors.EncodeFromUTF8(redacted, inputEncoding)); err != nil {
		// A short write on stdout means the consumer went away mid-stream. Report it rather
		// than exiting 0 on truncated redacted output, which a gateway would treat as clean.
		fmt.Fprintf(os.Stderr, "Error: writing redacted content to stdout: %v\n", err)
		return 1
	}

	if precommitConfig != nil {
		exitCode := precommit.Resolve(matches, precommitConfig).WithToolError(false).ExitCode
		return resolveIncompleteExitCode(exitCode, finalCfg.failOnIncomplete, incompleteCount)
	}
	return resolveIncompleteExitCode(0, finalCfg.failOnIncomplete, incompleteCount)
}

// writePrecommitStdinIncompleteNotice is the pre-commit form of the cut-short disclosure for
// --stdin: one line, no frame, as the file path's pre-commit notice is, because pre-commit output
// is read in a terminal mid-commit. Before #770 pre-commit mode suppressed the stdin warning
// outright, so a cut-short `git diff | ferret-scan --stdin --pre-commit-mode` printed nothing.
//
// Worded for what happened here, a scan cut short: the input was read and partly scanned. The file
// path's notice names its cause with the same label (#817).
func writePrecommitStdinIncompleteNotice(w io.Writer, label string) {
	fmt.Fprintf(w, "ferret-scan: %s NOT fully examined (coverage cut short) — findings may be missing. "+
		"Re-run without --pre-commit for detail.\n", label)
}

// formatStdinFindings is a small helper used by runStdinRedaction so the
// formatter logic isn't duplicated. It returns the formatted findings string
// (possibly empty when there are no matches and no suppressed matches).
//
// report may be nil, which means no pre-commit config and nothing known about the run beyond the
// flags: no stats block and no scope. runStdinRedaction always passes one.
func formatStdinFindings(
	matches []detector.Match,
	suppressedMatches []detector.SuppressedMatch,
	finalCfg *finalConfiguration,
	limit int,
	report *stdinReport,
) (string, error) {
	formatter, exists := formatters.Get(finalCfg.format)
	if !exists {
		return "", fmt.Errorf("unsupported output format %q", finalCfg.format)
	}
	// Propagated rather than exiting: this helper has an error return, and the caller decides.
	confidenceFilter, confErr := parseConfidenceLevels(finalCfg.confidenceLevels)
	if confErr != nil {
		return "", confErr
	}
	// Limit is passed through so the findings report from the redaction path is
	// capped exactly like the non-redaction path's. It only ever bounds the
	// report: the caller already redacted against the FULL match set, so a
	// smaller report can never mean less redacted content.
	opts := stdinFormatterOptions(finalCfg, confidenceFilter, limit, matches, report)
	if finalCfg.showSuppressed {
		return formatter.Format(matches, suppressedMatches, opts)
	}
	return formatter.Format(matches, nil, opts)
}

// stdinReport is what a --stdin findings report says about the run beyond the findings themselves.
type stdinReport struct {
	precommitConfig        *precommit.PrecommitConfig
	outputToFile           bool
	elapsed                time.Duration
	suppressedCount        int
	disabledDetectionTypes map[string][]string
	notExamined            []formatters.NotExaminedFile
	// scope is everything NewScanScope needs except the confidence filter, which each report site
	// parses itself.
	scope formatters.ScopeInputs
	// suppressionRulesUnmatched is how many enabled rules for this input matched no finding (#885).
	suppressionRulesUnmatched int
}

// stdinFormatterOptions is the ONE FormatterOptions both --stdin report sites build: the report runStdinScan
// writes to stdout or --output, and the one runStdinRedaction writes beside the redacted stream (#904).
//
// There were two keyed literals, and neither set Stats, NotExamined, OutputToFile or a scope, so the JSON
// document was `{"results": [...]}` whatever happened: no stats block, so a cut-short or narrowed stdin
// scan read as complete, and `--stdin --pre-commit-mode --output r.json` on clean input wrote 0 bytes
// where --file writes the 171-byte `{"stats":…,"results":[]}` document. Go does not flag a field missing
// from a keyed literal, which is how #699's expiry field reached one of main()'s copies and not this
// path's; one constructor is how a field added here reaches both report sites.
//
// Stats is the file path's block for one virtual file (total_files 1), set for every format but text.
// Text renders Stats as a "Scan Summary" block that --stdin text has never printed, and a full-scope
// text report must keep its bytes; the machine formats carry the same facts as data. NotExamined and
// FailOnIncomplete carry a cut-short scan into junit, sarif and gitlab-sast as --file does (#770), and
// the stderr warning stays.
func stdinFormatterOptions(
	finalCfg *finalConfiguration,
	confidence map[string]bool,
	limit int,
	matches []detector.Match,
	r *stdinReport,
) formatters.FormatterOptions {
	var precommitConfig *precommit.PrecommitConfig
	if r != nil {
		precommitConfig = r.precommitConfig
	}
	opts := formatters.FormatterOptions{
		ConfidenceLevel: confidence,
		Verbose:         finalCfg.verbose,
		NoColor:         finalCfg.noColor,
		ShowMatch:       finalCfg.showMatch,
		PrecommitMode:   effectivePrecommitQuiet(precommitConfig),
		// Resolved once by precommit.Resolve, so the message the user reads and the exit code
		// returned below cannot disagree. See precommit.Decision.
		PrecommitBlockMessage: precommit.Resolve(matches, precommitConfig).Message,
		Limit:                 limit,
		FailOnIncomplete:      finalCfg.failOnIncomplete,
	}
	if r == nil {
		return opts
	}
	// An explicitly requested artifact is written even when pre-commit mode would otherwise stay
	// silent, as on --file. See FormatterOptions.OutputToFile (#353).
	opts.OutputToFile = r.outputToFile
	opts.NotExamined = r.notExamined
	if finalCfg.format != "text" {
		opts.Stats = r.stats(matches)
	}
	scope := r.scope
	scope.ConfidenceLevel = confidence
	opts.Scan = formatters.NewScanScope(scope)
	return opts
}

// stats is the file path's stats block for a run over one virtual file. The counts are over the
// matches the report renders, which is what --file counts them over.
func (r *stdinReport) stats(matches []detector.Match) *formatters.ScanStats {
	var high, medium, low int
	for _, m := range matches {
		switch {
		case m.Confidence >= 90:
			high++
		case m.Confidence >= 60:
			medium++
		default:
			low++
		}
	}
	return &formatters.ScanStats{
		TotalFiles: 1,
		// A cut-short input is counted processed AND not examined, as --file counts a cut-short file:
		// it was read and partly scanned.
		FilesProcessed:         1,
		FilesNotExamined:       len(r.notExamined),
		DisabledDetectionTypes: r.disabledDetectionTypes,
		TotalFindings:          len(matches),
		High:                   high,
		Medium:                 medium,
		Low:                    low,
		Suppressed:             r.suppressedCount,
		Duration:               r.elapsed.Seconds(),
		// The rules for this input that matched nothing, as --file counts them (#885).
		SuppressionRulesUnmatched: r.suppressionRulesUnmatched,
	}
}

// stdinNotExamined is the structured not-examined entry for a cut-short --stdin scan, with the cause
// core.ScanContent stated and the detail humanized as --file humanizes it.
func stdinNotExamined(result *core.ScanResult, label string) []formatters.NotExaminedFile {
	if result == nil || len(result.NotExamined) == 0 {
		return nil
	}
	entries := make([]unscannedEntry, 0, len(result.NotExamined))
	for _, nf := range result.NotExamined {
		cause, ok := fromProducerCause(nf.Cause)
		if !ok {
			// ScanContent names only cut-shorts; an unstated cause on this path is one.
			cause = causeCutShort
		}
		path := nf.Path
		if path == "" {
			path = label
		}
		entries = append(entries, unscannedEntry{Path: path, Cause: cause, Detail: humanizeReason(path, nf.Detail)})
	}
	return toFormatterNotExamined(entries)
}

// The scope block both input paths render (#904). These helpers live beside the --stdin report because
// --file builds its FormatterOptions from them too, and one copy is what keeps the two paths agreeing.

// stdinChecksRun is the checks core.ScanContent runs for this --stdin scan, and the one it cannot run.
//
// core.ScanContent builds its validators from ParseChecksToRun(checks) and then deletes METADATA, which
// has no file for the metadata extractors to read; this is that set, from the same call. It is not an
// echo of --checks: an echo would list METADATA as run. core.ScanResult has no field for the set it
// built, which is the better source (follow-up).
func stdinChecksRun(checks []string) (run, notApplicable []string) {
	for name, enabled := range core.ParseChecksToRun(checks) {
		if enabled && name != "METADATA" {
			run = append(run, name)
		}
	}
	sort.Strings(run)
	return run, []string{"METADATA"}
}

// validatorNames is the check names of a validator set: on --file, the set handed to the detector.
func validatorNames(validators map[string]detector.Validator) []string {
	names := make([]string, 0, len(validators))
	for name := range validators {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// fileScanScope is --file's scope block: the validator set main() handed the detector, the parsed
// confidence filter, and what those validators report config disabled. nil for a full-scope run.
func fileScanScope(
	validators map[string]detector.Validator,
	confidence map[string]bool,
	disabled map[string][]string,
	run *preparedRun,
	flags extractedFlags,
	sm *suppressions.SuppressionManager,
) *formatters.ScanScope {
	in := scopeInputsFor(validatorNames(validators), nil, disabled, run, flags, sm)
	in.ConfidenceLevel = confidence
	return formatters.NewScanScope(in)
}

// scopeInputsFor gathers what both input paths know about a run for formatters.NewScanScope, except
// the confidence filter. The profile and the config source come from what prepareRun settled, not
// from re-reading flags: the profile is the one the run is under, whether --profile or pre-commit
// mode selected it.
func scopeInputsFor(
	checksRun, notApplicable []string,
	disabled map[string][]string,
	run *preparedRun,
	flags extractedFlags,
	sm *suppressions.SuppressionManager,
) formatters.ScopeInputs {
	in := formatters.ScopeInputs{
		ChecksRun:               checksRun,
		AllChecks:               core.CheckNames(),
		ChecksNotApplicable:     notApplicable,
		DisabledDetectionTypes:  disabled,
		SuppressionRulesEnabled: suppressionRulesInForce(sm),
	}
	if run == nil {
		return in
	}
	if run.activeProfile != nil && run.effectiveProfileName != "" {
		by := formatters.ProfileSelectedByPrecommit
		if flags.profileName != "" {
			by = formatters.ProfileSelectedByFlag
		}
		in.Profile = &formatters.ScanProfile{Name: run.effectiveProfileName, SelectedBy: by}
	}
	sourcePath := ""
	if run.cfg != nil {
		sourcePath = run.cfg.SourcePath
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	in.Config = formatters.ConfigSourceOf(sourcePath, flags.configFile != "", cwd)
	return in
}

// suppressionRulesInForce counts the rules IsSuppressed can apply: enabled, applied by the loader (#866)
// and not expired, in a manager that is itself enabled.
func suppressionRulesInForce(sm *suppressions.SuppressionManager) int {
	if sm == nil || !sm.IsEnabled() {
		return 0
	}
	now := time.Now()
	n := 0
	for _, rule := range sm.ListSuppressions() {
		if rule.Enabled && rule.NotApplied == "" && (rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt)) {
			n++
		}
	}
	return n
}

// configChecksNarrowing is the checks a working-directory config limited a run to, for the provenance
// note (#673 §2): the note used to say only that such a config "can disable detection types".
type configChecksNarrowing struct {
	run, notRun, notApplicable []string
	total                      int
}

// String is the note's clause, "EMAIL (18 of 19 not run)", naming what the input path cannot run so
// the counts add up: "EMAIL (17 of 19 not run, METADATA not applicable)" on --stdin.
func (n *configChecksNarrowing) String() string {
	ran := "no check"
	if len(n.run) > 0 {
		ran = strings.Join(n.run, ", ")
	}
	counts := fmt.Sprintf("%d of %d not run", len(n.notRun), n.total)
	if len(n.notApplicable) > 0 {
		counts += ", " + strings.Join(n.notApplicable, ", ") + " not applicable"
	}
	return ran + " (" + counts + ")"
}

// configChecksNarrowingFor returns what the CONFIG narrowed about the checks that ran, or nil when it
// narrowed nothing: --checks chose them, the built-in precommit profile chose them (a config may widen
// that profile's set but not narrow it, #768), or every check ran.
func configChecksNarrowingFor(cfg *config.Config, effectiveProfileName string, checksRun, notApplicable []string) *configChecksNarrowing {
	if cfg == nil || isFlagSet("checks") || cfg.BuiltinProfile(effectiveProfileName) != nil {
		return nil
	}
	all := core.CheckNames()
	skip := make(map[string]bool, len(checksRun)+len(notApplicable))
	for _, name := range checksRun {
		skip[name] = true
	}
	for _, name := range notApplicable {
		skip[name] = true
	}
	var notRun []string
	for _, name := range all {
		if !skip[name] {
			notRun = append(notRun, name)
		}
	}
	if len(notRun) == 0 {
		return nil
	}
	run := append([]string(nil), checksRun...)
	sort.Strings(run)
	return &configChecksNarrowing{run: run, notRun: notRun, notApplicable: notApplicable, total: len(all)}
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
	if effectivePrecommitQuiet(precommitConfig) {
		return true
	}
	if stdinStderrCarriesFindings(finalCfg, outputFile) {
		return true
	}
	return false
}

// stdinStderrCarriesFindings reports whether stderr is the findings DOCUMENT rather than a human
// channel.
//
// With --enable-redaction and no --output, the redacted content goes to stdout and the findings report
// goes to stderr, so any prose written there corrupts `2> findings.json`. This is the one reason to
// withhold even a disclosure, and it is separated from shouldSuppressStdinProse's other arms precisely
// so it can be applied on its own: --quiet and pre-commit are operator PREFERENCES about progress
// output, while this is a mechanical constraint about what stderr is carrying.
func stdinStderrCarriesFindings(finalCfg *finalConfiguration, outputFile string) bool {
	return finalCfg.enableRedaction && outputFile == ""
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
	// The stdin twin of the --output gate in main; see the reasoning there. An output path
	// refusal costs no coverage and is loud, so the refusal stays and only the substring test
	// is narrowed to a segment test. `--output ../escape.json` is still refused with a
	// non-zero exit, which TestStdin_OutputPathTraversalRejected pins; `--output
	// report..final.json` now works.
	if pathEscapesBase(outputFile) {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Path traversal not allowed in output path: %s", outputFile),
			"Use an absolute path, or one that does not climb above the working directory")
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
//
// Delegates to normalizeChecksArg so stdin mode and file mode share one vocabulary.
// This function used to do its own thing: no upper-casing and no validation, handing
// the raw strings to core.ParseChecksToRun, whose loop silently discards any name it
// does not recognise. The result was that "--checks ssn" found an SSN via --file and
// nothing via --stdin, and "--checks BOGUS" reported clean at rc 0 instead of the
// rc 1 file mode gives. See normalizeChecksArg for the measurements.
func parseChecksList(checks string) ([]string, error) {
	return normalizeChecksArg(checks)
}
