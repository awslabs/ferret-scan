// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// The unredacted disclosure, carried into every output format.
//
// writeUnredactedFilesWarning already said this on STDERR, which pipelines routinely
// discard, and the exit code was 0. Measured on a real 14KB PDF that extracts cleanly
// and yields 3 findings, scanned with --enable-redaction: SEVEN of seven output
// formats contained no mention of the refusal, so a consumer parsing stdout saw three
// findings and a clean report while the values sat unchanged on disk (#441).
//
// This file turns the same diagnostics into structured data for the formatters and
// into the count that --fail-on-incomplete acts on.

// classifyRedactionError maps a redactor's error string to a coarse cause.
//
// SUBSTRING MATCHING, and that is a known weakness rather than an oversight: the
// diagnostic carries only parallel.FileDiagnostic.Reason, which is
// result.RedactionError.Error() — free text. Typed errors from every redactor would
// be better and are a larger change than this disclosure.
//
// Two things make the weakness safe rather than merely acknowledged:
//
//  1. An unmatched string falls to formatters.UnredactedRefused, whose label
//     ("redaction refused") is true of EVERY refusal. Drift therefore loses detail
//     and never asserts a wrong remedy — it will not tell an operator to raise a
//     limit that was never hit.
//  2. TestClassifyRedactionErrorCoversTheRealRedactors pins the actual strings the
//     shipped redactors produce, so rewording one fails a test instead of silently
//     degrading every report.
func classifyRedactionError(reason string) formatters.UnredactedCause {
	r := strings.ToLower(reason)

	switch {
	// Checked before "not implemented" because the image redactor's budget refusal
	// and its unimplemented-format arm both surface through the same
	// "failed to redact image metadata: ..." prefix, and the budget message is the
	// more specific of the two.
	case strings.Contains(r, "budget") || strings.Contains(r, "too large") ||
		strings.Contains(r, "over the"):
		return formatters.UnredactedOverBudget

	case strings.Contains(r, "not implemented") || strings.Contains(r, "no redactor"):
		return formatters.UnredactedNoRedactor

	// The audio and video redactors refuse when a reported value is not present in
	// the bytes they may rewrite: their replacements must be the same length as the
	// value replaced, so a value they cannot locate cannot be overwritten without
	// moving every subsequent offset.
	case strings.Contains(r, "not found") || strings.Contains(r, "could not locate") ||
		strings.Contains(r, "not located"):
		return formatters.UnredactedValueNotLocated

	case strings.Contains(r, "permission denied") || strings.Contains(r, "no space") ||
		strings.Contains(r, "failed to create") || strings.Contains(r, "failed to write"):
		return formatters.UnredactedWriteFailed

	default:
		return formatters.UnredactedRefused
	}
}

// toFormatterUnredacted turns the per-file redaction diagnostics into the structured
// disclosure, counting how many REPORTED values each file leaves in cleartext.
//
// The value count comes from the matches actually being reported, not from the
// redactor: it is the number that sizes the exposure, and a consumer cannot recover it
// from the findings list alone because that list does not say which findings were
// written out redacted.
//
// matches must be the SAME slice the formatters receive — the unsuppressed set. Using
// allMatches would count suppressed findings as cleartext exposure, overstating it,
// and using a different slice than the formatter is the classic way for a summary to
// disagree with the rows beneath it.
func toFormatterUnredacted(diags []parallel.FileDiagnostic, matches []detector.Match) []formatters.UnredactedFile {
	if len(diags) == 0 {
		return nil
	}

	perFile := make(map[string]int, len(diags))
	for i := range matches {
		perFile[matches[i].Filename]++
	}

	out := make([]formatters.UnredactedFile, 0, len(diags))
	for _, d := range diags {
		// A file with NO reported values is not an exposure this report can speak to.
		//
		// It happens when every finding for the file was suppressed: the redactor still
		// reports a diagnostic, but there was nothing left to redact. Keeping the entry
		// produced a self-contradiction — "1 file not redacted, 0 values in cleartext" —
		// and warned about a file whose findings the operator had explicitly accepted.
		//
		// Safe because the count and the diagnostic share one path space: the diagnostic's
		// FilePath is the same string the matches carry as Filename (verified end to end —
		// an unredactable PDF with three findings counts three). If that ever diverges,
		// this would start hiding real exposures rather than dropping empty ones, which is
		// why TestSuppressedFileIsNotReportedAsExposed pins BOTH directions.
		if perFile[d.FilePath] == 0 {
			continue
		}
		out = append(out, formatters.UnredactedFile{
			Path:           d.FilePath,
			Cause:          classifyRedactionError(d.Reason),
			Detail:         scrubReportedValues(d.Reason, matches),
			ReportedValues: perFile[d.FilePath],
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// scrubReportedValues removes any reported finding's text from a redactor's error
// message before it becomes output.
//
// DEFENCE IN DEPTH, not the primary control. Detail is a redactor's own error string,
// and one of them did interpolate the raw value:
//
//	fmt.Errorf("match text %q not found in line %d", match.Text, match.LineNumber)
//
// That has been fixed at source (internal/redactors/plaintext), but before #441 such a
// string only reached stderr, and now it reaches JSON, YAML, CSV, JUnit, SARIF and the
// GitLab report. A single future Errorf can therefore turn a disclosure into a leak in
// seven places at once, which is too sharp an edge to leave guarded only by review.
//
// Deliberately NOT gated on --show-match. That flag governs whether a finding's own
// value is shown in its own row, where the reader asked for it; it is not a licence to
// print values inside a diagnostic string, and the two are different decisions. The
// value is always available in the finding itself.
//
// Cost is bounded: it runs once per unredacted file, over the reported values, and
// short-circuits on the overwhelmingly common case of an error containing no value at
// all. Values shorter than four characters are skipped, because replacing a two-digit
// string would corrupt line numbers and byte counts in the message while hiding
// nothing an attacker could not guess.
func scrubReportedValues(reason string, matches []detector.Match) string {
	if reason == "" {
		return reason
	}
	const minScrubLen = 4
	seen := make(map[string]struct{}, len(matches))
	out := reason
	for i := range matches {
		v := matches[i].Text
		if len(v) < minScrubLen {
			continue
		}
		if _, done := seen[v]; done {
			continue
		}
		seen[v] = struct{}{}
		if strings.Contains(out, v) {
			out = strings.ReplaceAll(out, v, fmt.Sprintf("[HIDDEN] (len=%d)", len(v)))
		}
	}
	return out
}
