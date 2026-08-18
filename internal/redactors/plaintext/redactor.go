// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/position"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// PlainTextRedactor implements redaction for plain text files
type PlainTextRedactor struct {
	// observer handles observability and metrics
	observer observability.Observer

	// outputManager handles file system operations
	outputManager *redactors.OutputStructureManager

	// positionCorrelator handles position correlation between extracted and original text
	positionCorrelator position.PositionCorrelator

	// enablePositionCorrelation controls whether to use position correlation
	enablePositionCorrelation bool

	// confidenceThreshold is the minimum confidence required for position-based redaction
	confidenceThreshold float64

	// fallbackToSimple controls whether to fall back to simple text replacement on correlation failure
	fallbackToSimple bool
}

// NewPlainTextRedactor creates a new PlainTextRedactor
func NewPlainTextRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *PlainTextRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &PlainTextRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        position.NewDefaultPositionCorrelator(),
		enablePositionCorrelation: true,
		confidenceThreshold:       0.8,
		fallbackToSimple:          true,
	}
}

// SetPositionCorrelationEnabled enables or disables position correlation
func (ptr *PlainTextRedactor) SetPositionCorrelationEnabled(enabled bool) {
	ptr.enablePositionCorrelation = enabled
}

// SetConfidenceThreshold sets the minimum confidence threshold for position-based redaction
func (ptr *PlainTextRedactor) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		ptr.confidenceThreshold = threshold
	}
}

// SetFallbackToSimple controls whether to fall back to simple text replacement on correlation failure
func (ptr *PlainTextRedactor) SetFallbackToSimple(fallback bool) {
	ptr.fallbackToSimple = fallback
}

// GetName returns the name of the redactor
func (ptr *PlainTextRedactor) GetName() string {
	return "plaintext_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (ptr *PlainTextRedactor) GetSupportedTypes() []string {
	return []string{"text", ".txt", ".log", ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".conf", ".ini"}
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (ptr *PlainTextRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument creates a redacted copy of the document at outputPath
func (ptr *PlainTextRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if ptr.observer != nil {
		finishTiming = ptr.observer.StartTiming("plaintext_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Read the original file
	content, err := os.ReadFile(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read original file: %w", err)
	}

	// Decode transcodable encodings (UTF-16 with/without BOM, BOM'd UTF-8)
	// to UTF-8 for redaction — matches were produced against the DECODED
	// text by the preprocessor, so redacting the raw bytes would never find
	// them (UTF-16 interleaves nulls through every match). The original
	// encoding is restored on write so a redacted .reg export or PowerShell
	// transcript remains a valid file in its native encoding.
	encoding := preprocessors.DetectTextEncoding(content)
	originalText, ok := preprocessors.DecodeToUTF8(content, encoding)
	if !ok {
		originalText = string(content)
	}

	// Perform redaction
	redactedText, redactionMap, err := ptr.redactText(originalText, matches, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to redact text: %w", err)
	}

	// Ensure output directory exists
	if ptr.outputManager != nil {
		err = ptr.outputManager.EnsureDirectoryExists(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// Write redacted content to output file with secure permissions,
	// re-encoded to the ORIGINAL file's encoding (BOM restored) so a
	// redacted UTF-16 file stays valid in its native tooling.
	// #nosec G703 -- outputPath is operator-controlled (--redaction-output-dir
	// + mirrored input filename); CLI-only path. Web mode hard-codes
	// EnableRedaction: false so this is unreachable from the HTTP boundary.
	err = os.WriteFile(outputPath, preprocessors.EncodeFromUTF8(redactedText, encoding), 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	// Preserve file attributes (but not content) if output manager is available
	if ptr.outputManager != nil {
		// Get original file info for attribute preservation
		originalInfo, err := os.Stat(originalPath)
		if err == nil {
			// Preserve permissions
			os.Chmod(outputPath, originalInfo.Mode())
			// Preserve timestamps
			os.Chtimes(outputPath, originalInfo.ModTime(), originalInfo.ModTime())
		}
	}

	processingTime := time.Since(startTime)
	confidence := ptr.calculateOverallConfidence(redactionMap)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// redactText performs the actual text redaction based on matches and strategy
func (ptr *PlainTextRedactor) redactText(originalText string, matches []detector.Match, strategy redactors.RedactionStrategy) (string, []redactors.RedactionMapping, error) {
	if len(matches) == 0 {
		return originalText, []redactors.RedactionMapping{}, nil
	}

	// Restore bounded (display-truncated) consolidated match texts to their
	// full-line spans FIRST: redaction locates matches by searching for
	// Match.Text, and a bounded display text does not occur in the document —
	// without this the whole consolidated line would silently survive
	// redaction. See redactors.RestoreBoundedMatchText.
	// Expand a consolidated cluster back into the real spans it replaced FIRST: its
	// Text is a rendered summary that occurs nowhere in the document, so without this
	// the cluster masks nothing and every handle it grouped survives in cleartext.
	// See redactors.ExpandClusterMatches and #289.
	matches = redactors.ExpandClusterMatches(matches)

	matches = redactors.RestoreBoundedMatchText(matches)

	// Collapse overlapping matches to their widest span first. Otherwise a
	// smaller match contained in a larger one (e.g. a PHONE match inside a
	// spaced CREDIT_CARD match) gets redacted first, mutating the text so the
	// larger match can no longer be located — leaving its un-redacted head
	// (the card's BIN) exposed. See redactors.ResolveOverlaps.
	matches = redactors.ResolveOverlaps(matches)

	// Sort matches by position (descending) to avoid position shifts during replacement
	sortedMatches := ptr.sortMatchesByPosition(matches)

	redactedText := originalText
	var redactionMap []redactors.RedactionMapping

	// Line start offsets, computed ONCE for the whole document and reused by
	// every match. Locating a match used to rescan the entire document per
	// match, which made redaction quadratic; see lineOffsets.
	offsets := lineOffsets(originalText)

	// Process matches in reverse order to maintain position accuracy
	for _, match := range sortedMatches {
		replacement, err := ptr.generateReplacement(match.Text, match.Type, strategy)
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate replacement for %s: %w", match.Type, err)
		}

		var startPos, endPos int
		var confidence float64
		var correlationUsed bool

		// Try position correlation if enabled
		if ptr.enablePositionCorrelation && ptr.positionCorrelator != nil {
			correlatedPos, correlationErr := ptr.correlateMatchPosition(match, originalText)
			if correlationErr == nil && correlatedPos.ConfidenceScore >= ptr.confidenceThreshold {
				// Use position correlation result
				startPos = correlatedPos.OriginalPosition.CharOffset
				endPos = startPos + len(match.Text)
				confidence = correlatedPos.ConfidenceScore
				correlationUsed = true

				// The match's own bytes are the sensitive value being redacted, so
				// they must not reach the log (BSC4) — the line, span and length
				// locate it precisely without disclosing it, which is what the
				// sibling match_skip event below already does.
				ptr.logEvent("position_correlation_success", true, map[string]interface{}{
					"match_line":         match.LineNumber,
					"match_length":       len(match.Text),
					"match_type":         match.Type,
					"confidence":         confidence,
					"correlation_method": correlatedPos.Method.String(),
					"start_pos":          startPos,
					"end_pos":            endPos,
				})
			} else {
				// Log correlation failure
				logData := map[string]interface{}{
					"match_line":       match.LineNumber,
					"match_length":     len(match.Text),
					"match_type":       match.Type,
					"error":            correlationErr,
					"threshold":        ptr.confidenceThreshold,
					"fallback_enabled": ptr.fallbackToSimple,
				}

				// Only add confidence if correlatedPos is not nil
				if correlatedPos != nil {
					logData["confidence"] = correlatedPos.ConfidenceScore
				}

				ptr.logEvent("position_correlation_failed", false, logData)

				// Fall back to simple text search if enabled
				if ptr.fallbackToSimple {
					simpleStartPos, simpleEndPos, simpleErr := ptr.findMatchPosition(redactedText, match, offsets)
					if simpleErr == nil {
						startPos = simpleStartPos
						endPos = simpleEndPos
						confidence = (match.Confidence / 100.0) * 0.5 // Normalize to 0-1 and reduce for fallback
						correlationUsed = false
					} else {
						// Skip this match if both correlation and fallback fail
						ptr.logEvent("match_skip", false, map[string]interface{}{
							"match_type":        match.Type,
							"match_line":        match.LineNumber,
							"correlation_error": correlationErr,
							"fallback_error":    simpleErr,
						})
						continue
					}
				} else {
					// Skip this match if correlation fails and fallback is disabled
					continue
				}
			}
		} else {
			// Use simple text search when position correlation is disabled
			simpleStartPos, simpleEndPos, err := ptr.findMatchPosition(redactedText, match, offsets)
			if err != nil {
				// Log warning but continue with other matches
				ptr.logEvent("position_warning", false, map[string]interface{}{
					"warning":      err.Error(),
					"match_line":   match.LineNumber,
					"match_length": len(match.Text),
					"match_type":   match.Type,
				})
				continue
			}
			startPos = simpleStartPos
			endPos = simpleEndPos
			confidence = match.Confidence
			correlationUsed = false
		}

		// Validate positions
		if startPos < 0 || endPos > len(redactedText) || startPos >= endPos {
			ptr.logEvent("invalid_position_warning", false, map[string]interface{}{
				"warning":          "invalid position calculated",
				"start_pos":        startPos,
				"end_pos":          endPos,
				"text_length":      len(redactedText),
				"correlation_used": correlationUsed,
			})
			continue
		}

		// Verify the text at the calculated position matches what we expect
		actualText := redactedText[startPos:endPos]
		if actualText != match.Text {
			ptr.logEvent("text_mismatch_warning", false, map[string]interface{}{
				"match_type":       match.Type,
				"match_line":       match.LineNumber,
				"start_pos":        startPos,
				"end_pos":          endPos,
				"correlation_used": correlationUsed,
			})

			// Try to find the correct position if there's a mismatch
			if correctedStart, correctedEnd, correctionErr := ptr.findMatchPosition(redactedText, match, offsets); correctionErr == nil {
				startPos = correctedStart
				endPos = correctedEnd
				confidence *= 0.7 // Reduce confidence for corrected positions

				ptr.logEvent("position_corrected", true, map[string]interface{}{
					"original_start":        startPos,
					"corrected_start":       correctedStart,
					"confidence_adjustment": 0.7,
				})
			} else {
				// Skip this match if we can't find the correct position
				continue
			}
		}

		// Replace the text
		redactedText = redactedText[:startPos] + replacement + redactedText[endPos:]

		// Create redaction mapping with enhanced metadata
		mapping := redactors.RedactionMapping{
			RedactedText: replacement,
			Position: redactors.TextPosition{
				Line:      match.LineNumber,
				StartChar: startPos,
				EndChar:   endPos,
			},
			DataType:   match.Type,
			Strategy:   strategy,
			Confidence: confidence,

			Metadata: map[string]interface{}{
				"correlation_used":    correlationUsed,
				"original_confidence": match.Confidence,
				"position_method":     ptr.getPositionMethodString(correlationUsed),
			},
		}

		redactionMap = append(redactionMap, mapping)

		// Log successful redaction
		ptr.logEvent("redaction_applied", true, map[string]interface{}{
			"match_type":         match.Type,
			"replacement_length": len(replacement),
			"confidence":         confidence,
			"correlation_used":   correlationUsed,
		})
	}

	return redactedText, redactionMap, nil
}

// generateReplacement delegates to the shared replacement package.
func (ptr *PlainTextRedactor) generateReplacement(originalText, dataType string, strategy redactors.RedactionStrategy) (string, error) {
	return replacement.Generate(originalText, dataType, strategy), nil
}

// Helper methods

// sortMatchesByPosition sorts matches in descending order by line number,
// then by position within the line (later positions first). This ensures
// that when replacing text, earlier positions are not shifted by later replacements.
func (ptr *PlainTextRedactor) sortMatchesByPosition(matches []detector.Match) []detector.Match {
	sorted := make([]detector.Match, len(matches))
	copy(sorted, matches)

	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].LineNumber != sorted[j].LineNumber {
			return sorted[i].LineNumber > sorted[j].LineNumber
		}
		// Same line: sort by position in context (later positions first)
		// Use the match text position within FullLine as a proxy for column offset
		posI := strings.LastIndex(sorted[i].Context.FullLine, sorted[i].Text)
		posJ := strings.LastIndex(sorted[j].Context.FullLine, sorted[j].Text)
		return posI > posJ
	})

	return sorted
}

// lineOffsets returns the byte offset at which each line of text begins.
//
// This is computed ONCE per document and shared by every match, replacing the
// per-match whole-document rescans that made redaction quadratic in
// (matches x content bytes). Measured on N distinct SSNs one per line:
// redaction cost grew 4.2x/3.6x/3.5x per input doubling (4.0x = quadratic)
// while scanning the same fixtures stayed linear, and a fixed-match/
// growing-content family showed cost tracking CONTENT at a constant match
// count — the signature of a per-match full-document scan. At ~1MB of dense
// matches this reached 78s, against a 100MB MaxFileSize ceiling.
//
// The table is returned rather than cached on the receiver because a redactor
// instance may be reused across documents and by concurrent callers; per-
// document state on the receiver would be a data race.
func lineOffsets(text string) []int {
	// One entry per line: len(text)/40 is a rough average line length, and the
	// slice grows from there rather than reallocating from zero.
	offsets := make([]int, 1, len(text)/40+2)
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// lineBounds returns the byte range of the given 1-based line in text, using a
// precomputed offset table. Only the line's own bytes are scanned, to find its
// terminating newline in text as it stands now.
//
// The caller may pass text that has already been partially rewritten. That is
// safe precisely because matches are applied in DESCENDING line order: every
// replacement made so far sits at a strictly later offset than any line still
// to be processed, so a line's start offset is still the one recorded in the
// table built from the original text. ok=false when the line is out of range.
func lineBounds(text string, offsets []int, lineNumber int) (start, end int, ok bool) {
	if lineNumber < 1 || lineNumber > len(offsets) {
		return 0, 0, false
	}
	start = offsets[lineNumber-1]
	if start > len(text) {
		return 0, 0, false
	}
	if idx := strings.IndexByte(text[start:], '\n'); idx >= 0 {
		return start, start + idx, true
	}
	return start, len(text), true
}

// findMatchPosition finds the start and end position of a match in the text.
//
// The match's own line is searched first, which is what the line number is for
// and is O(line) rather than O(document). A whole-document search remains as
// the fallback so behaviour is unchanged for a match whose recorded line number
// does not actually contain its text (a bounded/consolidated match, or a
// line-number drift from an extractor) — such a match is still located and
// still redacted, exactly as before.
func (ptr *PlainTextRedactor) findMatchPosition(text string, match detector.Match, offsets []int) (int, int, error) {
	if start, end, ok := lineBounds(text, offsets, match.LineNumber); ok {
		if idx := strings.Index(text[start:end], match.Text); idx >= 0 {
			pos := start + idx
			return pos, pos + len(match.Text), nil
		}
	}

	// Fall back to the first occurrence anywhere in the document.
	startPos := strings.Index(text, match.Text)
	if startPos == -1 {
		return 0, 0, fmt.Errorf("match text not found in document")
	}

	endPos := startPos + len(match.Text)
	return startPos, endPos, nil
}

// calculateOverallConfidence calculates the overall confidence for the redaction
func (ptr *PlainTextRedactor) calculateOverallConfidence(redactionMap []redactors.RedactionMapping) float64 {
	if len(redactionMap) == 0 {
		return 1.0
	}

	totalConfidence := 0.0
	for _, mapping := range redactionMap {
		totalConfidence += mapping.Confidence
	}

	return totalConfidence / float64(len(redactionMap))
}

// GetComponentName returns the component name for observability
func (ptr *PlainTextRedactor) GetComponentName() string {
	return "plaintext_redactor"
}

// RedactString applies redaction to in-memory content using the supplied
// matches and strategy. It is the file-free equivalent of RedactDocument /
// RedactContent: no disk I/O, no temp file, no output manager required —
// just (content, matches, strategy) in, (redactedContent, mappings) out.
//
// This is the entry point for streaming / lambda callers and for the CLI's
// stdin redaction path. Callers can construct the redactor with
// NewPlainTextRedactor(nil, nil) when they don't need an output manager.
//
// All three plaintext strategies (simple, format_preserving, synthetic) are
// supported; the strategy parameter is passed through to the same internal
// redactText routine that RedactDocument and RedactContent use, so there is
// only one redaction code path to maintain.
func (ptr *PlainTextRedactor) RedactString(content string, matches []detector.Match, strategy redactors.RedactionStrategy) (string, []redactors.RedactionMapping, error) {
	return ptr.redactText(content, matches, strategy)
}

// readFileHead returns up to n leading bytes of the file at path — enough
// for encoding detection without re-reading potentially 100MB of content.
func readFileHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the scan target the operator supplied
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := f.Read(buf)
	if read == 0 && err != nil {
		return nil, err
	}
	return buf[:read], nil
}

// RedactContent implements ContentRedactor interface for efficient content-based redaction
func (ptr *PlainTextRedactor) RedactContent(content *preprocessors.ProcessedContent, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if ptr.observer != nil {
		finishTiming = ptr.observer.StartTiming("plaintext_redactor", "redact_content", content.OriginalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Use the already-extracted text instead of re-reading the file
	originalText := content.Text

	// Perform redaction using the same logic as RedactDocument
	redactedText, redactionMap, err := ptr.redactText(originalText, matches, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to redact text: %w", err)
	}

	// Ensure output directory exists
	if ptr.outputManager != nil {
		err = ptr.outputManager.EnsureDirectoryExists(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// content.Text is the preprocessor's DECODED UTF-8; if the source file
	// was a transcodable encoding (UTF-16, BOM'd UTF-8), re-encode the
	// redacted text so the output stays valid in its native tooling — a
	// redacted .reg export or PowerShell transcript must not silently
	// become UTF-8. The original's leading bytes identify the encoding.
	outputBytes := []byte(redactedText)
	if head, rerr := readFileHead(content.OriginalPath, 512); rerr == nil {
		if enc := preprocessors.DetectTextEncoding(head); enc != preprocessors.EncodingUTF8 {
			outputBytes = preprocessors.EncodeFromUTF8(redactedText, enc)
		}
	}

	// Write redacted content to output file with secure permissions
	err = os.WriteFile(outputPath, outputBytes, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	// Preserve file attributes if output manager is available
	if ptr.outputManager != nil {
		// Get original file info for attribute preservation
		originalInfo, err := os.Stat(content.OriginalPath)
		if err == nil {
			// Preserve permissions
			os.Chmod(outputPath, originalInfo.Mode())
			// Preserve timestamps
			os.Chtimes(outputPath, originalInfo.ModTime(), originalInfo.ModTime())
		}
	}

	processingTime := time.Since(startTime)
	confidence := ptr.calculateOverallConfidence(redactionMap)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// logEvent logs an event if observer is available
func (ptr *PlainTextRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if ptr.observer != nil {
		ptr.observer.StartTiming("plaintext_redactor", operation, "")(success, metadata)
	}
}

// correlateMatchPosition correlates a detector match position with the original document
func (ptr *PlainTextRedactor) correlateMatchPosition(match detector.Match, originalText string) (*position.PositionCorrelation, error) {
	// Calculate character positions from line number and text
	startChar, endChar, err := ptr.calculateCharacterPositions(match, originalText)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate character positions: %w", err)
	}

	// Convert detector match to text position
	textPos := redactors.TextPosition{
		Line:      match.LineNumber,
		StartChar: startChar,
		EndChar:   endChar,
	}

	// Use the original text as both extracted and original content for plain text
	// In more complex scenarios, these would be different (e.g., extracted from PDF)
	correlation, err := ptr.positionCorrelator.CorrelatePosition(
		textPos,
		originalText,         // extracted text (same as original for plain text)
		[]byte(originalText), // original content
		"text",               // document type
	)

	if err != nil {
		return nil, fmt.Errorf("position correlation failed: %w", err)
	}

	// Validate the correlation result
	if err := ptr.positionCorrelator.ValidateCorrelation(correlation); err != nil {
		return nil, fmt.Errorf("correlation validation failed: %w", err)
	}

	return correlation, nil
}

// calculateCharacterPositions calculates start and end character positions from a match
func (ptr *PlainTextRedactor) calculateCharacterPositions(match detector.Match, text string) (int, int, error) {
	lines := strings.Split(text, "\n")

	if match.LineNumber < 1 || match.LineNumber > len(lines) {
		return 0, 0, fmt.Errorf("line number %d is out of range (1-%d)", match.LineNumber, len(lines))
	}

	line := lines[match.LineNumber-1] // Convert to 0-based indexing

	// Find the match text in the line
	startChar := strings.Index(line, match.Text)
	if startChar == -1 {
		return 0, 0, fmt.Errorf("match text %q not found in line %d", match.Text, match.LineNumber)
	}

	endChar := startChar + len(match.Text)

	return startChar, endChar, nil
}

// getPositionMethodString returns a string representation of the position method used
func (ptr *PlainTextRedactor) getPositionMethodString(correlationUsed bool) string {
	if correlationUsed {
		return "position_correlation"
	}
	return "simple_text_search"
}

// GetPositionCorrelationStats returns statistics about position correlation performance
func (ptr *PlainTextRedactor) GetPositionCorrelationStats() map[string]interface{} {
	return map[string]interface{}{
		"correlation_enabled":  ptr.enablePositionCorrelation,
		"confidence_threshold": ptr.confidenceThreshold,
		"fallback_enabled":     ptr.fallbackToSimple,
		"correlator_type":      fmt.Sprintf("%T", ptr.positionCorrelator),
	}
}

// calculateTextSimilarity calculates a coarse character-by-character
// similarity between two text strings. Used for telemetry/metrics in
// position-correlation logging, not as a security control.
//
// Implementation note: we compare rune-to-rune over both strings, indexed
// by rune position rather than byte offset, so multi-byte UTF-8 sequences
// produce the right answer. The previous implementation compared a rune
// from the shorter string against a byte at the same byte offset of the
// longer string, which silently produced wrong scores once either string
// contained non-ASCII content.
func (ptr *PlainTextRedactor) calculateTextSimilarity(text1, text2 string) float64 {
	if text1 == text2 {
		return 1.0
	}

	if len(text1) == 0 || len(text2) == 0 {
		return 0.0
	}

	r1 := []rune(text1)
	r2 := []rune(text2)
	shorter, longer := r1, r2
	if len(r1) > len(r2) {
		shorter, longer = r2, r1
	}

	commonChars := 0
	for i, char := range shorter {
		if char == longer[i] {
			commonChars++
		}
	}

	return float64(commonChars) / float64(len(longer))
}
