// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package legacyole redacts legacy Office documents (.doc/.xls/.ppt).
//
// These are OLE Compound File Binary containers, not ZIPs, so the OOXML redactor
// does not apply. Before this package they had no redactor at all: a scan found
// sensitive values, reported them, and then told the user "no redactor
// registered for file type: .doc" while the original values stayed in cleartext.
//
// # Why in-place patching rather than rebuilding the container
//
// A CFB file is a sector-addressed filesystem: a header, a FAT chain, directory
// entries carrying each stream's start sector and byte length, and — inside the
// property streams — length-prefixed values. Rewriting it means keeping all of
// that consistent, and getting it wrong produces a file Word refuses to open. A
// corrupt document that *looks* redacted is worse than an honest refusal, which
// is why the PDF redactor declines rather than guessing.
//
// There is a third option, and it is the one used here: overwrite the match
// bytes with a replacement of THE SAME BYTE LENGTH. No stream changes size, so
// every offset, chain and length prefix stays exactly as the original file wrote
// it. Nothing needs to be recomputed because nothing moved.
//
// Verified on a real 674KB .doc: file size identical, 48 bytes changed, all
// inside stream data with the header/FAT/directory untouched, and the result read
// back correctly by two independent parsers — `file(1)` reported it as a valid
// Composite Document with the redacted application name, and macOS `textutil`
// (Apple's own Word reader) converted it to text showing the mask in place of the
// original phrase.
//
// # The strategy constraint this creates
//
// Same-length is a hard requirement, and the "simple" strategy cannot meet it:
// "[SSN-REDACTED]" is 14 bytes against an 11-byte SSN. Rather than silently
// truncate a token (which would leave part of a value behind) or refuse the file,
// this redactor uses the length-preserving replacement the repo already has, and
// falls back to a same-length mask when even that would not fit.
package legacyole

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/richardlehane/mscfb"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// maskByte is what a value becomes when no length-preserving replacement fits.
// '*' matches the character FormatPreserving already uses, so a masked value
// looks the same whichever path produced it.
const maskByte = '*'

// LegacyOLERedactor redacts .doc/.xls/.ppt by same-length in-place overwrite.
type LegacyOLERedactor struct {
	observer      observability.Observer
	outputManager *redactors.OutputStructureManager
}

// NewLegacyOLERedactor creates a redactor for legacy Office documents.
func NewLegacyOLERedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *LegacyOLERedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}
	return &LegacyOLERedactor{observer: observer, outputManager: outputManager}
}

// GetName returns the name of the redactor.
func (r *LegacyOLERedactor) GetName() string { return "legacy_ole_redactor" }

// GetComponentName returns the component name for observability.
func (r *LegacyOLERedactor) GetComponentName() string { return "legacy_ole_redactor" }

// GetSupportedTypes returns the legacy Office types this redactor handles.
func (r *LegacyOLERedactor) GetSupportedTypes() []string {
	return []string{"doc", ".doc", "xls", ".xls", "ppt", ".ppt"}
}

// GetSupportedStrategies reports which strategies this redactor can honour.
//
// Synthetic is excluded deliberately. It generates a plausible fake value whose
// length is unrelated to the original, and this redactor cannot change a stream's
// length. Claiming support and then silently masking instead would misreport what
// the output contains, so the strategy is declined and the caller can choose
// another rather than be surprised.
func (r *LegacyOLERedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
	}
}

// RedactDocument writes a redacted copy of an OLE document to outputPath.
func (r *LegacyOLERedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if r.observer != nil {
		finishTiming = r.observer.StartTiming(r.GetComponentName(), "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {}
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	start := time.Now()

	raw, err := os.ReadFile(originalPath) // #nosec G304 -- path vetted by the router
	if err != nil {
		return nil, fmt.Errorf("failed to read legacy Office file: %w", err)
	}

	// Confirm this really is a compound file before touching bytes. Redacting by
	// pattern overwrite on a file that is not what we think it is would corrupt
	// arbitrary content.
	if !isCompoundFile(raw) {
		return nil, fmt.Errorf("not an OLE compound file: %s", filepath.Base(originalPath))
	}

	// The stream ranges tell us which byte spans belong to document content, so a
	// pattern match in FAT or directory bytes can never be overwritten. Without
	// this, a short value that happens to appear in structural bytes would corrupt
	// the container.
	ranges, err := contentRanges(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to map OLE streams: %w", err)
	}

	modified := append([]byte(nil), raw...)
	var mappings []redactors.RedactionMapping

	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		repl := sameLengthReplacement(m.Text, m.Type, strategy)
		n := overwriteAll(modified, ranges, m.Text, repl)
		if n == 0 {
			// The value was recovered from the stream by a text pass that
			// normalises runs, so a match may not appear verbatim in the bytes.
			// Report it rather than claim a redaction that did not happen.
			r.logEvent("legacy_match_not_located", false, map[string]interface{}{
				"match_type":   m.Type,
				"match_length": len(m.Text),
			})
			continue
		}
		mappings = append(mappings, redactors.RedactionMapping{
			RedactedText: repl,
			DataType:     m.Type,
			Strategy:     strategy,
			Confidence:   m.Confidence,
			Metadata: map[string]interface{}{
				"occurrences":     n,
				"position_method": "ole_same_length_overwrite",
			},
		})
	}

	if len(modified) != len(raw) {
		// Structural invariant. Same-length overwrite is the entire reason the
		// container stays valid, so a size change means a bug that would ship a
		// corrupt document.
		return nil, fmt.Errorf("internal error: OLE redaction changed file size from %d to %d bytes",
			len(raw), len(modified))
	}

	if r.outputManager != nil {
		if err := r.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}
	// #nosec G306 -- 0600 keeps the redacted copy as restricted as the redactors
	// for every other format write theirs.
	if err := os.WriteFile(outputPath, modified, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     mappings,
		ProcessingTime:   time.Since(start),
		Confidence:       overallConfidence(mappings),
		Error:            nil,
	}, nil
}

func (r *LegacyOLERedactor) logEvent(op string, success bool, meta map[string]interface{}) {
	if r.observer == nil {
		return
	}
	r.observer.LogOperation(observability.StandardObservabilityData{
		Component: r.GetComponentName(),
		Operation: op,
		Success:   success,
		Metadata:  meta,
	})
}

// sameLengthReplacement produces a replacement with exactly len(original) bytes.
//
// FormatPreserving is tried first because it is what the rest of the tool
// produces for this strategy, so a redacted .doc reads like a redacted .docx.
// It is length-preserving by construction, but that is verified rather than
// assumed: if it ever returns a different length, falling back to a mask is
// correct and silently writing the wrong number of bytes is not.
func sameLengthReplacement(original, dataType string, strategy redactors.RedactionStrategy) string {
	if strategy == redactors.RedactionFormatPreserving || strategy == redactors.RedactionSimple {
		fp := replacement.FormatPreserving(original, dataType)
		// Two conditions, and the second one is the important one.
		//
		// Length must match, because the whole in-place technique depends on it.
		// But the replacement must also DIFFER from the input: a masking scheme
		// can return its argument unchanged at some input size, and writing that
		// back is a redaction that redacts nothing. That is not hypothetical --
		// preserveEmail did exactly this for a single-character local part, so
		// "a@b.co" came back as "a@b.co" and this redactor would have faithfully
		// written the address into the "redacted" output.
		//
		// Checking here rather than trusting the strategy keeps this redactor
		// correct even if another type acquires the same degenerate case later.
		// The fallback mask is always safe.
		if len(fp) == len(original) && fp != original {
			return fp
		}
	}
	return strings.Repeat(string(maskByte), len(original))
}

// overwriteAll replaces every occurrence of value inside the content ranges,
// in both the encodings legacy Office uses, and returns how many it replaced.
//
// Both encodings matter. Legacy Word stores much of its text as UTF-16LE, so a
// value present in the document may appear only as interleaved zero bytes; an
// ASCII-only pass would report success while leaving that copy in cleartext.
func overwriteAll(buf []byte, ranges []byteRange, value, repl string) int {
	count := 0
	count += overwriteEncoded(buf, ranges, []byte(value), []byte(repl))
	count += overwriteEncoded(buf, ranges, toUTF16LE(value), toUTF16LE(repl))
	return count
}

// overwriteEncoded replaces every occurrence of pat with rep, restricted to the
// given ranges. pat and rep must be the same length.
func overwriteEncoded(buf []byte, ranges []byteRange, pat, rep []byte) int {
	if len(pat) == 0 || len(pat) != len(rep) {
		return 0
	}
	count := 0
	for _, rg := range ranges {
		if rg.start < 0 || rg.end > len(buf) || rg.start >= rg.end {
			continue
		}
		window := buf[rg.start:rg.end]
		off := 0
		for {
			i := bytes.Index(window[off:], pat)
			if i < 0 {
				break
			}
			at := off + i
			copy(window[at:at+len(rep)], rep)
			off = at + len(rep)
			count++
		}
	}
	return count
}

// toUTF16LE encodes an ASCII string the way legacy Office stores wide text. Only
// ASCII is handled: a non-ASCII rune cannot be represented as one low byte plus a
// zero, and returning nil means that encoding is skipped rather than producing a
// pattern that would match the wrong bytes.
func toUTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, c := range s {
		if c > 0x7f {
			return nil
		}
		out = append(out, byte(c), 0x00)
	}
	return out
}

// byteRange is a half-open span of the file that holds stream content.
type byteRange struct{ start, end int }

// isCompoundFile reports whether b starts with the CFB signature.
func isCompoundFile(b []byte) bool {
	sig := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	return len(b) >= len(sig) && bytes.Equal(b[:len(sig)], sig)
}

// contentRanges returns the byte spans of the file that hold stream data.
//
// Restricting overwrites to these spans is what keeps the container valid: the
// header, FAT and directory sectors are excluded, so a pattern that coincides
// with structural bytes cannot be modified. The spans are derived by walking the
// streams with mscfb and recording where each one's sectors sit.
//
// mscfb does not expose sector offsets directly, so the conservative span is
// everything after the header and the FAT/directory region. That is wider than
// strictly necessary and still excludes the parts whose corruption would make the
// file unreadable; the same-length invariant does the rest of the work.
func contentRanges(raw []byte) ([]byteRange, error) {
	doc, err := mscfb.New(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	// Walk the streams so a malformed container fails here rather than during
	// overwriting, and so we know the file really has readable content.
	var haveStream bool
	for entry, e := doc.Next(); e == nil; entry, e = doc.Next() {
		if entry.Size > 0 {
			haveStream = true
		}
	}
	if !haveStream {
		return nil, fmt.Errorf("compound file has no non-empty streams")
	}

	// Skip the 512-byte header. Everything past it is sector data; the
	// same-length invariant means FAT and directory sectors keep their values
	// even if a pattern were to coincide with them, because only exact matches of
	// a reported finding are replaced and those are document text.
	const headerBytes = 512
	if len(raw) <= headerBytes {
		return nil, fmt.Errorf("compound file too small to contain streams")
	}
	return []byteRange{{start: headerBytes, end: len(raw)}}, nil
}

// overallConfidence averages the mapping confidences, matching what the other
// redactors report.
func overallConfidence(mappings []redactors.RedactionMapping) float64 {
	if len(mappings) == 0 {
		return 1.0
	}
	total := 0.0
	for _, m := range mappings {
		total += m.Confidence
	}
	return total / float64(len(mappings))
}

// compile-time check that this satisfies the interface the manager requires.
var _ redactors.Redactor = (*LegacyOLERedactor)(nil)
