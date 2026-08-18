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
	"unicode/utf16"

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

	// Map every stream's LOGICAL bytes onto the file, so redaction searches the same
	// reassembled bytes the extractor read. A stream is a chain of sectors that need
	// not be adjacent, so a value can be contiguous in the stream and split across
	// distant sectors on disk — see streammap.go.
	layout, err := parseCFBLayout(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to map OLE streams: %w", err)
	}

	modified := append([]byte(nil), raw...)
	var mappings []redactors.RedactionMapping

	// The logical bytes of each stream, read once. Values are searched here and
	// written back through the chain, and the cache is updated after each write so a
	// later match cannot be found in bytes an earlier one already masked.
	logical := make([][]byte, len(layout.streams))
	for i, s := range layout.streams {
		logical[i] = s.readLogical(modified)
	}

	// Normalize the match set before searching the streams for it. BOTH of these rewrite
	// matches whose Text does not occur in the document, and this redactor locates a value
	// by searching for m.Text in each CFB stream's logical bytes — so an un-normalized
	// match silently masks nothing.
	//
	// A consolidated cluster's Text is a rendered summary present in no stream
	// (ExpandClusterMatches, #289). A bounded consolidated text — the
	// INTELLECTUAL_PROPERTY "... [+N more matches on line]" display form — is likewise
	// absent, and RestoreBoundedMatchText was NEVER called here at all: this redactor got
	// the cluster expansion without its sibling, so a bounded legal-notice consolidation in
	// a legacy .doc was located by nothing and the whole line survived.
	//
	// Order matters and matches the other paths: expand first, then restore, then let the
	// caller's overlap resolution run over the result.
	matches = redactors.ExpandClusterMatches(matches)
	matches = redactors.RestoreBoundedMatchText(matches)

	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		repl := sameLengthReplacement(m.Text, m.Type, strategy)
		n := 0
		for i, s := range layout.streams {
			n += overwriteInStream(modified, s, logical[i], m.Text, repl)
		}
		if n == 0 {
			// The extractor recovers body text through a pass that normalises runs,
			// so a reported match need not appear verbatim in any stream. Say so
			// rather than claim a redaction that did not happen.
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
				"position_method": "ole_logical_stream_overwrite",
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

// overwriteInStream replaces every occurrence of value inside one stream's LOGICAL
// bytes, writing each replacement back through the stream's sector chain, and
// returns how many it replaced.
//
// Both encodings are searched, and each needs a replacement of its own byte width:
// "José" is 5 bytes as UTF-8 but 8 as UTF-16LE. The logical slice is updated in
// step with the file so a later match cannot be found in bytes already masked.
func overwriteInStream(raw []byte, s streamExtent, logical []byte, value, repl string) int {
	count := 0

	narrow := []byte(value)
	narrowRepl := []byte(repl)
	if len(narrow) > 0 && len(narrow) == len(narrowRepl) {
		count += replaceLogical(raw, s, logical, narrow, narrowRepl)
	}

	wide := toUTF16LE(value)
	if len(wide) == 0 {
		return count
	}
	wideRepl := toUTF16LE(repl)
	if len(wideRepl) != len(wide) {
		// A same-length overwrite is what keeps every sector offset valid, so when
		// the format-preserving replacement does not encode to the same width a mask
		// of the correct width is used instead.
		wideRepl = bytes.Repeat([]byte{maskByte, 0x00}, len(wide)/2)
	}
	count += replaceLogical(raw, s, logical, wide, wideRepl)

	return count
}

// replaceLogical finds every occurrence of pat in a stream's logical bytes and
// writes rep back through the sector chain.
func replaceLogical(raw []byte, s streamExtent, logical, pat, rep []byte) int {
	if len(pat) == 0 || len(pat) != len(rep) {
		return 0
	}
	count := 0
	off := 0
	for off <= len(logical)-len(pat) {
		i := bytes.Index(logical[off:], pat)
		if i < 0 {
			break
		}
		at := off + i
		if !s.writeLogical(raw, at, rep) {
			// Unwritable (a truncated or inconsistent chain). Skip past it rather
			// than spin, and leave the count alone so the caller does not report a
			// redaction that did not happen.
			off = at + 1
			continue
		}
		// Keep the logical view in step with the file.
		copy(logical[at:at+len(rep)], rep)
		off = at + len(rep)
		count++
	}
	return count
}

// toUTF16LE encodes a string the way legacy Office stores wide text: UTF-16
// little-endian, with surrogate pairs for anything outside the BMP.
//
// This used to bail out and return nil for any non-ASCII rune, which was a
// cleartext leak rather than a limitation. Legacy Word stores property values and
// much of its body text as UTF-16LE, so for a name like "José Ramírez" the
// redactor's ASCII pass searched the UTF-8 bytes (absent from the file) and the
// wide pass was skipped entirely — overwriteAll found nothing, and RedactDocument
// reported Success with zero mappings while the name stayed in the output. Any
// non-ASCII author, company or body value was affected, which is most of the world's
// names.
//
// The encoding must be exact rather than approximate: a wrong pattern would either
// miss the value (a leak) or match unrelated bytes (corruption). utf16.Encode
// handles the surrogate cases that hand-rolling gets wrong.
func toUTF16LE(s string) []byte {
	if s == "" {
		return nil
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// isCompoundFile reports whether b starts with the CFB signature.
func isCompoundFile(b []byte) bool {
	sig := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	return len(b) >= len(sig) && bytes.Equal(b[:len(sig)], sig)
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
