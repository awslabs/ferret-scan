// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package rtf redacts reported values out of a Rich Text Format document while leaving it
// a document.
//
// It exists for exactly the reason internal/redactors/svg does, and the failure was measured
// the same way. RTF extraction is LOSSY BY DESIGN — the preprocessor emits only character
// data from document destinations (see text-extract-rtftextlib), which is what keeps control
// words, font tables and embedded image hex away from the validators. The plaintext
// redactor's RedactContent writes the EXTRACTED text, and the worker pool prefers
// RedactContent over RedactDocument whenever a redactor offers it. For a .txt those are the
// same bytes; for an .rtf they are not.
//
// Measured on a 115-byte RTF carrying an SSN and an email, before this package existed:
//
//	original:  {\rtf1\ansi\deff0 {\fonttbl{\f0 Helvetica;}} \f0\fs24 Employee SSN: ...
//	"redacted" output:  Employee SSN: [SSN-REDACTED]\nEmail: [EMAIL-REDACTED]
//
// Both values were gone and so was the document: no {\rtf header, no font table, no control
// words. `textutil -convert txt` — the tool that produced the file — read **0 bytes** of text
// back out of it, where it read 54 from the same file redacted by the older path. An operator
// who redacts a directory of RTFs would have silently converted every one to plain text.
//
// So this redactor deliberately does NOT implement RedactContent. It reuses the plaintext
// redactor's RedactDocument, which reads the ORIGINAL file, locates each reported value in
// those bytes and substitutes in place, leaving the markup intact.
//
// # The RTF-specific hazard, and why it is a loud failure rather than a silent one
//
// The whole point of the RTF extractor is that a producer SPLITS a value across formatting
// runs: macOS textutil writes `452-11-9384` as
//
//	452-11-\f1\b 9384
//
// The extractor reassembles it, so the value is reported — which is the leak that
// text-extract-rtftextlib closes. But the reassembled value then occurs NOWHERE in the file,
// so a byte substitution finds nothing and would leave it in cleartext while reporting
// success. That is the same class as the SVG numeric-character-reference case, and it gets
// the same answer: a residue check at the sink, run against the DECODED rendering as well as
// the raw bytes, and a refusal to write a file that still holds a reported value.
//
// A loud failure is the honest end state, not a shrug. The scan reported the finding either
// way, so the operator knows the value is there; what must not happen is a file they will
// read as redacted that still contains it. Redacting split values in place needs a byte-span
// map from the extractor's output back to the source, which is tracked separately.
package rtf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	rtfextract "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-rtftextlib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// RTFRedactor rewrites the reported values inside an RTF's markup.
type RTFRedactor struct {
	// inner does the substitution. Composed rather than reimplemented for the same reason
	// the SVG redactor composes it: there is one redactText in this codebase and it carries
	// the cluster expansion, overlap resolution and bounded-text restoration that three
	// separate bugs added to it. A second copy would be a second place for those to be
	// missing.
	inner    *plaintext.PlainTextRedactor
	observer observability.Observer
}

// NewRTFRedactor creates an RTF redactor.
func NewRTFRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *RTFRedactor {
	return &RTFRedactor{
		inner:    plaintext.NewPlainTextRedactor(outputManager, observer),
		observer: observer,
	}
}

// GetName returns the name of the redactor.
func (r *RTFRedactor) GetName() string { return "rtf_redactor" }

// GetComponentName returns the component name for observability.
func (r *RTFRedactor) GetComponentName() string { return "rtf_redactor" }

// GetSupportedTypes returns the file types this redactor can handle.
//
// .rtf only. .rtfd is a BUNDLE (a directory containing TXT.rtf plus its media), not a file,
// so it never reaches a file redactor and claiming it would promise a redaction that cannot
// happen here.
func (r *RTFRedactor) GetSupportedTypes() []string { return []string{".rtf"} }

// GetSupportedStrategies returns the redaction strategies this redactor supports.
//
// All three, because all three are the inner redactor's and the substitution is
// strategy-agnostic: none of them touches anything but the located span.
func (r *RTFRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument writes a redacted copy of the RTF at outputPath.
func (r *RTFRedactor) RedactDocument(originalPath string, outputPath string,
	matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {

	result, err := r.inner.RedactDocument(originalPath, outputPath, matches, strategy)
	if err != nil {
		return nil, err
	}
	if result == nil || !result.Success {
		return result, fmt.Errorf("rtf redaction of %s did not succeed", filepath.Base(originalPath))
	}

	// VERIFY THE SINK. A redactor reporting success with a populated RedactionMap is the same
	// evidence that has been wrong before in this codebase, so the only claim worth making is
	// that the value is no longer in the bytes that were written.
	written := result.RedactedFilePath
	if written == "" {
		written = outputPath
	}
	out, readErr := os.ReadFile(filepath.Clean(written)) // #nosec G304 -- path from the output manager
	if readErr != nil {
		return nil, fmt.Errorf("reading back redacted RTF %s: %w", filepath.Base(outputPath), readErr)
	}
	if residue := residueTypes(out, matches); len(residue) > 0 {
		// Remove the output. Leaving a file an operator will read as redacted is worse than
		// leaving no file: the scan reported the finding either way, so the honest end state
		// is a loud failure, and the worker pool records a RedactionError without dropping
		// the findings.
		_ = os.Remove(written)
		return nil, fmt.Errorf("redacted RTF %s still holds reported value(s) of type %s; refusing to write it",
			filepath.Base(outputPath), strings.Join(residue, ", "))
	}

	// A document that was RTF before and is not RTF now was broken by the replacement. Refused
	// for the same reason as residue: an output no reader will open is data loss wearing a
	// success. Every strategy shipped today emits alphanumerics and brackets, so this cannot
	// fire on them — it is the guard for the strategy someone adds later, and for the
	// RedactContent regression this package exists to prevent, which would fail it outright.
	if !looksLikeRTF(out) {
		_ = os.Remove(written)
		return nil, fmt.Errorf("redacting %s produced bytes that are no longer RTF; refusing to write it",
			filepath.Base(outputPath))
	}

	return result, nil
}

// looksLikeRTF checks the signature the specification requires, tolerating a UTF-8 BOM.
//
// Deliberately the same shallow check the extractor makes rather than a full parse: the
// question is "is this still the same class of document", and the signature is what every
// RTF reader dispatches on.
func looksLikeRTF(data []byte) bool {
	const sig = `{\rtf`
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return len(data) >= len(sig) && strings.HasPrefix(string(data), sig)
}

// residueTypes returns the TYPES whose value survives in out, deduplicated and in
// first-seen order.
//
// Searched in TWO renderings, and the second is the one that matters here: the raw bytes
// catch a value written literally, and the DECODED rendering — the extractor's own output —
// catches a value the file spells across a control word or in \'hh escapes. Checking only
// the raw bytes is how a split value would ship as a redacted SSN, since `452-11-\f1\b 9384`
// contains the reported `452-11-9384` nowhere.
//
// The TYPE is returned, never the value: this string reaches the operator through the
// redaction-error channel, and naming the value there would republish exactly what the run
// exists to remove (BSC4).
func residueTypes(out []byte, matches []detector.Match) []string {
	raw := string(out)

	// Best-effort: if the redacted bytes no longer parse, the caller's signature gate below
	// reports that separately and an empty decoding here just means the raw check stands.
	decoded := ""
	if tc, err := rtfextract.ExtractFromBytes("redacted.rtf", out); err == nil && tc != nil {
		decoded = tc.Text
	}

	seen := map[string]bool{}
	var types []string
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		if strings.Contains(raw, m.Text) || (decoded != "" && strings.Contains(decoded, m.Text)) {
			if !seen[m.Type] {
				seen[m.Type] = true
				types = append(types, m.Type)
			}
		}
	}
	return types
}
