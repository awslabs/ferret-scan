// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package svg redacts reported values out of an SVG drawing while leaving the drawing
// a drawing.
//
// It exists because SVG extraction is LOSSY BY DESIGN. The preprocessor collects only
// prose-bearing nodes (see text-extract-svgtextlib), which is what keeps path geometry
// away from the validators — and the plaintext redactor's RedactContent writes the
// EXTRACTED text, which the worker pool prefers over RedactDocument whenever a redactor
// offers it. For a .txt those are the same bytes. For an .svg they are not: measured on
// a 479-byte drawing carrying an SSN, an email, a name and a phone, routing it to the
// plaintext redactor produced an output holding five lines of prose, no <svg> element
// and no geometry. Every value was gone and so was the file.
//
// So this redactor deliberately does NOT implement RedactContent. It reuses the
// plaintext redactor's RedactDocument, which reads the ORIGINAL file, locates each
// reported value in those bytes and substitutes in place — the XML structure, the
// geometry and every attribute survive untouched.
//
// Two things it adds on top:
//
//  1. XML-ESCAPED SPELLINGS. A value stored in XML character data is escaped, so a
//     Match whose text contains & < > " or ' does not occur literally in the file. The
//     substitution would find nothing and the value would survive in cleartext with the
//     run reporting success — the same leak class as the OOXML one.
//
//  2. A RESIDUE CHECK AT THE SINK, run in BOTH the raw bytes and the DECODED
//     rendering. The decoded half is what catches the general escape: a value written
//     with numeric character references (452-11-93&#56;4) is reported at HIGH 100
//     because the extractor decodes it, occurs literally nowhere in the file, and so
//     survives any byte substitution. Before this check that shipped as a redacted
//     copy at exit 0 -- detected, "redacted", still there. It is now a loud failure,
//     which is #311's stated policy and the honest end state when the value cannot be
//     removed. (The same class exists in the OOXML redactor and is NOT fixed here.)
//
//  3. A WELL-FORMEDNESS GATE. If the input parsed and the output does not, the
//     redaction broke the drawing, so it is refused. A replacement is chosen by the
//     strategy, and a strategy is free to emit any bytes; a redacted file that no SVG
//     renderer will open is a different kind of data loss, not a success.
package svg

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// SVGRedactor rewrites the reported values inside an SVG's markup.
type SVGRedactor struct {
	// inner does the substitution. Composed rather than reimplemented: there is one
	// redactText in this codebase and it carries the cluster expansion, the overlap
	// resolution and the bounded-text restoration that three separate bugs added to
	// it. A second copy would be a second place for those to be missing.
	inner    *plaintext.PlainTextRedactor
	observer observability.Observer
}

// NewSVGRedactor creates an SVG redactor.
func NewSVGRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *SVGRedactor {
	return &SVGRedactor{
		inner:    plaintext.NewPlainTextRedactor(outputManager, observer),
		observer: observer,
	}
}

// GetName returns the name of the redactor.
func (r *SVGRedactor) GetName() string { return "svg_redactor" }

// GetComponentName returns the component name for observability.
func (r *SVGRedactor) GetComponentName() string { return "svg_redactor" }

// GetSupportedTypes returns the file types this redactor can handle.
//
// .svg only. .emf, .wmf and .wdp are the other vector-ish types this tool sees and
// none of them is XML — they are binary metafiles with no text extractor, so nothing
// reports a value in them and there is nothing here to remove. Claiming them would
// promise a redaction that could not happen. See embedded.SkipTextPipeline.
func (r *SVGRedactor) GetSupportedTypes() []string { return []string{".svg"} }

// GetSupportedStrategies returns the redaction strategies this redactor supports.
//
// All three, because all three are the inner redactor's and the substitution is
// strategy-agnostic: simple writes a [TYPE-REDACTED] token, format_preserving keeps the
// value's shape, synthetic writes a fresh fake value. None of them can change the
// document's structure, because none of them touches anything but the located span.
func (r *SVGRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument writes a redacted copy of the SVG at outputPath.
func (r *SVGRedactor) RedactDocument(originalPath string, outputPath string,
	matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {

	// Rewrite any match whose literal does not occur in the file to the spelling that
	// does. Done BEFORE the substitution, because the inner redactor locates a match by
	// searching for Match.Text and verifies the located span equals it exactly — an
	// escaped value fails both and is skipped, silently.
	raw, err := os.ReadFile(filepath.Clean(originalPath)) // #nosec G304 -- path already vetted by the router
	if err != nil {
		return nil, fmt.Errorf("reading SVG %s: %w", filepath.Base(originalPath), err)
	}
	// Recorded BEFORE redaction. A malformed source SVG is still redactable -- the
	// extractor reads one best-effort -- so the gate below can only fire when the
	// replacement is what broke the markup.
	inputWellFormed := wellFormed(raw)

	prepared := escapedForFile(raw, matches)

	result, err := r.inner.RedactDocument(originalPath, outputPath, prepared, strategy)
	if err != nil {
		return nil, err
	}
	if result == nil || !result.Success {
		return result, fmt.Errorf("svg redaction of %s did not succeed", filepath.Base(originalPath))
	}

	// VERIFY THE SINK. A redactor reporting success with a populated RedactionMap is
	// the same evidence that has been wrong before in this codebase, so the only claim
	// worth making is that the value is no longer in the bytes that were written.
	written := result.RedactedFilePath
	if written == "" {
		written = outputPath
	}
	out, readErr := os.ReadFile(filepath.Clean(written)) // #nosec G304 -- path from the output manager
	if readErr != nil {
		return nil, fmt.Errorf("reading back redacted SVG %s: %w", filepath.Base(outputPath), readErr)
	}
	if residue := residueTypes(out, matches); len(residue) > 0 {
		// Remove the output. Leaving a file that an operator will read as redacted is
		// worse than leaving no file: the scan reported the finding either way, so the
		// honest end state is a loud failure, and the worker pool records a
		// RedactionError without dropping the findings.
		_ = os.Remove(written)
		return nil, fmt.Errorf("redacted SVG %s still holds reported value(s) of type %s; refusing to write it",
			filepath.Base(outputPath), strings.Join(residue, ", "))
	}

	// A drawing that parsed before and does not parse now was broken by the
	// replacement, not by its author. Refused for the same reason as residue: an output
	// no renderer will open is data loss wearing a success. Every strategy shipped today
	// emits alphanumerics and brackets, so this cannot fire on them -- it is the guard
	// for the strategy someone adds later.
	if inputWellFormed && !wellFormed(out) {
		_ = os.Remove(written)
		return nil, fmt.Errorf("redacting %s produced markup that no longer parses as XML; refusing to write it",
			filepath.Base(outputPath))
	}

	return result, nil
}

// wellFormed reports whether data parses as XML end to end, in STRICT mode.
//
// Strict deliberately, unlike the extractor: the question here is not "can we read
// something out of this" but "is this still the same class of document it was", and the
// answer has to be able to come back false or the gate is decoration.
func wellFormed(data []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		if _, err := dec.Token(); err != nil {
			return errors.Is(err, io.EOF)
		}
	}
}

// decodedRendering returns the text a reader (and a validator) sees: every character
// datum and every attribute value, with character references resolved.
//
// This is what makes the residue check general. XMLEscapeVariants covers the five
// predefined entities; a numeric character reference is unbounded in form
// (452-11-93&#56;4, &#x38;, &#0056;) and cannot be enumerated, so residue is looked for
// in the DECODED text instead of guessing spellings of it.
func decodedRendering(data []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	dec.AutoClose = xml.HTMLAutoClose
	dec.Entity = xml.HTMLEntity

	var b strings.Builder
	b.Grow(len(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			// Partial is the right answer on a parse failure: whatever was decoded is
			// still a place a value can be hiding, and the caller also searches the raw
			// bytes, so nothing is lost by stopping here.
			break
		}
		switch t := tok.(type) {
		case xml.CharData:
			b.Write(t)
			b.WriteByte('\n')
		case xml.StartElement:
			for _, a := range t.Attr {
				b.WriteString(a.Value)
				b.WriteByte('\n')
			}
		case xml.Comment:
			b.Write(t)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// escapedForFile returns matches with each value spelled the way the FILE spells it.
//
// A match is rewritten only when its literal is absent from the file AND an escaped
// spelling is present, so a value that occurs literally is never disturbed. A match
// whose value occurs in NEITHER form is left alone: the inner redactor's own
// not-found handling records it, and the residue check below cannot see a value that
// is not there, so nothing leaks by leaving it.
func escapedForFile(raw []byte, matches []detector.Match) []detector.Match {
	text := string(raw)

	out := make([]detector.Match, len(matches))
	copy(out, matches)
	for i := range out {
		if out[i].Text == "" || strings.Contains(text, out[i].Text) {
			continue
		}
		for _, v := range embedded.XMLEscapeVariants(out[i].Text) {
			if v != out[i].Text && strings.Contains(text, v) {
				out[i].Text = v
				break
			}
		}
	}
	return out
}

// residueTypes returns the TYPES whose value survives in out, deduplicated and in
// first-seen order.
//
// Searched in TWO renderings: the raw bytes, which catch a value written literally, and
// the decoded rendering, which catches every escaped spelling including numeric
// character references. Checking only the raw bytes is how "452-11-93&#56;4" shipped as
// a redacted SSN.
//
// The TYPE is returned, never the value: this string reaches the operator through the
// redaction-error channel, and naming the value there would republish exactly what the
// run exists to remove (BSC4).
func residueTypes(out []byte, matches []detector.Match) []string {
	raw := string(out)
	decoded := decodedRendering(out)
	seen := map[string]bool{}
	var types []string
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		found := strings.Contains(decoded, m.Text)
		if !found {
			for _, v := range embedded.XMLEscapeVariants(m.Text) {
				if strings.Contains(raw, v) {
					found = true
					break
				}
			}
		}
		if found && !seen[m.Type] {
			seen[m.Type] = true
			types = append(types, m.Type)
		}
	}
	return types
}
