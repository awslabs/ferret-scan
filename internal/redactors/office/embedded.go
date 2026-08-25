// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/xmlref"
)

// embeddedChild is a file found inside this document, held for redaction in its
// own right.
type embeddedChild struct {
	// name is the archive entry name. Producer-controlled; used to pick a redactor
	// by allowlisted extension and to name the part in disclosure text, never as a
	// filesystem path.
	name string
	// content is the part's decompressed bytes, already bounded by the caller's
	// per-entry and cumulative decompression caps.
	content []byte
}

// unredactedPart records an embedded part that still holds a reported value after
// redaction ran.
//
// This type exists because the alternative is silence, and silence here is the
// whole bug: the container's own redactions succeed, a file appears in the output
// directory, the exit code is 0, and a value the scanner reported is still in it.
type unredactedPart struct {
	name   string
	reason string
}

func (u unredactedPart) String() string {
	return fmt.Sprintf("%s (%s)", u.name, u.reason)
}

// redactEmbeddedParts redacts every embedded file and stores the results back at
// their original entry names.
//
// Returns the mappings to merge into the container's audit trail, and the parts
// that could not be redacted. The caller decides what to do with the second list;
// it must not be dropped.
func (or *OfficeRedactor) redactEmbeddedParts(
	parentPath string,
	contents *OfficeZipContents,
	children []embeddedChild,
	matches []detector.Match,
	strategy redactors.RedactionStrategy,
) ([]redactors.RedactionMapping, []unredactedPart) {
	if len(children) == 0 || len(matches) == 0 {
		// No children, or nothing reported to remove. With nothing to redact there is
		// nothing to leak, and dispatching every embedded image in a clean document
		// would be pure cost on the slowest stage of a scan.
		return nil, nil
	}

	// The value set, built ONCE for the whole document rather than per child.
	//
	// Includes each value's XML-escaped spelling, because a value stored in an OOXML
	// part is escaped and the raw literal from a Match need not occur in the bytes.
	values := embeddedValueSet(matches)
	if len(values) == 0 {
		return nil, nil
	}

	var merged []redactors.RedactionMapping
	var unredacted []unredactedPart
	dispatched := 0

	for _, child := range children {
		// SKIP A PART ONLY WHEN IT CAN BE PROVEN TO HOLD NOTHING.
		//
		// This gate is the difference between redacting an embedded value and
		// vandalizing the document around it. Every redactor here is lossy in some
		// way -- the image redactor DECODES and re-encodes, and strips all metadata --
		// so dispatching a part that holds none of the reported values silently
		// degrades content that was never implicated. Measured before this gate: a
		// document whose BODY held an SSN and which also carried an unrelated 706-byte
		// photo came back with that photo re-encoded to 664 bytes, a different hash,
		// and its caption removed. Nothing in the photo had ever been reported.
		//
		// The polarity matters and is asymmetric. For an INSPECTABLE format the byte
		// scan is a sound test for absence -- EXIF, OLE streams and audio tags are
		// stored in the clear, and the scan inflates archive members -- so "nothing
		// found" means "leave it alone". For an OPAQUE format it is not: PDF text lives
		// in FlateDecode streams, so nothing found means only that we cannot see. Such
		// a part is therefore ALWAYS dispatched, and if no redactor can rewrite it the
		// container is refused rather than written. Scanning it is still worth it --
		// the finding gets reported either way -- and failing loudly is the honest end
		// state when the value cannot be removed.
		if embedded.ResidueInspectable(child.name) && !partHoldsValue(child.content, values, 0) {
			continue
		}

		// Bound the work. A container with tens of thousands of embedded entries that
		// all hold a value would otherwise be an unbounded number of full
		// extract-redact-repackage cycles.
		if dispatched >= embedded.MaxDispatchedParts {
			unredacted = append(unredacted, unredactedPart{
				name: child.name,
				reason: fmt.Sprintf("more than %d embedded parts hold reported values; "+
					"traversal stopped", embedded.MaxDispatchedParts),
			})
			continue
		}
		dispatched++

		if or.embeddedRedactor == nil {
			// nil is a supported state -- the redactor is usable standalone -- but it
			// must not quietly mean "this document has no embedded content". The part
			// demonstrably holds a reported value, so say so.
			unredacted = append(unredacted, unredactedPart{
				name:   child.name,
				reason: "no embedded-redaction dispatcher configured",
			})
			continue
		}

		res, err := or.embeddedRedactor.RedactEmbedded(redactors.EmbeddedRedactionRequest{
			ParentPath: parentPath,
			PartName:   child.name,
			Content:    child.content,
			Matches:    matches,
			Strategy:   strategy,
		})
		if err != nil {
			// The part holds a reported value and could not be rewritten. That is a
			// leak if the container is written, so it is reported unconditionally --
			// no residue re-test, because the residue test is what got us here.
			unredacted = append(unredacted, unredactedPart{
				name:   child.name,
				reason: describeEmbeddedFailure(err),
			})
			continue
		}

		// Verify the sink instead of trusting the report.
		//
		// A redactor returning Success with a RedactionMap is the same evidence that
		// has been wrong before in this codebase: a count of 1 has been reported on an
		// output byte-identical to its input. The only claim worth making is that the
		// value is no longer there, so check the bytes that will actually be written.
		if residue := valuesPresentIn(res.Content, values, 0, false); len(residue) > 0 {
			unredacted = append(unredacted, unredactedPart{
				name: child.name,
				reason: fmt.Sprintf("%d reported value(s) still present after redaction",
					len(residue)),
			})
			continue
		}

		// Store the redacted bytes back at the same entry name, so the container's
		// repackager ships them with no special handling and the archive keeps its
		// original entry order.
		contents.addFile(child.name, res.Content)

		for _, m := range res.RedactionMap {
			if m.Metadata == nil {
				m.Metadata = map[string]interface{}{}
			}
			// Re-label so the audit trail says WHERE inside the container the redaction
			// happened; without it a nested redaction is indistinguishable from one in
			// the container's own body.
			m.Metadata["embedded_part"] = child.name
			m.Metadata["embedded_in"] = filepath.Base(parentPath)
			merged = append(merged, m)
		}
	}

	return merged, unredacted
}

// embeddedValueSet collapses the match list into the distinct byte strings a residue
// scan should look for, including XML-escaped spellings.
//
// Values shorter than minResidueValueLen are dropped: they would produce meaningless
// hits in binary data, and redaction only ever searches for the literal value, so
// such a value is not something a redactor could have targeted either.
func embeddedValueSet(matches []detector.Match) [][]byte {
	seen := make(map[string]struct{}, len(matches)*2)
	var out [][]byte
	for _, m := range matches {
		if len(m.Text) < minResidueValueLen {
			continue
		}
		for _, v := range embedded.XMLEscapeVariants(m.Text) {
			if len(v) < minResidueValueLen {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, []byte(v))
		}
	}
	return out
}

// minResidueValueLen is the shortest value worth searching for in arbitrary bytes.
const minResidueValueLen = 4

// describeEmbeddedFailure turns a dispatch error into a short operator-facing
// reason.
//
// It must never carry document content. The underlying errors are structural
// ("no redactor handles this embedded file type", "PDF redaction is not
// implemented"), which is safe and is the actionable part, so they are passed
// through; the sentinels are named explicitly so the two coverage gaps read
// differently from a transient failure.
func describeEmbeddedFailure(err error) string {
	switch {
	case errors.Is(err, embedded.ErrTooDeep):
		return fmt.Sprintf("nesting deeper than %d levels was not examined", embedded.MaxDepth)
	case errors.Is(err, redactors.ErrNoEmbeddedRedactor):
		return "no redactor handles this file type"
	default:
		return err.Error()
	}
}

// maxResidueDepth bounds the recursive residue scan.
//
// One deeper than embedded.MaxDepth on purpose: the scan's job is to VERIFY the
// bound was respected, so it has to be able to look at the level the redactor
// refused to descend into. A scan capped at the same depth as the redactor could
// never see the value the redactor admitted it did not reach.
const maxResidueDepth = embedded.MaxDepth + 1

// maxResidueScanBytes bounds how much a single residue scan will inflate.
//
// The scan decompresses archive members, so without a bound the oracle that exists
// to detect a bomb would itself be one. Mirrors the container redactor's cumulative
// cap.
const maxResidueScanBytes = 200 * 1024 * 1024

// partHoldsValue reports whether any reported value occurs in a part's bytes.
//
// Descends into a zip so a deflated member is checked DECOMPRESSED. That is not
// optional: grepping a .docx searches compressed bytes and finds nothing, which is
// indistinguishable from a clean file and is the single most common way a leak in
// this area gets certified as fixed.
func partHoldsValue(content []byte, values [][]byte, depth int) bool {
	return len(valuesPresentIn(content, values, depth, true)) > 0
}

// valuesPresentIn returns the values occurring in content, descending into nested
// zip members.
//
// stopAtFirst short-circuits for the boolean caller. The two callers want different
// answers -- "is there anything here?" versus "exactly what survived?" -- and sharing
// the traversal keeps them from disagreeing about what counts as present.
func valuesPresentIn(content []byte, values [][]byte, depth int, stopAtFirst bool) []string {
	budget := int64(maxResidueScanBytes)
	return scanForValues(content, values, depth, stopAtFirst, &budget)
}

func scanForValues(content []byte, values [][]byte, depth int, stopAtFirst bool, budget *int64) []string {
	if depth > maxResidueDepth || *budget <= 0 {
		return nil
	}

	var found []string
	seen := make(map[string]struct{}, len(values))

	// The part's bytes as they are, plus -- only when they could hold an XML character
	// reference -- the same bytes with references resolved.
	//
	// Without the second view this scan is BLIND to a value the part spells differently
	// from the way it was reported, and because the caller uses "nothing found" as
	// permission to SKIP the part, that blindness is a leak rather than a missed
	// optimisation. Measured on a .docx carrying word/embeddings/inner.docx whose
	// document.xml held `Patient SSN 449-87-410&#48;`: reported as one SSN finding, then
	// skipped here, and the value came back out of the "redacted" file via ElementTree at
	// exit 0 with no warning. The same value spelled plainly, and the same escaped value at
	// TOP level, both redacted correctly -- so the redactor was always capable and this gate
	// was the whole defect (#475).
	//
	// Decoding rather than enumerating spellings, for the reason internal/xmlref documents:
	// '&' introduces character references, so any character at any offset can be respelled
	// in decimal or hex with arbitrary leading zeros, and the spellings are combinatorial.
	// embedded.XMLEscapeVariants still contributes the five predefined entities to the value
	// set, which covers the opposite direction -- a value REPORTED in its escaped form.
	//
	// Cost: one decode per part, not per value, so the work stays linear in part size. The
	// length test is what keeps a part with no reference from being scanned twice, and
	// xmlref.Decode returns its input unchanged, without copying, when there is no '&' at
	// all -- which is the overwhelming majority of embedded parts, since most are binary.
	// Any successful decode strictly shortens the buffer, a reference being at least four
	// bytes, so a length change is a sound test for "something was resolved".
	views := [][]byte{content}
	if decoded := xmlref.Decode(content); len(decoded) != len(content) {
		views = append(views, decoded)
	}

	for _, v := range values {
		if _, dup := seen[string(v)]; dup {
			continue
		}
		for _, view := range views {
			if bytes.Contains(view, v) {
				seen[string(v)] = struct{}{}
				found = append(found, string(v))
				break
			}
		}
		if stopAtFirst && len(found) > 0 {
			return found
		}
	}

	// Only descend if the bytes are a zip; anything else is already searched above.
	if !bytes.HasPrefix(content, []byte("PK")) {
		return found
	}
	reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return found
	}
	for _, f := range reader.File {
		if f.UncompressedSize64 > maxOfficeEntryBytes {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		inner, err := io.ReadAll(io.LimitReader(rc, maxOfficeEntryBytes))
		_ = rc.Close()
		if err != nil {
			continue
		}
		*budget -= int64(len(inner))
		if *budget <= 0 {
			return found
		}
		for _, s := range scanForValues(inner, values, depth+1, stopAtFirst, budget) {
			if _, dup := seen[s]; dup {
				continue
			}
			seen[s] = struct{}{}
			found = append(found, s)
			if stopAtFirst {
				return found
			}
		}
	}
	return found
}

// embeddedFailureSummary renders the unredacted parts as one operator-facing line.
func embeddedFailureSummary(parts []unredactedPart) string {
	names := make([]string, 0, len(parts))
	for _, p := range parts {
		names = append(names, p.String())
	}
	return strings.Join(names, "; ")
}
