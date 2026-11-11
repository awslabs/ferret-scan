// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	textextractofficetextlib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-officetextlib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The scanner's view of the copy (#914).
//
// Every check this redactor makes reads the parts through a view of its own: one character-data token at
// a time, tokens joined with nothing, or tokens joined with a newline. The SCANNER joins them differently,
// and per format: a slide's runs and an OpenDocument paragraph or cell with a space, a sheet's cells with
// a tab. A value it reported across one of those joins was therefore in none of the redactor's views, so
// nothing rewrote it and nothing refused it. Measured on main @ 2fb4719 over the public corpus: 65
// reported values left in their redacted copies across one .xlsx, one .pptx, one .pptm and one .ods, every
// copy written at exit 0 with an empty stderr and nothing in stats.files_not_redacted.
//
// So the copy is read back through the scanner's own Office reader before it is written, and a reported
// value that reader still finds refuses the write. A model of the reader would drift from it; this calls
// the reader.

// storedPackage serialises contents into an in-memory zip, entries STORED (uncompressed) in package
// order, and opens it for reading. Storing rather than deflating keeps the cost to one copy: the only
// consumer is the reader below, and the copy that is written is packaged separately.
func storedPackage(contents *OfficeZipContents) (*zip.Reader, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range contents.orderedNames() {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(contents.Files[name]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	// ErrInsecurePath comes with a usable reader. A producer's part names are what they are, and the
	// scanner read the original through the same zip package under the same rule.
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, err
	}
	return zr, nil
}

// scannerText returns the text the scanner's Office reader extracts from contents, read as a file named
// name. ok is false when that reader does not handle name's extension, so there is no view to check.
//
// An extraction error is not a reason to look away: the reader returns what it read before failing, and
// that is what a re-scan of the copy would see.
func scannerText(contents *OfficeZipContents, name string) (text string, ok bool, err error) {
	zr, err := storedPackage(contents)
	if err != nil {
		return "", false, err
	}
	tc, _ := textextractofficetextlib.ExtractTextFromFiles(zr.File, name)
	if tc == nil {
		return "", false, nil
	}
	return tc.Text, true, nil
}

// residueCandidates returns the distinct reported values worth searching the scanner's text for, in
// first-seen order, with the first match carrying each. The floor is minResidueValueLen, the one every
// other residue check here uses, so this check cannot refuse a value the others are told to ignore.
func residueCandidates(matches []detector.Match) ([]string, map[string]detector.Match) {
	values := make([]string, 0, len(matches))
	byText := make(map[string]detector.Match, len(matches))
	for _, m := range matches {
		if len(m.Text) < minResidueValueLen {
			continue
		}
		if _, dup := byText[m.Text]; dup {
			continue
		}
		byText[m.Text] = m
		values = append(values, m.Text)
	}
	return values, byText
}

// survivingValues returns the indices of the values that occur in text, ascending.
//
// Two linear passes rather than one strings.Contains per value: that loop is O(values x text) and this
// one runs on documents that are about to be written, not only on ones being refused. The first pass is
// a presence oracle and is all a clean document pays. The second replaces each occurrence with a marker
// naming the value and reads the markers back. Values are offered longest first, so where two overlap the
// longer is named, the precedence every rewrite here uses; a value hidden entirely inside a longer
// occurrence is named on the next look, after the longer one is gone.
//
// The markers are NUL-delimited, and NUL cannot occur in XML character data. A part that holds one
// anyway (the scanner reads bytes with a regex, not a parser) falls back to the per-value loop rather
// than parse markers it might have forged.
func survivingValues(text string, values []string) []int {
	if text == "" || len(values) == 0 {
		return nil
	}
	order := make([]int, len(values))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		va, vb := values[order[a]], values[order[b]]
		if len(va) != len(vb) {
			return len(va) > len(vb)
		}
		return va < vb
	})

	probeArgs := make([]string, 0, 2*len(values))
	for _, i := range order {
		probeArgs = append(probeArgs, values[i], "")
	}
	if strings.NewReplacer(probeArgs...).Replace(text) == text {
		return nil
	}

	found := make(map[int]bool)
	if strings.IndexByte(text, 0) >= 0 {
		for i, v := range values {
			if strings.Contains(text, v) {
				found[i] = true
			}
		}
	} else {
		markArgs := make([]string, 0, 2*len(values))
		for _, i := range order {
			markArgs = append(markArgs, values[i], "\x00"+strconv.Itoa(i)+"\x00")
		}
		marked := strings.NewReplacer(markArgs...).Replace(text)
		for rest := marked; ; {
			open := strings.IndexByte(rest, 0)
			if open < 0 {
				break
			}
			rest = rest[open+1:]
			end := strings.IndexByte(rest, 0)
			if end < 0 {
				break
			}
			if i, err := strconv.Atoi(rest[:end]); err == nil && i >= 0 && i < len(values) {
				found[i] = true
			}
			rest = rest[end+1:]
		}
	}

	out := make([]int, 0, len(found))
	for i := range found {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

// closeBoundarySpans reads contents back through the scanner's reader once every other rewrite has run,
// rewrites the write units it still finds across their node boundaries (rewriteAcrossBoundaries), and
// returns what the reader would still find after that: the residue RedactDocument refuses on.
//
// A clean document pays one read and one presence pass. The rewrite, and the second read that confirms
// it, run only when the first read found something.
//
// Each unit rewritten here keeps the replacement it is already written with in any other part, so a value
// reads the same everywhere (#886); a unit no other route placed gets its first audit entry here, with
// position_method "boundary_joined_text" and no character offsets, because it has no contiguous position
// in any part.
func (or *OfficeRedactor) closeBoundarySpans(
	contents *OfficeZipContents,
	name string,
	docType OfficeDocumentType,
	strategy redactors.RedactionStrategy,
	units, unlocated []officeWriteUnit,
	matches []detector.Match,
	pending map[string]*partReplacements,
) ([]detector.Match, []redactors.RedactionMapping, error) {
	// Every reported value and every unit's union: a member can survive outside its union.
	all := make([]detector.Match, 0, len(matches)+len(units))
	all = append(all, matches...)
	for _, u := range units {
		all = append(all, u.match)
	}
	values, byText := residueCandidates(all)
	if len(values) == 0 {
		return nil, nil, nil
	}
	text, ok, err := scannerText(contents, name)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the copy back through the scanner's reader: %w", err)
	}
	if !ok {
		return nil, nil, nil
	}
	hits := survivingValues(text, values)
	if len(hits) == 0 {
		return nil, nil, nil
	}

	unitRepl := make(map[string]string, len(units))
	for _, u := range units {
		if _, seen := unitRepl[u.match.Text]; !seen {
			unitRepl[u.match.Text] = u.replacement
		}
	}
	partNames := make([]string, 0, len(pending))
	for p := range pending {
		partNames = append(partNames, p)
	}
	sort.Strings(partNames)

	repl := make(map[string]string, len(hits))
	targets := make([]string, 0, len(hits))
	for _, i := range hits {
		v := values[i]
		r, isUnit := unitRepl[v]
		if !isUnit {
			continue // a member: its unit is the value written, and the residue check below still sees it
		}
		for _, p := range partNames {
			if pr := pending[p]; pr != nil {
				if w, recorded := pr.repl[v]; recorded {
					r = w
					break
				}
			}
		}
		repl[v] = r
		targets = append(targets, v)
	}
	sort.SliceStable(targets, func(i, j int) bool {
		if len(targets[i]) != len(targets[j]) {
			return len(targets[i]) > len(targets[j])
		}
		return targets[i] < targets[j]
	})

	rewritten := rewriteAcrossBoundaries(contents, docType, targets, repl, strategy != redactors.RedactionSimple)

	var mappings []redactors.RedactionMapping
	for _, u := range unlocated {
		parts, done := rewritten[u.match.Text]
		if !done || len(parts) == 0 {
			continue
		}
		mappings = append(mappings, redactors.RedactionMapping{
			RedactedText: repl[u.match.Text],
			Position: redactors.TextPosition{
				Line:      u.match.LineNumber,
				StartChar: -1,
				EndChar:   -1,
			},
			DataType:   u.match.Type,
			Strategy:   strategy,
			Confidence: u.match.Confidence,
			Metadata: map[string]interface{}{
				"office_file":        parts[0],
				"office_files":       parts,
				"document_type":      docType.String(),
				"position_method":    "boundary_joined_text",
				"split_across_nodes": true,
			},
		})
	}

	if len(rewritten) > 0 {
		or.logEvent("office_boundary_span_rewrites", true, map[string]interface{}{
			"values":        len(rewritten),
			"document_type": docType.String(),
		})
		if text, ok, err = scannerText(contents, name); err != nil {
			return nil, nil, fmt.Errorf("reading the copy back through the scanner's reader: %w", err)
		}
		if !ok {
			return nil, mappings, nil
		}
		hits = survivingValues(text, values)
	}

	residue := make([]detector.Match, 0, len(hits))
	for _, i := range hits {
		residue = append(residue, byText[values[i]])
	}
	return residue, mappings, nil
}
