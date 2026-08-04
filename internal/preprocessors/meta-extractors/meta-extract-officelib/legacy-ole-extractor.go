// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/richardlehane/mscfb"
	"github.com/richardlehane/msoleps"
	"github.com/richardlehane/msoleps/types"
)

// Legacy Office (.doc/.xls/.ppt) support.
//
// These are OLE Compound File Binary containers, not ZIPs, so none of the OOXML
// code applies. Until now they returned "legacy Office formats not supported":
// the file was reported as an error and NOTHING in it was scanned. For a DLP
// tool that is a silent recall hole on a format still common in email archives,
// shared drives and anything exported from an older system.
//
// Two things are recovered, and they are not equally exact:
//
//   - METADATA is exact. The SummaryInformation / DocumentSummaryInformation
//     property streams are a documented key/value format, parsed by msoleps.
//     This is the legacy counterpart of docProps/*.xml, which is the same place
//     an author name, company or template path leaks from in a modern document.
//   - BODY TEXT is approximate. mscfb gives the raw WordDocument / Workbook /
//     PowerPoint Document stream; a full format parser (piece tables, FIB
//     structures, BIFF records) is a much larger undertaking. A conservative
//     printable-run scan recovers the character data a validator needs without
//     pretending to reconstruct layout.
//
// So .doc recall is good, not equal to .docx. That is stated plainly rather than
// implied, because a scanner that quietly under-reads a format is worse than one
// that says what it can do.

// maxLegacyStreamBytes bounds a single decompressed OLE stream, mirroring the
// 50MB per-entry cap the OOXML paths already use. An OLE container declares its
// own stream sizes, so an unbounded io.ReadAll here would be the same
// decompression-bomb hole that cap exists to close.
const maxLegacyStreamBytes = 50 * 1024 * 1024

// legacyBodyStreams are the streams that hold document character data, by
// format. Names are exact and case-sensitive, as written by Office.
var legacyBodyStreams = map[string]bool{
	"WordDocument":        true, // .doc
	"Workbook":            true, // .xls (Excel 97+)
	"Book":                true, // .xls (Excel 5.0/95)
	"PowerPoint Document": true, // .ppt
}

// legacyPropertyStreams hold the document properties — the legacy equivalent of
// docProps/core.xml and docProps/app.xml.
var legacyPropertyStreams = map[string]bool{
	"SummaryInformation":         true,
	"DocumentSummaryInformation": true,
}

// extractLegacyOfficeMetadata reads an OLE compound file, filling metadata from
// its property streams and returning the recovered body text.
//
// A stream that fails to parse is skipped rather than failing the file: a
// truncated property stream must not cost the caller the body text, and vice
// versa. Partial recovery beats none for a scanner.
func extractLegacyOfficeMetadata(filePath string, metadata *Metadata) (*Metadata, string, error) {
	f, err := os.Open(filePath) // #nosec G304 -- path already vetted by the router
	if err != nil {
		return metadata, "", fmt.Errorf("failed to open legacy Office file: %w", err)
	}
	defer f.Close()

	doc, err := mscfb.New(f)
	if err != nil {
		return metadata, "", fmt.Errorf("not a readable OLE compound file: %w", err)
	}

	var body strings.Builder
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		switch {
		case legacyBodyStreams[entry.Name]:
			buf, rerr := io.ReadAll(io.LimitReader(entry, maxLegacyStreamBytes))
			if rerr != nil {
				continue
			}
			body.WriteString(recoverPrintableRuns(buf))

		case legacyPropertyStreams[entry.Name]:
			buf, rerr := io.ReadAll(io.LimitReader(entry, maxLegacyStreamBytes))
			if rerr != nil {
				continue
			}
			applyLegacyProperties(buf, metadata)
		}
	}

	return metadata, body.String(), nil
}

// applyLegacyProperties maps an OLE property stream onto the shared Metadata
// struct, so a legacy document's author reaches the report through the same
// field a modern document's does.
//
// Only fields that can carry free text are mapped. The numeric and structural
// properties (page/word/character counts, revision number, edit time, security
// flags) are skipped: they are not PII, and surfacing them would add noise to
// every report for no detection value — the same reasoning that excludes them
// from OOXML docProps redaction.
func applyLegacyProperties(streamBytes []byte, metadata *Metadata) {
	r, err := msoleps.NewFrom(bytes.NewReader(streamBytes))
	if err != nil {
		return
	}
	for _, p := range r.Property {
		v := strings.TrimSpace(p.String())
		if v == "" {
			continue
		}
		switch p.Name {
		case "Title":
			setIfEmpty(&metadata.Title, v)
		case "Subject":
			setIfEmpty(&metadata.Subject, v)
		case "Author":
			setIfEmpty(&metadata.Author, v)
			setIfEmpty(&metadata.Creator, v)
		case "Keywords":
			setIfEmpty(&metadata.Keywords, v)
		case "Comments":
			setIfEmpty(&metadata.Comments, v)
		case "LastAuthor":
			setIfEmpty(&metadata.LastModifiedBy, v)
		case "AppName":
			setIfEmpty(&metadata.Application, v)
		case "Template":
			setIfEmpty(&metadata.Template, v)
		case "Company":
			setIfEmpty(&metadata.Company, v)
		case "Manager":
			setIfEmpty(&metadata.Manager, v)
		case "Category":
			setIfEmpty(&metadata.Category, v)
		// "Content status", with the space, is the name msoleps produces for
		// property 0x1B. A "ContentStatus" case matches nothing: property names
		// come from msoleps's own tables, not from the OOXML vocabulary, and the
		// two spellings differ. There is no "Identifier" name in those tables at
		// all, so Metadata.Identifier has no legacy source and is not mapped.
		case "Content status":
			setIfEmpty(&metadata.ContentStatus, v)
		case "Language":
			setIfEmpty(&metadata.Language, v)
		case "Version":
			setIfEmpty(&metadata.Revision, v)
		case "CreateTime":
			setTimeIfZero(&metadata.Created, p)
		case "LastSaveTime":
			setTimeIfZero(&metadata.Modified, p)
		}
	}
}

// setIfEmpty fills a field only when it has no value yet. SummaryInformation and
// DocumentSummaryInformation can both define a property; first writer wins, so
// the result does not depend on stream order.
func setIfEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// setTimeIfZero fills a timestamp field from a property whose value is a time.
//
// Property.T carries the typed value; a FileTime is the OLE representation of a
// timestamp. Anything else with the same property name is ignored rather than
// coerced, so a malformed stream cannot put a nonsense date in a report.
//
// The assertion is on the VALUE type, not a pointer. msoleps builds FileTime
// properties with MakeFileTime, which returns types.FileTime by value, so a
// *types.FileTime assertion never succeeds and every legacy document would report
// a zero Created/Modified — a silent whole-field loss with no error anywhere. The
// pointer form is accepted as well so a future msoleps change cannot quietly
// reintroduce that.
func setTimeIfZero(dst *time.Time, p *msoleps.Property) {
	if !dst.IsZero() {
		return
	}
	switch ft := p.T.(type) {
	case types.FileTime:
		*dst = ft.Time()
	case *types.FileTime:
		*dst = ft.Time()
	}
}

// recoverPrintableRuns pulls character data out of a raw legacy body stream.
//
// This is deliberately conservative rather than clever. Legacy Word interleaves
// text with binary structures and mixes single-byte and UTF-16LE runs, so both
// encodings are scanned. Runs shorter than minLegacyRun are dropped: below that
// length, binary structure bytes coincide with printable ASCII often enough to
// produce garbage that wastes validator time and invites false positives.
//
// What this does NOT do: reconstruct reading order, resolve the piece table, or
// drop deleted-but-retained text. For a scanner that is acceptable — a value
// present anywhere in the stream is a value the document can disclose — but it
// does mean recovered text is not a faithful rendering of the document.
func recoverPrintableRuns(b []byte) string {
	var out strings.Builder
	out.Grow(len(b) / 2)

	// Single-byte pass.
	var run strings.Builder
	flush := func() {
		if run.Len() >= minLegacyRun {
			out.WriteString(run.String())
			out.WriteByte('\n')
		}
		run.Reset()
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			run.WriteByte(c)
			continue
		}
		flush()
	}
	flush()

	// UTF-16LE pass: an ASCII byte followed by a zero byte. Legacy Word stores
	// much of its text this way, and the single-byte pass above sees only every
	// other character of it.
	var wide strings.Builder
	flushWide := func() {
		if wide.Len() >= minLegacyRun {
			out.WriteString(wide.String())
			out.WriteByte('\n')
		}
		wide.Reset()
	}
	for i := 0; i+1 < len(b); i += 2 {
		if b[i] >= 0x20 && b[i] < 0x7f && b[i+1] == 0 {
			wide.WriteByte(b[i])
			continue
		}
		flushWide()
	}
	flushWide()

	return out.String()
}

// minLegacyRun is the shortest printable run treated as text. Eight characters
// is long enough that binary structure bytes rarely produce one by accident, and
// short enough to keep values a scanner cares about — an SSN is 11 characters, a
// card number 15+, an email longer still.
const minLegacyRun = 8

// extractLegacyOfficeMetadataOnly adapts extractLegacyOfficeMetadata to the
// metadata-only signature the format dispatch uses. The recovered body text is
// carried in Properties["LegacyBodyText"] rather than discarded, so the
// preprocessor can hand it to the document path.
func extractLegacyOfficeMetadataOnly(filePath string, metadata *Metadata) (*Metadata, error) {
	md, body, err := extractLegacyOfficeMetadata(filePath, metadata)
	if err != nil {
		return md, err
	}
	if body != "" {
		if md.Properties == nil {
			md.Properties = make(map[string]string)
		}
		md.Properties["LegacyBodyText"] = body
	}
	return md, nil
}
