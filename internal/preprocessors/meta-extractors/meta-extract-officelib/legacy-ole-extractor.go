// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
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
// A var, not a const, so a test can lower it and assert the truncation actually
// happens. It was a const and nothing asserted it — a mutation raising it to 1<<62
// compiled and every test still passed. That is precisely the guard that must not be
// silently removable, because scanning every stream (see below) applies it to far more
// bytes than the previous four-name allowlist did.
var maxLegacyStreamBytes int64 = 50 * 1024 * 1024

// legacyBodyStreams names the streams KNOWN to hold document character data.
//
// Retained for documentation and for the ordering guarantee below, NOT as a gate:
// body text is now recovered from every stream that is not a property stream. The
// allowlist was a detection hole, because a .doc keeps a large fraction of its text
// outside WordDocument:
//
//	1Table / 0Table   revision marks, comments, fast-save text
//	Data              embedded content
//	ObjectPool/*      embedded objects
//
// Measured on a real 690KB .doc: 1Table held 14 recoverable printable runs that no
// validator ever saw, and a fixture with an SSN placed only in 1Table produced zero
// findings — so the value survived into the "redacted" copy in cleartext, since only
// reported findings are redacted. That is the normal on-disk layout of an edited Word
// document; it needs no attacker.
//
// recoverPrintableRuns was already name-agnostic and conservative (a minimum run
// length, single-byte and UTF-16 passes), so the allowlist bought nothing on the body
// side while excluding most of the document. See #266.
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
		// Property streams are PARSED as properties; everything else is scavenged for
		// printable runs.
		//
		// Inverted from an allowlist of four body-stream names, which silently
		// excluded 1Table/0Table/Data/ObjectPool — where an edited .doc keeps its
		// revision marks, comments and fast-save text. A value living only there was
		// never reported and therefore never redacted (#266).
		//
		// Deliberately a default-scan rather than a longer allowlist: the failure mode
		// being fixed is "a stream nobody thought of", so a list of names we thought of
		// cannot close it. recoverPrintableRuns is conservative enough to run on
		// arbitrary bytes — it emits only runs of printable characters at or above a
		// minimum length, so structural bookkeeping yields nothing.
		//
		// The per-stream io.LimitReader cap is unchanged and now matters more, since it
		// applies to more streams: an OLE container declares its own stream sizes, so
		// this stays bounded per stream rather than becoming a bomb amplifier.
		switch {
		case legacyPropertyStreams[entry.Name]:
			buf, rerr := io.ReadAll(io.LimitReader(entry, maxLegacyStreamBytes))
			if rerr != nil {
				continue
			}
			applyLegacyProperties(buf, metadata)

		default:
			buf, rerr := io.ReadAll(io.LimitReader(entry, maxLegacyStreamBytes))
			if rerr != nil {
				continue
			}
			body.WriteString(recoverPrintableRuns(buf))
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

	// Vector-valued properties are decoded from the stream, because msoleps cannot
	// read one: it looks for the vector flag in the wrong half of the type word, so a
	// real vector arrives here as the scalar I1(0) and p.String() returns "0". See
	// legacy-ole-vectors.go for the measurement. Keyed by index into r.Property,
	// which msoleps builds in property-table order.
	vectors := legacyVectorStrings(streamBytes)

	for i, p := range r.Property {
		v := strings.TrimSpace(p.String())
		if vec, ok := vectors[i]; ok {
			// A multi-valued property collected as a custom property gets ONE entry
			// per element, so no validator can match across two unrelated elements —
			// two adjacent sheet names joined on one line would invite exactly that.
			// A mapped scalar field has nowhere to put a list, so those are joined.
			if handleVectorProperty(metadata, p.Name, vec) {
				continue
			}
			v = strings.Join(vec.Elements, "; ")
		}
		if v == "" {
			continue
		}
		switch p.Name {
		// The mapped fields below are the KNOWN properties. Anything else with a
		// name is a user-defined (custom) property and is collected verbatim by the
		// default arm, because a custom property is free-form text a document
		// author chose — historically one of the likeliest metadata leak channels,
		// and the same reason the OOXML path reads docProps/custom.xml.
		case "Title":
			keepValue(metadata, &metadata.Title, p.Name, v)
		case "Subject":
			keepValue(metadata, &metadata.Subject, p.Name, v)
		case "Author":
			keepValue(metadata, &metadata.Author, p.Name, v)
			setIfEmpty(&metadata.Creator, v)
		case "Keywords":
			keepValue(metadata, &metadata.Keywords, p.Name, v)
		case "Comments":
			keepValue(metadata, &metadata.Comments, p.Name, v)
		case "LastAuthor":
			keepValue(metadata, &metadata.LastModifiedBy, p.Name, v)
		case "AppName":
			keepValue(metadata, &metadata.Application, p.Name, v)
		case "Template":
			keepValue(metadata, &metadata.Template, p.Name, v)
		case "Company":
			keepValue(metadata, &metadata.Company, p.Name, v)
		case "Manager":
			keepValue(metadata, &metadata.Manager, p.Name, v)
		case "Category":
			keepValue(metadata, &metadata.Category, p.Name, v)
		// "Content status", with the space, is the name msoleps produces for
		// property 0x1B. A "ContentStatus" case matches nothing: property names
		// come from msoleps's own tables, not from the OOXML vocabulary, and the
		// two spellings differ. There is no "Identifier" name in those tables at
		// all, so Metadata.Identifier has no legacy source and is not mapped.
		case "Content status":
			setIfEmpty(&metadata.ContentStatus, v)
		case "Language":
			setIfEmpty(&metadata.Language, v)
		case "RevNumber":
			// The document's revision count, SummaryInformation 0x09. This is what
			// Metadata.Revision means, and the OOXML path fills it from
			// docProps/core.xml's <cp:revision>. Removing the wrong "Version"
			// mapping without adding this one would have left Revision permanently
			// empty for legacy documents — a field the report renders, so a legacy
			// document would silently show less than an equivalent .docx.
			setIfEmpty(&metadata.Revision, v)
		case "Link base":
			// HyperlinkBase. The same UNC/URL disclosure class as Template: it
			// routinely holds an internal share or intranet host.
			setCustomProp(metadata, "HyperlinkBase", v)
		case "CreateTime":
			setTimeIfZero(&metadata.Created, p)
		case "LastSaveTime":
			setTimeIfZero(&metadata.Modified, p)
		default:
			// A user-defined property. Its NAME comes from the property set's own
			// dictionary, so it is document-author-controlled and must not be
			// allowed to collide with a mapped field — see setCustomProp.
			//
			// Skipping these was a cleartext leak: a custom property named
			// "ClientSSN" holding a real SSN was reported by NOTHING, and only
			// reported findings are redacted. Measured on a .doc carrying an SSN and
			// an AWS key in custom properties: 0 findings for either before this.
			if isCollectableCustomProperty(p.Name) {
				setCustomProp(metadata, p.Name, v)
			}
		}
	}
}

// legacyStructuralProperties are the property names that carry no free text worth
// scanning: counts, flags, packed version numbers and the property set's own
// bookkeeping. They are excluded from custom-property collection because surfacing
// "Byte count: 4096" on every legacy document is pure report noise, and noise
// trains users to skim past real findings.
//
// Note "Version" is here rather than mapped to Metadata.Revision: it is the packed
// application version that WROTE the file, not a document revision number, so
// putting it in Revision would report a wrong value in a named field.
var legacyStructuralProperties = map[string]bool{
	"Dictionary": true, "CodePage": true, "Locale": true, "Behaviour": true,
	"Byte count": true, "Line count": true, "Paragraph count": true,
	"Slide count": true, "Note count": true, "Multimedia clips count": true,
	"Character count": true, "PageCount": true, "WordCount": true, "CharCount": true,
	"Scale": true, "Dirty links": true, "Shared document": true,
	"Hyperlinks changed": true, "Digital Signature": true, "Thumbnail": true,
	"DocSecurity": true, "EditTime": true, "LastPrinted": true,
	"Version": true, "Document Version": true, "Presentation Format": true,
	// "Heading pair" stays: it is a VT_VECTOR|VT_VARIANT of (name, count) pairs, so
	// its text is the words "Worksheets"/"Slide Titles" and its numbers are counts.
	"Heading pair": true,
	// "Document parts" (DocumentSummaryInformation 0x0D) is NOT structural and is no
	// longer excluded. It is the vector of part names: every SHEET NAME in a workbook,
	// every SLIDE TITLE in a deck. That is document content an author wrote, and it
	// routinely carries a customer name, a project codename or an account number.
	//
	// It was excluded when the value reaching this code was the literal "0" — msoleps
	// mis-decodes a vector (see legacy-ole-vectors.go), so the property looked like
	// structural noise. Now that the elements are decoded, excluding it would drop
	// real content: measured on an .xls whose sheet names include an SSN, the value
	// was reported by nothing at all.
}

// isCollectableCustomProperty reports whether an unmapped property name should be
// collected as a custom property.
func isCollectableCustomProperty(name string) bool {
	if strings.TrimSpace(name) == "" {
		// msoleps leaves the name empty when a property ID is absent from both its
		// tables and the stream's dictionary. There is nothing to label such a value
		// with, and an unlabelled entry cannot be acted on.
		return false
	}
	return !legacyStructuralProperties[name]
}

// setCustomProp records a custom property, keeping document-author-controlled
// names from colliding with each other.
//
// The name comes from the property set's dictionary, which the document author
// writes, so two custom properties can legitimately share a name and a hostile
// document can pick any name it likes. First writer wins and later collisions are
// suffixed rather than dropped: silently discarding the second value would be the
// same leak this function exists to close.
func setCustomProp(metadata *Metadata, name, value string) {
	if metadata.CustomProps == nil {
		metadata.CustomProps = make(map[string]string)
	}
	if _, exists := metadata.CustomProps[name]; !exists {
		metadata.CustomProps[name] = value
		return
	}
	if metadata.CustomProps[name] == value {
		return // an exact duplicate carries no additional information
	}
	for i := 2; i < 1000; i++ {
		key := name + " (" + strconv.Itoa(i) + ")"
		if existing, exists := metadata.CustomProps[key]; !exists {
			metadata.CustomProps[key] = value
			return
		} else if existing == value {
			return
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

// keepValue fills a mapped field, and keeps the value as a custom property when
// the field is already taken.
//
// Both halves matter and they pull in opposite directions. A property NAME comes
// from the property set's own dictionary, which the document author writes, so a
// document can define a custom property called "Author" and a plain first-writer-
// wins rule would let it decide what the report calls the author. Hence the mapped
// field is never overwritten.
//
// But simply discarding the loser is the leak this function was added to close: the
// displaced value is still document content, and a value that reaches no field
// reaches no validator and is never redacted. So it is preserved under its name in
// CustomProps instead of being dropped.
func keepValue(metadata *Metadata, dst *string, name, v string) {
	if *dst == "" {
		*dst = v
		return
	}
	if *dst == v {
		return // the same value from both property sets carries nothing new
	}
	setCustomProp(metadata, name, v)
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
