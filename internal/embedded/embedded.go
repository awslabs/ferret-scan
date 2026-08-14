// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package embedded holds the contract shared by the two halves of
// container-inside-container handling: the READ side that finds embedded files
// and the WRITE side that has to redact them.
//
// It exists because those two halves live in packages that cannot import each
// other. The extractor is internal/preprocessors/meta-extractors/
// meta-extract-officelib, and internal/preprocessors imports it, so the
// extractor cannot import its own parent. The redactor is under
// internal/redactors. A leaf package with no internal dependencies is the only
// place both can reach.
//
// Why it has to be shared at all, rather than each side keeping its own copy:
// the admission set IS the contract. Only reported findings are redacted, so if
// the read side descends into a part the write side does not, the tool reports a
// finding it cannot redact and writes a "redacted" file with the value still in
// cleartext, at exit 0. That is not a hypothetical — it is the measured
// behaviour this package was extracted to prevent:
//
//	outer.docx -> word/embeddings/oleObject1.docx   SSN reported, survived redaction
//	outer.docx -> word/media/image1.jpg (EXIF)      SSN reported, survived redaction
//
// Both at exit 0 with nothing on stderr. Duplicating the predicate and adding a
// test that the two copies agree was the alternative; a single definition makes
// the divergence unrepresentable instead of merely detected.
package embedded

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
)

// MaxDepth bounds how deep container-inside-container traversal goes, counting
// the top-level file as depth 0 and a part inside it as depth 1.
//
// A bound is required in both directions, and for different reasons. On the read
// side an embedded OOXML document routes back through the Office preprocessor,
// which extracts ITS embeddings, which route back again: measured with a 7KB
// .docx embedding itself nine times, all nine levels were followed. On the write
// side the redactor dispatches each embedded part to a redactor, which for an
// OOXML part is the Office redactor again — the same unbounded recursion, plus a
// decompression-bomb amplifier, because every level gets a fresh per-package
// budget unless one is threaded through (see BudgetBytes).
//
// Three is deep enough for the real cases (a workbook in a deck in a report) and
// shallow enough that the amplification stays bounded.
//
// Reaching the bound must be DISCLOSED, never skipped quietly. Refusing to
// descend is incomplete coverage, and undisclosed incomplete coverage reads as a
// clean result — which is the failure this whole area keeps reproducing.
const MaxDepth = 3

// BudgetBytes is the cumulative decompression budget for one top-level file and
// everything nested inside it.
//
// This is deliberately a WHOLE-TRAVERSAL budget, not a per-package one. A
// per-package cap does not bound a nested bomb: each level would get its own
// fresh allowance, so the worst case multiplies by the number of children at
// every level rather than staying flat. With a per-package 200MB cap and a
// package able to hold thousands of tiny entries, three levels of nesting is an
// amplifier measured in terabytes. Threading one budget through the recursion
// makes the total the same whether the bytes are in one file or spread across a
// nested tree.
const BudgetBytes int64 = 200 * 1024 * 1024

// ErrTooDeep reports that a container nests deeper than MaxDepth.
//
// A sentinel rather than a formatted string so a caller can branch on it with
// errors.Is and tell "coverage was cut short, say so" apart from "this child
// failed to parse", which the ordinary error path already handles.
var ErrTooDeep = errors.New("embedded container nesting limit reached")

// ErrBudgetExhausted reports that a traversal hit BudgetBytes.
//
// Distinct from ErrTooDeep because the disclosure differs: too-deep means a
// known part was skipped, budget-exhausted means the file is a probable
// decompression bomb. Both leave content unexamined and both must be surfaced.
var ErrBudgetExhausted = errors.New("embedded container decompression budget exhausted")

// kindByExt maps a lower-cased extension to the class of embedded file it is.
//
// The empty string means "no preprocessor can read this", and such a part is
// skipped by both sides. Keeping the map unexported with an accessor keeps it
// from being mutated at run time by one side and not the other.
//
// Ordering note: this is a map only for lookup; nothing iterates it, so map
// order cannot reach output.
var kindByExt = map[string]string{
	// Images. Scanned for metadata (EXIF/XMP/IPTC), which is where an author
	// name, GPS fix or free-text description leaks from.
	".jpg": "image", ".jpeg": "image", ".png": "image",
	".tiff": "image", ".tif": "image", ".gif": "image",
	".bmp": "image", ".webp": "image",

	// Audio. Admitted on the read side because tags carry free text (Artist,
	// Comment). NOTE: no redactor handles audio, so a finding inside an
	// embedded clip cannot be removed — that case must be disclosed rather
	// than silently dropped. See Redactable.
	".mp3": "audio", ".wav": "audio", ".m4a": "audio", ".flac": "audio",

	// Legacy OLE compound files. A leaf on the read side: the extractor reads
	// their streams directly and does not follow embeddings, so admitting them
	// adds no recursion.
	".doc": "legacy_document", ".xls": "legacy_document", ".ppt": "legacy_document",

	// OOXML documents. These DO recurse — an embedded .docx routes back into the
	// same code on both sides — which is what MaxDepth and BudgetBytes bound.
	".docx": "document", ".xlsx": "document", ".pptx": "document",

	// PDF. Admitted for SCANNING, and it cannot be redacted, so it fails LOUDLY.
	//
	// Previously absent from the read side's switch, so an embedded PDF was never
	// examined at all: measured, an SSN in word/embeddings/attachment.pdf produced
	// zero findings, exit 0, and no warning, while the value sat in the "redacted"
	// output. Admitting it took that fixture from 1 finding to 3.
	//
	// Detection is not the thing to give up. But PDF redaction is unimplemented and
	// refuses to write output, and PDF text lives in FlateDecode streams, so a byte
	// scan of the part cannot prove it clean either. The honest resolution is the one
	// encoded in opaqueExts below: an embedded PDF is always handed to a redactor, the
	// redactor always refuses, and the container is therefore refused with a message
	// saying exactly that. The tool never silently ships a document whose attached PDF
	// it could not scrub.
	".pdf": "document",
}

// Kind classifies an embedded part by extension, returning "" for anything no
// preprocessor can read.
//
// ext is matched case-insensitively: a zip entry name is producer-controlled
// data and nothing makes the conventional spelling normative. A case-sensitive
// predicate in this same area let a part named word/Document.xml be detected and
// then survive redaction in cleartext.
func Kind(ext string) string {
	return kindByExt[strings.ToLower(ext)]
}

// KindOfPath classifies an embedded part by its full entry name.
func KindOfPath(name string) string {
	return Kind(filepath.Ext(name))
}

// KindDocument is the class of embedded part that can itself contain further
// embedded parts. Named because both bounds exist for it specifically.
const KindDocument = "document"

// Recurses reports whether descending into this part can lead back into another
// container, which is what makes MaxDepth and BudgetBytes necessary.
//
// Derived from Kind rather than listing the extensions again. A second list would
// be a second thing to keep in step, and an extension present in one and absent
// from the other is precisely the divergence class this package exists to make
// unrepresentable. The legacy OLE and image kinds are leaves; "document" is not.
func Recurses(name string) bool {
	return KindOfPath(name) == KindDocument
}

// opaqueExts are admitted formats whose payload can be COMPRESSED internally, so
// scanning their raw bytes proves nothing about what they contain.
//
// Only PDF qualifies today, and the set exists for it. This is NOT the same mistake an
// earlier revision made: that version also listed the audio formats, which would have
// made every embedded clip block its container. Audio tags are stored uncompressed --
// ID3v2 text frames, RIFF INFO, Vorbis comments, MP4 ilst atoms -- so audio is
// inspectable and a clip holding nothing is correctly left alone.
//
// The consequence of being opaque is deliberate and asymmetric: an inspectable part is
// dispatched only when a byte scan finds a reported value in it, whereas an OPAQUE part
// is ALWAYS dispatched, because absence cannot be established. If no redactor can
// rewrite it, that surfaces as a refusal to write the container rather than as a
// silent pass.
var opaqueExts = map[string]bool{
	".pdf": true,
}

// ResidueInspectable reports whether scanning a part's raw bytes for a value is a
// sound test for that value's ABSENCE.
//
// False means "we cannot see inside this", which makes the part always-dispatched
// rather than always-skipped. Getting that polarity backwards is how a value inside a
// compressed stream gets judged harmless and shipped.
//
// An UNKNOWN extension defaults to inspectable, and that is sound rather than
// optimistic. The scan and the preprocessors have the same visibility: a value can only
// be REPORTED from a part if some preprocessor extracted it, and for every format that
// happens through text/EXIF/OLE bytes the raw scan reads, or through zip members the
// scan inflates. The one exception is a format whose text a preprocessor decompresses
// but the scan cannot — PDF — which is why PDF is listed explicitly above. A format
// nobody can extract from produces no findings, so there is nothing reported to leak.
func ResidueInspectable(name string) bool {
	return !opaqueExts[strings.ToLower(filepath.Ext(name))]
}

// AdmittedExts returns every extension the two halves descend into, sorted.
//
// Exported for the contract test that enforces this package's central invariant:
// EVERY ADMITTED TYPE MUST BE BYTE-INSPECTABLE -- a reported value present in such a
// part must be findable by scanning the part's bytes, after inflating any archive
// members.
//
// That invariant is what lets the redactor treat "the byte scan found nothing" as
// "this part holds none of the reported values", which in turn is what keeps an
// unredactable-but-harmless part from blocking its whole container. It holds for
// every type above:
//
//	images       EXIF/IPTC/XMP text is stored uncompressed
//	audio        ID3v2 text frames, RIFF INFO, Vorbis comments and MP4 ilst
//	             atoms are all stored uncompressed
//	legacy OLE   property and body streams are uncompressed
//	OOXML        deflated, but the scan inflates archive members
//
// It does NOT hold for PDF, which is why PDF is listed in opaqueExts above and is
// always dispatched instead of being skipped on a clean byte scan.
func AdmittedExts() []string {
	out := make([]string, 0, len(kindByExt))
	for ext := range kindByExt {
		out = append(out, ext)
	}
	sort.Strings(out) // sorted: the result reaches test output and error text
	return out
}

// XMLEscapeVariants returns the spellings a value can take inside an admitted part.
//
// A value stored in OOXML XML is escaped, so the literal from a Match does not
// necessarily occur in the part's bytes: an ampersand in a name is written &amp;, and
// a value inside an attribute may carry escaped quotes. A residue scan looking only
// for the raw literal would report "clean" for a part that plainly holds the value --
// the exact false negative this mechanism exists to avoid.
//
// The raw form is always first. The escaped form is appended only when it differs, so
// the common case allocates nothing extra.
func XMLEscapeVariants(s string) []string {
	esc := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	).Replace(s)
	if esc == s {
		return []string{s}
	}
	return []string{s, esc}
}

// MaxDispatchedParts bounds how many embedded parts one container hands out for
// redaction.
//
// Each dispatched part is a full extract-redact-repackage cycle, and redaction is
// already the slowest stage of a scan, so an archive with tens of thousands of tiny
// embedded entries is a cheap way to make one document cost minutes. The cap is
// generous because legitimate documents are: a large deck can carry several hundred
// media parts. Truncation must be DISCLOSED -- a silently capped traversal is
// incomplete coverage reading as a clean result.
const MaxDispatchedParts = 512

// IsPartPath reports whether an OOXML part path holds an embedded file that
// should be handled in its own right.
//
// "/media/" alone was not enough: Word stores an embedded DOCUMENT under
// word/embeddings/ as an OLE object, and that path was never considered, so a
// document attached to a document was invisible. Both prefixes are checked as
// substrings rather than anchored prefixes because the container's own
// convention varies by format (word/, xl/, ppt/).
func IsPartPath(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "/media/") || strings.Contains(n, "/embeddings/")
}

// SafeExt returns the extension to give a temporary file materialized from an
// embedded part.
//
// The result is NEVER a slice of the caller's string used as-is. A zip entry name is
// producer-controlled and this value is concatenated into a filesystem path, so per
// BSC1 it is validated against an allowlist at the sink. The allowlist here is a
// CHARACTER CLASS rather than a table of known types: a dot followed by 1-10 ASCII
// alphanumerics, lower-cased. Nothing outside that class can appear in the result, so
// no separator, "..", NUL, or overlong component is representable regardless of what
// the entry is called.
//
// Why a class and not the admission table it used to be: the table listed only the
// types someone had enumerated, which meant an embedded .svg — 411 of them across 334
// real Office files, and plain XML text that scans fine on its own — could not even be
// written to a temp file, so it was never examined. The pipeline decides what it can
// process; this function's job is only to make the handoff safe, not to second-guess
// coverage.
//
// A part whose name yields nothing usable (no extension, or characters outside the
// class) gets fallbackExt, so it still reaches the byte-sniffing preprocessors rather
// than being dropped for the shape of its name.
func SafeExt(name string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(name))
	// len < 2 covers both "" (no extension) and a bare "." from a name ending in a
	// dot, which filepath.Ext returns verbatim. A lone dot is not a well-formed
	// extension and would produce a temp file named "embedded." -- harmless but
	// malformed, and the fallback is the right answer for a name that yields nothing.
	if len(ext) < 2 || len(ext) > 11 { // 1 dot + at most 10 chars
		return fallbackExt, true
	}
	for i := 1; i < len(ext); i++ {
		c := ext[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return fallbackExt, true
		}
	}
	return ext, true
}

// fallbackExt is given to a part whose own name yields no safe extension.
//
// ".bin" specifically: it is claimed by no metadata preprocessor, so the
// byte-sniffing text fallback gets a chance at it, which is the best available answer
// for a part we cannot classify by name.
const fallbackExt = ".bin"
