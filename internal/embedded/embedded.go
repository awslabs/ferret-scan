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
	"archive/zip"
	"bytes"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
// decompression-bomb amplifier, because every container gets a fresh allowance
// (BudgetBytes is per-container, not threaded — see the note there).
//
// Three is deep enough for the real cases (a workbook in a deck in a report) and
// shallow enough that DEPTH-driven amplification stays bounded. Depth is the only
// axis this constant bounds; fan-out is not bounded here.
//
// Reaching the bound must be DISCLOSED, never skipped quietly. Refusing to
// descend is incomplete coverage, and undisclosed incomplete coverage reads as a
// clean result — which is the failure this whole area keeps reproducing.
const MaxDepth = 3

// BudgetBytes is the decompression budget for embedded parts.
//
// It bounds TWO different things, and the distinction is the whole point of #474:
//
//   - per container, the bytes one container may inflate while deciding what it
//     holds. Enforced by the Office extractor's own unexported budget.
//   - per TOP-LEVEL FILE, the bytes the whole traversal may MATERIALISE, however
//     those bytes are spread across nesting and fan-out. Enforced by Budget below,
//     created once per top-level file and inherited by every descendant.
//
// The second bound did not exist, and this comment used to say so. What it cost,
// measured on a real LibreOffice-authored .docx:
//
//	4 levels of nesting, 205KB in     8 grants    720MB written to temp
//	  the same, with --enable-redaction            peak RSS 1,353MiB
//	1 level, 64 sibling containers, 367KB in    130 grants   11,531MB written
//
// The last row is a 32,947x write amplification from a third of a megabyte, at
// exit 0, with nothing on stderr. MaxDepth bounded the depth factor and nothing
// bounded fan-out, so that row is reachable at depth 1 and at 1.6% of
// maxEmbeddedParts. Each container drew its own fresh 200MB allowance because
// newExtractionBudget granted one per call and the recursion runs in other
// packages (internal/router, internal/redactors) that materialise each child as
// its own file and re-enter extraction on it.
//
// A single container already refused and disclosed correctly; only the aggregate
// was unbounded. That is the "declared size bounds declared size" shape one level
// up: every individual check passes and the checks compose to nothing.
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

// Budget bounds the bytes ONE TOP-LEVEL FILE may materialise across its entire
// embedded traversal.
//
// # Why it must be per top-level file, and not narrower or wider
//
// Narrower — per container — is what BudgetBytes' comment describes and is not
// enough: the aggregate scales with container COUNT, so splitting one refused
// container into sixty admissible ones defeats it.
//
// Wider — a package-level counter shared by the whole scan — would be worse than
// the bug. Files are scanned by a parallel worker pool, so a shared budget makes
// WHICH parts get examined depend on worker interleaving: the findings and the
// disclosure would both differ run to run, and a large file early in a directory
// would make later files report clean. Detection must not depend on scheduling.
// Per top-level file is the widest scope that is still deterministic, and it is
// released when that file finishes so the next file starts whole.
//
// A Budget is created by the router for each top-level file and handed to every
// descendant of it, so the sum below is over the real traversal rather than over
// one container.
type Budget struct {
	// Guarded because a Budget outlives one call and is reachable from anywhere in
	// one file's traversal. Today that traversal is sequential, so the lock is never
	// contended; it is here so that parallelising the part loop later cannot turn a
	// resource bound into a data race.
	mu        sync.Mutex
	remaining int64
	limit     int64

	// exhausted latches once a reservation has been refused.
	//
	// A flag rather than zeroing remaining, because reservations are RELEASED when a part
	// turns out to be smaller than it declared. Zeroing would let a refund resurrect a
	// traversal that had already been refused, and then whether a part was examined would
	// depend on the ORDER parts appear in the archive — which the producer chooses. Latching
	// keeps the refusal order-independent while leaving the accounting intact.
	exhausted bool
}

// NewBudget returns a whole-traversal budget of BudgetBytes.
func NewBudget() *Budget {
	return &Budget{remaining: BudgetBytes, limit: BudgetBytes}
}

// Reserve claims n bytes, reporting whether the traversal may still afford them.
//
// A nil Budget always allows, so a caller that has not been given one behaves
// exactly as it did before this bound existed. That matters for the direct callers
// of the extractor's exported functions, which have no router to ask.
//
// Charged with bytes ACTUALLY written rather than a declared size, for the same
// reason the per-container budget is: an over-claim would otherwise let one lying
// part deny coverage to the rest of the document.
func (b *Budget) Reserve(n int64) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exhausted || n > b.remaining {
		b.exhausted = true
		return false
	}
	b.remaining -= n
	return true
}

// Exhausted reports whether this traversal has already refused a part.
//
// Callers use it to skip work they know will be refused, so an exhausted traversal costs
// nothing per remaining part rather than one refusal each.
func (b *Budget) Exhausted() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exhausted
}

// Release returns an unspent reservation.
//
// The traversal is reserved on a part's DECLARED size, before any bytes are written, so that an
// exhausted traversal refuses a part without materialising it — refusing AFTER the copy bounds
// what gets scanned but not what gets written, which is most of the harm. The declared size is
// producer-controlled, so whatever it over-claimed is handed back here as soon as the real length
// is known. That is what keeps a lying declaration from denying coverage to the rest of the
// document, which is the hazard post-copy charging exists to avoid.
//
// Never raises the allowance above its limit: a release without a matching reservation would
// otherwise mint budget.
func (b *Budget) Release(n int64) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remaining += n
	if b.remaining > b.limit {
		b.remaining = b.limit
	}
}

// Limit reports the budget this traversal started with, for the refusal message.
func (b *Budget) Limit() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limit
}

// Remaining reports the unspent allowance. Used by tests to prove the charge
// actually happened, since a budget that is threaded but never charged looks
// identical to a fixed one from the outside.
func (b *Budget) Remaining() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.remaining
}

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
	// Comment), and redactable on the write side since #357 — this note used to
	// say the opposite. Measured on a .docx carrying word/embeddings/clip.mp3
	// with an SSN in its ID3 comment: reported at HIGH 100, and absent from the
	// embedded part of the redacted document.
	".mp3": "audio", ".wav": "audio", ".m4a": "audio", ".flac": "audio",

	// Video is deliberately NOT here. It is redactable at the top level (#358),
	// but admitting it as an embedded part is a read-side change with its own
	// extraction cost and budget questions, and nothing measures it yet. An
	// embedded clip is therefore not scanned at all rather than scanned and
	// left unredacted.

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

// vectorGraphicsExts hold DRAWING GEOMETRY that NO extractor in this tool can separate
// from prose, so they must not be fed to the text validators.
//
// The rule is about the EXTRACTOR, not the format. The original list also held .svg,
// on the reasoning that an .svg is XML text and the byte-sniffing text path claims it
// happily -- so admitting it fed coordinate soup to every validator. That measurement
// was real. Re-measured at 9046dae on a 75KB SVG built from integer-coordinate glyph
// paths, the shape real icon and font SVGs carry:
//
//	1,313 findings: PHONE 1,143 (162 HIGH), SSN 87, CREDIT_CARD 83,
//	SSN 3 HIGH + 73 LOW  --  every one of them path coordinates
//
// (The two example strings this comment used to show, "43.5968 15.4721 43.4928 15.7281
// 43.3048 15.9" and "38.9358 20.3361 37.5138 18.9301 40.1318 16.2", produce ZERO
// findings at a0e983c: #443/PR #445 taught the identifier-adjacency guard to treat "."
// as a boundary, which removed the 4-decimal shape. Anyone probing with them would have
// concluded the flood was fixed. The integer form above is what still fires --
// "0 863 76 1012 109", lifted from a real glyph path, is one SSN HIGH 100 on its own.)
//
// But excluding the part is not what removes the flood, and it costs the coverage. The
// cost, measured: the same drawing carrying an SSN, an email, a name and a phone in its
// <text>, <title> and <desc> nodes reported 4 findings standalone and 0 embedded in a
// .docx -- exit 0, nothing on stderr, exit 0 again under --fail-on-incomplete, and no
// redacted copy written at all. Since only reported findings reach the redactor, that is
// a cleartext leak, not merely a gap.
//
// .svg was therefore REMOVED from this list and given the extractor the old comment
// asked for (internal/preprocessors/text-extractors/text-extract-svgtextlib): it
// collects only prose-bearing nodes and attributes, so the digits that caused the flood
// are never handed to a validator. Measured after: the 75KB glyph-path SVG reports 0
// findings of any type embedded or standalone, and the <text>-carrying part reports its
// 4. See #314.
//
// The three that remain are BINARY metafiles with no text reader anywhere in this tool.
// Admitting them would make a part reach a preprocessor and extract nothing, which is
// worse than the exclusion: "Success, 0 findings" is indistinguishable from a clean
// file, whereas an excluded part is at least an excluded part. They stay out until they
// get comparable treatment.
var vectorGraphicsExts = map[string]bool{
	".emf": true, // Enhanced Metafile: binary drawing records, no text reader
	".wmf": true, // Windows Metafile: same
	".wdp": true, // JPEG XR / HD Photo: binary raster, no metadata reader
}

// SkipTextPipeline reports whether a part holds drawing geometry rather than prose, and
// so must not be routed to the text validators.
func SkipTextPipeline(name string) bool {
	return vectorGraphicsExts[strings.ToLower(filepath.Ext(name))]
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

// zipBackedExts are the admitted extensions whose content is stored INSIDE a zip
// archive, so that inspecting such a part's bytes requires the archive to open.
//
// Only the OOXML forms qualify among the admitted types. Images, audio and legacy OLE
// store their text uncompressed and are readable as a flat byte range; PDF is compressed
// but is handled by opaqueExts, which is a stronger statement.
var zipBackedExts = map[string]bool{
	".docx": true, ".xlsx": true, ".pptx": true,
}

// ContentInspectable reports whether a part's bytes can ACTUALLY be inspected, given
// the bytes.
//
// ResidueInspectable answers the same question from the name alone, and for a zip-backed
// type its answer rests on a premise: that the residue scan can inflate the archive's
// members. When the archive will not open, that premise fails — the scan reads only the
// compressed bytes, finds nothing, and the caller reads "nothing found" as "holds none of
// the reported values". So an unopenable OOXML part is not inspectable, whatever its
// extension says, and must be treated the way PDF is: always dispatched, and refused
// rather than written if no redactor can rewrite it.
//
// Measured on a real .docx carrying word/embeddings/attach.docx whose bytes begin with the
// zip magic but are not a readable archive: the scan could not parse it, so the value
// inside was never REPORTED, so it was absent from the redaction value set, so the residue
// scan was not looking for it, so the part was skipped and copied through verbatim — a
// "redacted" document shipping cleartext at exit 0. The scan disclosed the part as not
// examined (#404) and the write side had no way to act on it. See #517.
//
// A part whose extension is not zip-backed is unaffected: the answer collapses to
// ResidueInspectable, so nothing else changes shape.
func ContentInspectable(name string, content []byte) bool {
	if !ResidueInspectable(name) {
		return false
	}
	if !zipBackedExts[strings.ToLower(filepath.Ext(name))] {
		return true
	}
	// An empty or truncated part cannot be an archive either, and zip.NewReader is the
	// same reader the residue scan uses, so this asks exactly the question the scan's
	// premise depends on.
	if _, err := zip.NewReader(bytes.NewReader(content), int64(len(content))); err != nil {
		return false
	}
	return true
}

// ResidueInspectable reports whether scanning a part's raw bytes for a value is a
// sound test for that value's ABSENCE.
//
// Judged from the NAME alone. For a zip-backed type the answer is conditional on the
// archive opening — see ContentInspectable, which callers holding the bytes should prefer.
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
