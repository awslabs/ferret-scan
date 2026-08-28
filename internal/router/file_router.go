// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// FileRouter handles file routing and preprocessing decisions
type FileRouter struct {
	registry      *PreprocessorRegistry
	preprocessors []preprocessors.Preprocessor
	metrics       *RouterMetrics
	logger        *DebugLogger
	observer      observability.Observer

	// embeddedDepth records how deep each in-flight file sits inside a container,
	// keyed by the path handed to ProcessEmbedded. Absent means top level (0).
	//
	// This lives on the ROUTER because nothing else can hold it: one preprocessor
	// instance is shared across concurrent workers, and Preprocessor.Process takes no
	// context to thread a depth through. A mutex-protected map keyed on path is the
	// mechanism a stale comment in base_metadata_preprocessor.go used to CLAIM
	// existed (citing a FileRouter.noteEmbeddedChild that was never written); this is
	// that mechanism, actually written. See #297.
	//
	// Entries are removed when the child finishes, so the map holds only the files
	// currently being processed rather than growing across a directory scan.
	embeddedDepthMu sync.Mutex
	embeddedDepth   map[string]int

	// traversalBudget records the whole-traversal byte budget each in-flight file
	// belongs to, keyed the same way embeddedDepth is.
	//
	// It lives beside the depth for the same reason and rides on the same fact: a
	// path identifies one in-flight file, because the top level's paths are distinct
	// and every embedded part is materialised under a freshly named temp file. The
	// TOP-LEVEL file creates the entry and releases it when it finishes; a child
	// inherits its parent's Budget rather than making one, which is what turns a
	// per-container allowance into a per-file one. See #474.
	traversalBudgetMu sync.Mutex
	traversalBudget   map[string]*embedded.Budget
}

// MaxEmbeddedDepth bounds how deep the router follows containers inside containers.
//
// Without a bound, admitting embedded OOXML documents is a decompression-bomb
// amplifier: an embedded .docx routes back through the Office preprocessor, which
// extracts ITS embeddings, which route back again. Measured previously with a 7KB
// .docx that embeds itself nine times: all nine levels were followed, with nothing to
// stop a file declaring more.
//
// Three levels covers every legitimate shape observed (a report with an attached
// workbook that itself has an embedded image) with margin. Reaching the bound is
// DISCLOSED, not silently skipped -- see ErrEmbeddedTooDeep.
//
// Defined in package embedded rather than here, because the REDACTION side needs the
// same bound and must not carry its own copy. A write side shallower than the read
// side reports findings from a level it will not rewrite -- a cleartext leak that
// reads as success -- and a write side deeper than the read side redacts in a place
// nothing scanned. The earlier attempt at this mirrored the literal 3 in
// internal/redactors/office and added a test asserting the two stayed equal; sharing
// one constant makes the drift impossible instead of merely detected.
const MaxEmbeddedDepth = embedded.MaxDepth

// MaxFileSize is the ceiling for a file whose whole content is read (100 MB).
//
// It is the default for every type, and the right default: a preprocessor that has to
// hold a document in memory to make sense of it — an Office ZIP, a PDF, a plaintext file
// — costs memory proportional to the file, so the size of the input IS the bound on the
// work. MaxSizeForPath is what exempts the one family where that is not true.
const MaxFileSize = int64(100 * 1024 * 1024)

// MaxVideoFileSize is the ceiling for a video container (500 MB).
//
// A video is the one type this tool reads WITHOUT holding it: the extractor parses the
// `moov` box and seeks past `mdat`, so its memory is O(min(|moov|, MaxMoovParse)) and
// independent of the file's length. Both downstream video gates have said 500 MB since
// they were written — meta-extract-videolib.MaxFileSize and
// preprocessors.DefaultResourceLimits().MaxVideoFileSize — and neither was reachable,
// because every file met the flat 100 MB gate first and was refused there (#410).
//
// Measured on real files rather than assumed, scanning each with the gate raised:
//
//	file                                       size      peak RSS   wall
//	macOS "Tahoe Day.mov" wallpaper            162 MB    29.0 MB    1.12s
//	GarageBand "Piano Lesson 1" media          150 MB    28.8 MB    0.37s
//	macOS aerial wallpaper .mov                453 MB    29.5 MB    0.39s
//
// Peak RSS is FLAT in file size — 29 MB for a 453 MB file — which is what makes this
// exemption safe rather than merely useful. A gate exists to bound resource use, and for
// this type the file's size was never what bounded it. Compare the 162 MB case, whose
// `moov` sits LAST at byte 169,820,847: the extractor still reaches it, so admitting the
// file is not vacuous.
//
// Deliberately NOT extended to audio. Discovery once allowed 500 MB for .mp3/.wav/.m4a/
// .flac and it bought nothing: audio metadata is capped at 100 MB by three more gates
// downstream, and measured on 150 MB and 450 MB files, raising the ceiling alone yielded
// zero additional findings. That allowance only decided which counter recorded the miss,
// which is the bug #355 fixed by REMOVING it. Video is the opposite case: here the
// downstream ceilings are already 500 MB and it is only the front gate that refuses.
const MaxVideoFileSize = int64(500 * 1024 * 1024)

// videoSizeClass answers "is this path a video container", and is the SAME answer the
// routing decision uses — preprocessors.VideoMetadataPreprocessor.CanProcess consults
// this type too.
//
// A package-level value rather than a per-call constructor: MaxSizeForPath is called once
// per discovered file, and NewFileExtensionValidator builds five maps, so constructing one
// per call would put five allocations on every entry of a directory walk.
// TestMaxSizeForPathDoesNotAllocate pins that.
var videoSizeClass = preprocessors.NewFileExtensionValidator()

// MaxSizeForPath returns the largest size the tool will admit for path.
//
// One function rather than a constant per gate, because this repository has twice shipped
// a bug caused by two size gates disagreeing: discovery once allowed 500 MB where the
// router allowed 100 MB, and the router's refusal landed in the counter that names an
// unsupported TYPE, so a file the tool never opened was reported as a clean scan (#355).
// Every gate consults this, so the numbers cannot drift apart.
//
// The extension is the whole test, and it decides only how many bytes we are willing to
// admit — never how the file is parsed. A .mp4 that is not really a video is admitted at
// 500 MB and then read by the same extractor as before, which rejects it on its box
// structure. So the worst a misleading extension buys is a bounded read of a file the
// operator already has, and never a different parse.
func MaxSizeForPath(path string) int64 {
	if videoSizeClass.IsVideoFile(path) {
		return MaxVideoFileSize
	}
	return MaxFileSize
}

// NewFileRouter creates a new file router
func NewFileRouter(debug bool) *FileRouter {
	level := observability.ObservabilityMetrics
	if debug {
		level = observability.ObservabilityDebug
	}
	return &FileRouter{
		registry:      NewPreprocessorRegistry(),
		preprocessors: make([]preprocessors.Preprocessor, 0),
		metrics:       NewRouterMetrics(),
		logger:        NewDebugLogger(debug, os.Stderr),
		observer:      observability.NewStandardObserver(level, os.Stderr),
	}
}

// RegisterPreprocessor adds a preprocessor factory to the registry
func (fr *FileRouter) RegisterPreprocessor(name string, factory PreprocessorFactory) {
	fr.registry.Register(name, factory)
}

// InitializePreprocessors creates and registers all preprocessors
func (fr *FileRouter) InitializePreprocessors(config map[string]interface{}) {
	fr.preprocessors = fr.registry.CreateAll(config)
}

// ReasonUnreadable prefixes the reason returned when a file exists but cannot be
// opened or stat'ed — a permission error, a broken symlink, a vanished file.
//
// It is deliberately distinct from "Unsupported file type". Those two are opposite
// facts: an unsupported type is a file we looked at and chose not to scan, while an
// unreadable file is one we never saw. Reporting the second as the first tells the
// user their .txt is an unrecognized format and invites them to ignore it — when in
// truth a file that may be full of PII went unscanned. Callers can test for this
// prefix to separate "nothing to find here" from "we could not look".
const ReasonUnreadable = "Unreadable"

// CanProcessFile determines if a file can be processed. The second return value is
// a human-readable reason; when it begins with ReasonUnreadable the file was not
// examined at all, as opposed to examined and skipped.
func (fr *FileRouter) CanProcessFile(filePath string, enablePreprocessors bool) (bool, string) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check file size. A stat error here is the first sign the file cannot be read
	// (permissions, a dangling symlink, a race with deletion). Previously it was
	// swallowed by `err == nil` and execution fell through to the generic
	// "Unsupported file type" at the bottom of this function.
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return false, fmt.Sprintf("%s: %v", ReasonUnreadable, err)
	}

	// Refuse anything that is not a regular file.
	//
	// This is an operational bound, not a security boundary: a character device, a
	// FIFO, a socket or a kernel pseudo-file has no meaningful size, so the size
	// gate below cannot bound it. Opening /dev/zero or a FIFO with no writer means
	// reading forever, and the extractors downstream read the whole file into memory.
	//
	// It replaces a prefix denylist that used to live in the Office metadata
	// extractor and refused /proc/, /sys/, /dev/ by name. A mode check is both wider
	// and narrower in the right directions: it covers block and character devices,
	// FIFOs and sockets on every platform, including the Windows device namespace
	// (\\.\PhysicalDrive0) and reserved DOS names that a Unix-shaped path denylist
	// never matched — while it does NOT reject the ordinary files that happen to sit
	// under one of those prefixes. /dev/shm is the case that matters: it is
	// world-writable tmpfs, routinely used for temporary files by scripts and CI, and
	// the files in it are regular files. A path denylist rejected them; this does not.
	//
	// It lives here because the router is where "can this file be processed" is
	// decided, and it already has the stat. The extractors get a path this function
	// has already vetted, so each of the seven no longer needs its own copy of the
	// rule — only one of them ever had one.
	if !info.Mode().IsRegular() {
		return false, fmt.Sprintf("%s: not a regular file (%s)", ReasonUnreadable, DescribeFileMode(info.Mode()))
	}

	// The limit is per TYPE, and the message is built from the same value that refused,
	// so the number an operator reads cannot disagree with the number that stopped the
	// file. See MaxSizeForPath.
	if limit := MaxSizeForPath(filePath); info.Size() > limit {
		return false, fmt.Sprintf("File too large (max: %dMB)", limit/(1024*1024))
	}

	// Binary documents require preprocessors
	if isBinaryDocument(ext) {
		if enablePreprocessors {
			return true, "Binary document"
		}
		return false, "Binary document (requires preprocessors)"
	}

	// Check if it's a text file. Distinguish "read it, it is not text" from "could
	// not read it": the old condition (err == nil && isText) collapsed both into
	// the unsupported-type reason below, so a permission-denied .txt was reported
	// as an unrecognized file format.
	isText, err := isTextFile(filePath)
	if err != nil {
		return false, fmt.Sprintf("%s: %v", ReasonUnreadable, err)
	}
	if isText {
		return true, "Text file"
	}

	return false, "Unsupported file type"
}

// CanProcessType reports whether this path's TYPE is one the router would process,
// ignoring the file's size.
//
// CanProcessFile cannot answer this question. Its own size gate returns
// "File too large" before the type is ever considered, so asking it about an
// oversize file is circular.
//
// The caller that needs it is the discovery-time decision of whether a file refused
// for size is worth telling the user about. That decision used to be a hardcoded
// 11-extension list duplicated at two call sites, which made the tool quiet about a
// few known-big binary types and noisy about everything else — including files it
// could never have scanned at any size, and including browser partial downloads
// whose random suffixes no extension list can ever cover. The right question is not
// "is this one of eleven names" but "would we have processed it at all", which is
// this. Same correction as deriving embedded-part handling from capability rather
// than from a hand-maintained list.
//
// Note this returns true for video and audio, when preprocessors are enabled: the
// tool extracts and scans their METADATA, so an oversize video that went unscanned
// is a genuine coverage loss, not a non-event.
//
// Cost is bounded regardless of file size: the text branch sniffs at most the first
// 512 bytes.
func CanProcessType(filePath string, enablePreprocessors bool) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Binary documents (office, pdf, image, video, audio) are processable exactly
	// when preprocessors are available to handle them.
	if isBinaryDocument(ext) {
		return enablePreprocessors
	}

	// Anything else is processable only if it sniffs as text. An unreadable file is
	// reported as not-processable here: the caller is deciding whether to mention a
	// SIZE refusal, and a file that also cannot be opened is a separate diagnostic
	// raised through the unreadable channel.
	isText, err := isTextFile(filePath)
	if err != nil {
		return false
	}
	return isText
}

// DescribeFileMode names the non-regular kind a path turned out to be, so the skip
// reason tells the user what they actually pointed at rather than only that it was
// rejected. Directories are included because a caller can hand a directory path to a
// single-file scan.
//
// Exported because the directory WALK needs the same words for the same decision
// (#485). It previously dropped a non-regular entry with no record at all, and giving
// cmd its own copy of this switch is how the two would drift into describing the same
// object differently. The partition is exhaustive by construction rather than by
// enumeration: os.FileMode.IsRegular() is true iff no type bit is set, so an object type
// Go learns to report later reaches the default arm and is NAMED rather than dropped --
// which is also what handles a Windows junction, reported as ModeIrregular.
func DescribeFileMode(m os.FileMode) string {
	switch {
	case m.IsDir():
		return "directory"
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m&os.ModeNamedPipe != 0:
		return "named pipe"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeCharDevice != 0:
		return "character device"
	case m&os.ModeDevice != 0:
		return "block device"
	case m&os.ModeIrregular != 0:
		return "irregular file"
	default:
		return m.String()
	}
}

// ProcessFileWithContext processes a file through the routing system with full context
func (fr *FileRouter) ProcessFileWithContext(filePath string, config *ProcessingContext) (*preprocessors.ProcessedContent, error) {
	return fr.processFileInternal(filePath, config)
}

// ProcessFile processes a file through the routing system (interface method)
// ProcessEmbedded processes a child file extracted OUT OF parentPath, enforcing
// MaxEmbeddedDepth.
//
// The caller (a metadata preprocessor, via RouterInterface) knows its own path -- that
// is the argument its Process received -- so passing it as parentPath is all the router
// needs to compute the child's depth. That avoids threading a depth through
// Preprocessor.Process, which would touch every preprocessor for the benefit of the two
// that recurse.
//
// Returns ErrEmbeddedTooDeep at the bound. The caller must DISCLOSE that: refusing to
// descend is incomplete coverage, and this whole change exists because undisclosed
// missing coverage reads as a clean result.
func (fr *FileRouter) ProcessEmbedded(childPath, parentPath string) (*preprocessors.ProcessedContent, error) {
	depth := fr.depthOf(parentPath) + 1
	if depth > MaxEmbeddedDepth {
		return nil, fmt.Errorf("%w: %s is nested %d levels deep (limit %d)",
			preprocessors.ErrEmbeddedTooDeep, filepath.Base(childPath), depth, MaxEmbeddedDepth)
	}

	fr.setDepth(childPath, depth)
	// Removed when this child finishes, so the map tracks only in-flight files.
	defer fr.clearDepth(childPath)

	// Inherit the parent's whole-traversal budget, so every descendant of one
	// top-level file draws from a single allowance.
	//
	// Nil when the parent is not tracked — a test calling ProcessEmbedded directly,
	// for instance. That degrades to the old per-container behaviour rather than
	// failing, and processFileInternal will not manufacture a second budget for a
	// child, because a child's bytes have already been charged by whoever extracted
	// it. Giving it a fresh one is exactly the amplification being removed.
	fr.setBudget(childPath, fr.budgetOf(parentPath))
	defer fr.clearBudget(childPath)

	return fr.ProcessFile(childPath, nil)
}

// EmbeddedBudget returns the whole-traversal budget the given in-flight file belongs
// to, or nil if it is not tracked.
//
// The preprocessor asks for this by its OWN path — the argument its Process received
// — exactly as it passes that path to ProcessEmbedded. That keeps the budget off the
// Preprocessor interface, which one shared instance across concurrent workers could
// not carry anyway.
func (fr *FileRouter) EmbeddedBudget(path string) *embedded.Budget {
	return fr.budgetOf(path)
}

// EmbeddedDepthOf reports how deep an in-flight file sits inside containers.
//
// Exposed so a preprocessor can decline to MATERIALISE parts it already knows the
// router will refuse to descend into. MaxEmbeddedDepth is enforced in
// ProcessEmbedded, which runs only after each part has been written to temp, so the
// deepest level's bytes were inflated, written and then thrown away. Asking first
// turns that into no I/O at all.
func (fr *FileRouter) EmbeddedDepthOf(path string) int {
	return fr.depthOf(path)
}

func (fr *FileRouter) budgetOf(path string) *embedded.Budget {
	fr.traversalBudgetMu.Lock()
	defer fr.traversalBudgetMu.Unlock()
	return fr.traversalBudget[path]
}

// setBudget associates a path with a traversal budget. A nil budget is recorded as
// an explicit entry, so budgetOf cannot tell "absent" from "known to be untracked" —
// which is what stops processFileInternal handing a child a fresh allowance.
func (fr *FileRouter) setBudget(path string, b *embedded.Budget) {
	fr.traversalBudgetMu.Lock()
	defer fr.traversalBudgetMu.Unlock()
	if fr.traversalBudget == nil {
		fr.traversalBudget = make(map[string]*embedded.Budget)
	}
	fr.traversalBudget[path] = b
}

func (fr *FileRouter) hasBudgetEntry(path string) bool {
	fr.traversalBudgetMu.Lock()
	defer fr.traversalBudgetMu.Unlock()
	_, ok := fr.traversalBudget[path]
	return ok
}

// clearBudget releases the entry. Without this a directory scan would accumulate one
// entry per file, and — far worse — a re-scanned path would inherit an EXHAUSTED
// budget and report clean.
func (fr *FileRouter) clearBudget(path string) {
	fr.traversalBudgetMu.Lock()
	defer fr.traversalBudgetMu.Unlock()
	delete(fr.traversalBudget, path)
}

// depthOf reports how deep a path sits inside containers. Absent = top level.
func (fr *FileRouter) depthOf(path string) int {
	fr.embeddedDepthMu.Lock()
	defer fr.embeddedDepthMu.Unlock()
	return fr.embeddedDepth[path]
}

func (fr *FileRouter) setDepth(path string, depth int) {
	fr.embeddedDepthMu.Lock()
	defer fr.embeddedDepthMu.Unlock()
	if fr.embeddedDepth == nil {
		fr.embeddedDepth = make(map[string]int)
	}
	fr.embeddedDepth[path] = depth
}

func (fr *FileRouter) clearDepth(path string) {
	fr.embeddedDepthMu.Lock()
	defer fr.embeddedDepthMu.Unlock()
	delete(fr.embeddedDepth, path)
}

func (fr *FileRouter) ProcessFile(filePath string, config interface{}) (*preprocessors.ProcessedContent, error) {
	if ctx, ok := config.(*ProcessingContext); ok {
		return fr.processFileInternal(filePath, ctx)
	}
	// Create minimal context if none provided
	ctx := &ProcessingContext{FilePath: filePath}
	return fr.processFileInternal(filePath, ctx)
}

// processFileInternal is the actual implementation
func (fr *FileRouter) processFileInternal(filePath string, config *ProcessingContext) (*preprocessors.ProcessedContent, error) {
	// A TOP-LEVEL file opens a whole-traversal budget and closes it again when it
	// finishes; everything nested inside draws from that one allowance.
	//
	// The test for "top level" is the absence of an entry: ProcessEmbedded records one
	// for every child before routing it, so only a file that arrived here directly has
	// none. Releasing it on the way out is what keeps the bound per-file — a budget
	// that survived the file would make the SECOND file in a directory scan report
	// clean because the first one spent the allowance.
	if !fr.hasBudgetEntry(filePath) {
		fr.setBudget(filePath, embedded.NewBudget())
		defer fr.clearBudget(filePath)
	}

	// Use standardized observability
	finishTiming := fr.observer.StartTiming("router", "file_evaluation", config.FilePath)
	defer finishTiming(true, map[string]interface{}{
		"file_size": config.FileSize,
		"file_ext":  config.FileExt,
	})

	// A 0-byte file is not a FAILURE, it is a file with nothing in it.
	//
	// Checked FIRST, before preprocessor selection, because size 0 is decidable
	// without consulting any preprocessor — and because both later exits reject it
	// otherwise: "no preprocessor can handle file" when the extension is unregistered,
	// and "all preprocessors failed" when every capable one declines the empty input.
	// An earlier version of this fix only covered the second, so it worked through the
	// CLI (where .csv has a preprocessor) and still failed for an empty file of an
	// unregistered type. A unit test with a bare router caught that.
	//
	// The CLI surfaced either error as:
	//
	//	NOT EXAMINED: 1 of 1 file — contents were never read, so findings may be missing
	//
	// and made --fail-on-incomplete exit 3. All of that is false: the contents WERE
	// read, there are none, and an empty file cannot hold sensitive data. False alarms
	// are how the warning that matters becomes noise an operator filters out — and it
	// shares a channel with the warning that says a file full of PII went unexamined.
	if fi, statErr := os.Stat(filePath); statErr == nil && fi.Size() == 0 {
		return &preprocessors.ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          "",
			ProcessorType: "empty_file",
			Success:       true,
		}, nil
	}

	// Find capable preprocessors
	var capable []preprocessors.Preprocessor
	for _, p := range fr.preprocessors {
		if p.CanProcess(filePath) {
			capable = append(capable, p)
		}
	}

	if len(capable) == 0 {
		return nil, fmt.Errorf("no preprocessor can handle file: %s", filePath)
	}

	// Sort by name so the assembly order below is a property of the file type,
	// not of how the registry happened to be iterated. For Office and PDF files
	// this puts "Text Extractor" ahead of "office_metadata"/"pdf_metadata", so
	// the document body is the leading section and each metadata block carries
	// an explicit "--- name ---" header.
	sort.Slice(capable, func(i, j int) bool {
		return capable[i].GetName() < capable[j].GetName()
	})

	// Run ALL capable preprocessors in parallel
	type preprocessorResult struct {
		idx      int
		name     string
		result   *preprocessors.ProcessedContent
		err      error
		duration time.Duration
	}

	resultChan := make(chan preprocessorResult, len(capable))

	// Start all preprocessors in parallel
	for i, p := range capable {
		go func(idx int, processor preprocessors.Preprocessor) {
			processStart := time.Now()

			// Recover from any panics in preprocessors to prevent crashing the whole scan
			var result *preprocessors.ProcessedContent
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("preprocessor panic in %s: %v", processor.GetName(), r)
					}
				}()
				result, err = processor.Process(filePath)
			}()

			processingTime := time.Since(processStart)

			resultChan <- preprocessorResult{
				idx:      idx,
				name:     processor.GetName(),
				result:   result,
				err:      err,
				duration: processingTime,
			}
		}(i, p)
	}

	// Collect results.
	//
	// Drain into a slice indexed by LAUNCH position, not by arrival position.
	// Preprocessors run concurrently, so consuming the channel in completion
	// order made the assembled text — and therefore every line number reported
	// against it — depend on which goroutine won the race. For a .docx both
	// "Text Extractor" and "office_metadata" are capable, so the metadata block
	// landed above or below the body at random, and findings shifted by the
	// height of that block between two scans of the same file (issue #179).
	//
	// The overwhelmingly common case is a single successful preprocessor (one
	// file type → one extractor). For that case we must NOT copy the extracted
	// text a second time: a strings.Builder.WriteString duplicates the whole
	// payload into the builder's buffer (a full second copy of, e.g., a 10 MB
	// extracted PDF), even though String() itself is zero-copy. So we keep a
	// direct reference to the sole result's text (firstText) and only fall back
	// to the strings.Builder when a SECOND successful preprocessor arrives and
	// we genuinely have to concatenate with separators. The builder path emits
	// the first successful text, then "\n\n--- name ---\n" + text for each
	// subsequent processor, in sorted-name order; the single-processor path
	// yields Text == firstText exactly, since no separator is prepended to the
	// first write. (v2 gap 2.3: eliminate the combine-step second copy.)
	ordered := make([]preprocessorResult, len(capable))
	for i := 0; i < len(capable); i++ {
		pResult := <-resultChan
		ordered[pResult.idx] = pResult
	}

	var combinedContent strings.Builder
	var firstText string
	var combinedMetadata = make(map[string]interface{})
	var totalWordCount, totalCharCount, totalLineCount int
	var successfulProcessors []string
	// extractionWarnings collects each preprocessor's "read the file but got no
	// document text" note, in launch order so the message is stable.
	//
	// Deliberately gathered regardless of pResult.err. The note is set by the
	// extractor that produced no text, and for the most important case — the body
	// part is absent from the archive entirely — that extractor ALSO returns an
	// error ("document.xml not found in the archive"). Requiring err == nil dropped
	// the warning exactly when it mattered: a .docx with no recognizable body part
	// still had a successful office_metadata sibling, so the file reported Success
	// with metadata-only findings, exit 0, and nothing said the document body had
	// never been read. Measured before this: such a file produced
	// {PERSON_NAME, AUTHOR_INFO} and no warning at all.
	var extractionWarnings []string
	// sections records the structure of the concatenation OUT OF BAND, one entry
	// per successful preprocessor, built in this same loop so it cannot drift from
	// the text it describes.
	//
	// The name comes from Preprocessor.GetName(), which is our own code's constant
	// — not a byte from the scanned document. That is what makes a boundary here
	// unforgeable, and it is the whole reason for this field: the content router
	// used to recover this same structure by scanning the assembled text for
	// "--- name ---" lines, which a document author can simply type.
	//
	// sectionLine tracks where the next section starts, as a line index into the
	// text assembled so far, so it is maintained incrementally rather than by
	// re-scanning the (potentially multi-megabyte) result.
	var sections []preprocessors.ContentSection
	var extractionCauses []coverage.Cause
	sectionLine := 0

	for _, pResult := range ordered {
		if pResult.result != nil && pResult.result.ExtractionWarning != "" {
			// Prefix ONCE. An embedded container routes back through this same function,
			// and each level used to add its own copy, so a note from four levels down
			// reached the operator as
			//
			//	office_metadata: office_metadata: office_metadata: office_metadata: embedded item …
			//
			// The name is here to say which reader produced the note; repeating it says
			// nothing more and pushes the part that matters off the line.
			warning := pResult.result.ExtractionWarning
			if !strings.HasPrefix(warning, pResult.name+": ") {
				warning = pResult.name + ": " + warning
			}
			extractionWarnings = append(extractionWarnings, warning)
			// Carry the producer's cause alongside its note. Collecting them per preprocessor and
			// reducing once is the only way the cause survives the join below: the segments become
			// one string, and inferring a cause back out of that string is the guess this replaces.
			extractionCauses = append(extractionCauses, pResult.result.ExtractionCause)
		}
		if pResult.err == nil && pResult.result != nil && pResult.result.Success && pResult.result.Text != "" {
			if len(successfulProcessors) == 0 {
				// First success: reference its text directly (no copy).
				firstText = pResult.result.Text
			} else {
				// Second+ success: we are truly combining. Flush the stashed
				// first text into the builder once, then append this one with a
				// separator.
				if combinedContent.Len() == 0 {
					combinedContent.WriteString(firstText)
				}
				combinedContent.WriteString("\n\n--- " + pResult.name + " ---\n")
				combinedContent.WriteString(pResult.result.Text)
				// The separator "\n\n--- name ---\n" advances the line cursor by 3
				// (it closes the previous section's last line, adds a blank line,
				// and adds the header line itself).
				sectionLine += 3
			}

			// Prefer the preprocessor's OWN declared sections. A metadata
			// extractor can carry sub-structure the router cannot see: the Office
			// extractor appends each embedded media item's text to its own, and
			// those items route to a DIFFERENT metadata rule set (a .wav inside a
			// .docx has an "Artist:" field, which is on the audio field list but
			// not the office one). Only that extractor knows where the split is,
			// so re-anchor what it declared instead of overwriting it with one
			// coarse section.
			if declared := pResult.result.Sections; len(declared) > 0 {
				for _, s := range declared {
					if s.SourceFile == "" {
						s.SourceFile = filePath
					}
					s.LineOffset += sectionLine
					sections = append(sections, s)
				}
			} else {
				kind, metaType := preprocessors.ClassifySection(pResult.name)
				sections = append(sections, preprocessors.ContentSection{
					Name:       pResult.name,
					Kind:       kind,
					Type:       metaType,
					SourceFile: filePath,
					// A substring reference, not a copy: Go strings share backing
					// storage, so recording every section costs pointers, not bytes.
					Text:       pResult.result.Text,
					LineOffset: sectionLine,
				})
			}
			sectionLine += strings.Count(pResult.result.Text, "\n")

			// Accumulate metadata
			for k, v := range pResult.result.Metadata {
				combinedMetadata[pResult.name+"_"+k] = v
			}

			// Accumulate counts
			totalWordCount += pResult.result.WordCount
			totalCharCount += pResult.result.CharCount
			totalLineCount += pResult.result.LineCount

			successfulProcessors = append(successfulProcessors, pResult.name)
		}
	}

	// Return combined results if any preprocessor succeeded
	if len(successfulProcessors) > 0 {
		combinedMetadata["successful_processors"] = successfulProcessors
		// Single successful processor → use its text directly (zero extra copy);
		// multiple → the builder holds the byte-identical concatenation.
		text := firstText
		if combinedContent.Len() > 0 {
			text = combinedContent.String()
		}
		result := &preprocessors.ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          text,
			Format:        "combined",
			WordCount:     totalWordCount,
			CharCount:     totalCharCount,
			LineCount:     totalLineCount,
			ProcessorType: strings.Join(successfulProcessors, "+"),
			Success:       true,
			Metadata:      combinedMetadata,
			// Carry the warnings up. Without this the combine step swallowed them:
			// a .docx whose body part was never found still had a successful
			// office_metadata result, so the file reported Success with only
			// metadata findings and nothing said the document body was missing.
			ExtractionWarning: strings.Join(extractionWarnings, "; "),
			ExtractionCause:   coverage.Reduce(extractionCauses),
			// The out-of-band structure of Text. Set unconditionally on this
			// success path so the content router never has to fall back to
			// re-parsing the text for separators.
			Sections: sections,
		}

		return result, nil
	}

	return nil, fmt.Errorf("all preprocessors failed for file: %s", filePath)
}

// CreateProcessingContext creates a standardized processing context for a file.
func (fr *FileRouter) CreateProcessingContext(filePath string, debug bool) (*ProcessingContext, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	requestID := generateRequestID()

	return &ProcessingContext{
		FilePath:    filePath,
		FileSize:    info.Size(),
		FileExt:     strings.ToLower(filepath.Ext(filePath)),
		MaxFileSize: MaxFileSize,
		RequestID:   requestID,
		StartTime:   time.Now(),
		Debug:       debug,
		metrics:     fr.metrics,
		logger:      fr.logger,
	}, nil
}

// GetMetrics returns current router metrics
func (fr *FileRouter) GetMetrics() *RouterMetrics {
	return fr.metrics
}

// GetPreprocessorCount returns the number of registered preprocessors
func (fr *FileRouter) GetPreprocessorCount() int {
	return len(fr.preprocessors)
}

// CanContainMetadata determines if a file type can contain meaningful metadata
func (fr *FileRouter) CanContainMetadata(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	canContain := isMetadataCapableFile(ext)

	// Debug logging for file type detection decisions
	if fr.observer != nil && fr.observer.Debug() != nil {
		fr.observer.Debug().LogDetail("file_type_detection",
			fmt.Sprintf("File: %s, Extension: %s, CanContainMetadata: %t",
				filepath.Base(filePath), ext, canContain))
	}

	return canContain
}

// GetMetadataType returns the preprocessor-specific metadata type for a file
func (fr *FileRouter) GetMetadataType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	metadataType := getMetadataTypeForExtension(ext)

	// Debug logging for metadata type detection
	if fr.observer != nil && fr.observer.Debug() != nil {
		fr.observer.Debug().LogDetail("metadata_type_detection",
			fmt.Sprintf("File: %s, Extension: %s, MetadataType: %s",
				filepath.Base(filePath), ext, metadataType))
	}

	return metadataType
}

// Helper functions

// extValidator is the SINGLE source of truth for which extensions the metadata
// preprocessors actually handle. The router's routing gate (isBinaryDocument /
// isMetadataCapableFile / getMetadataTypeForExtension) delegates to it so the
// gate can never claim to process an extension that no preprocessor supports.
//
// Previously the router carried its own broader hardcoded list (adding e.g.
// .heic/.doc/.avi/.ogg) that had DRIFTED from what the preprocessors' own
// FileExtensionValidator recognizes. A .heic file passed the gate, then reached
// processFileInternal where every preprocessor's CanProcess returned false,
// producing a mid-pipeline "no preprocessor can handle file" error instead of a
// clean "unsupported file type" skip. Deriving the gate from the same validator
// the preprocessors use removes that drift (v2 gap 5.3).
var extValidator = preprocessors.NewFileExtensionValidator()

// extProbe turns a bare extension (".heic") into a filename the
// FileExtensionValidator's path-based predicates can inspect (its Is*File
// methods run filepath.Ext internally, which returns "" for a bare ".heic").
func extProbe(ext string) string { return "f" + ext }

func isBinaryDocument(ext string) bool {
	p := extProbe(ext)
	return extValidator.IsOfficeFile(p) ||
		extValidator.IsPDFFile(p) ||
		extValidator.IsImageFile(p) ||
		extValidator.IsVideoFile(p) ||
		extValidator.IsAudioFile(p)
}

// isMetadataCapableFile determines if a file extension indicates metadata capability
// This reuses the existing isBinaryDocument logic as these files can contain metadata
func isMetadataCapableFile(ext string) bool {
	return isBinaryDocument(ext)
}

// getMetadataTypeForExtension returns the specific metadata type for preprocessor
// routing, keyed off the shared FileExtensionValidator. The returned strings are
// the same the specialized preprocessors identify with (office/document/image/
// video/audio_metadata); "none" for anything no preprocessor handles.
func getMetadataTypeForExtension(ext string) string {
	p := extProbe(ext)
	switch {
	case extValidator.IsOfficeFile(p):
		return "office_metadata"
	case extValidator.IsPDFFile(p):
		return "document_metadata"
	case extValidator.IsImageFile(p):
		return "image_metadata"
	case extValidator.IsVideoFile(p):
		return "video_metadata"
	case extValidator.IsAudioFile(p):
		return "audio_metadata"
	default:
		return "none"
	}
}

func isTextFile(filePath string) (bool, error) {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		// An empty file is readable, not unreadable. Read returns io.EOF with
		// n == 0 for a zero-byte file, and reporting that as an error made the
		// caller classify it as ReasonUnreadable — which surfaces as the alarming
		// "could not be opened ... any sensitive data they contain was NOT
		// detected". A zero-byte file contains nothing, so there is nothing
		// undetected and nothing for an operator to act on. Measured on a real
		// tree: all 25 files in that warning were zero bytes (build artifacts,
		// empty .err logs, a .venv lock file, empty golden fixtures), which
		// buried the diagnostic's real purpose — genuinely unreadable files.
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return false, err
	}

	buffer = buffer[:n]

	// Null-byte gating happens inside LooksLikeText, after encoding
	// detection — UTF-16 text carries a null per ASCII character, so a
	// pre-decode null check would (and previously did) classify every
	// UTF-16 file as binary.
	// UTF-8-aware sniff shared with the plaintext preprocessor: the previous
	// ASCII-byte-ratio copy here silently classified short lines containing
	// any multi-byte character (™, em-dash, accents, non-Latin scripts) as
	// binary, skipping the file for every validator in file mode.
	return preprocessors.LooksLikeText(buffer), nil
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
