// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package video redacts metadata in ISO base media video files (.mp4/.m4v/.mov).
//
// Before this package video had no redactor at all. The read side is complete — a dedicated
// preprocessor and extractor walk moov>udta and report the title, author, comment, copyright,
// camera make and model, software and GPS position — so a clip's comment holding an SSN was
// found, scored and printed. Then --enable-redaction wrote no output file and exited 0. A
// reported value that cannot be removed is the same leak as an undetected one, dressed as a
// success. See #358, and #306 for the audio case this follows.
//
// # Streaming, not read-then-copy
//
// The audio redactor reads the whole file and holds a modified copy, which is right for a voice
// memo and wrong for video: a 4 GB recording would need ~8 GB of RAM. Here the atom tree is
// walked with ReadAt — 8 bytes per atom header — and only the tag payloads are read. The output
// is produced by copying the file and overwriting those payloads in place, so peak memory is
// bounded by the size of the metadata rather than by the size of the movie. The media stream is
// never in memory at all.
//
// That is only possible because the replacement is always exactly as long as the value it
// replaces. Changing a length would mean rewriting every enclosing atom size AND every sample
// offset in stco, because moving bytes moves the video; getting that wrong yields a file a
// player refuses. A corrupt file that looks redacted is worse than an honest refusal, which is
// why synthetic — whose output length is unrelated to the input's — is declined rather than
// silently masked.
//
// # Coordinates are not text
//
// GPS is the one reported video value that never appears in the file as the text that was
// reported: the position is stored as fixed-point binary or as an ISO 6709 string, and the
// extractor re-formats it to six decimals. A text search finds nothing, and so does the residue
// check that is supposed to catch a miss — the check agrees with the bug. So coordinates are
// scrubbed structurally, by zeroing the payload of the atom that holds them, and verified by
// their own assertion rather than by the text search. See isobmff.CoordinateSpans.
package video

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/isobmff"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/tagmeta"
)

// maxTagBytes caps the total metadata this redactor will hold in memory at once.
//
// The point of the streaming walk is that a movie's size does not become a memory cost, and a
// declared atom size is attacker-controlled: a 4 KB file can claim a 4 GB udta. #350's lesson is
// that a declared size may only be trusted after it has been checked against a real one, and the
// walk already bounds each span by the file's actual length — this bounds the SUM, which the
// per-span check does not.
//
// 10 MB matches the metadata extractor's own MaxMetadataRead, so a value beyond it could not
// have been reported in the first place. Exceeding it is a refusal rather than a truncation:
// #374 is an open issue about exactly the "skip the oversize part and report the container
// clean" shape.
const maxTagBytes = 10 << 20

// gpsType is the finding type the metadata validator emits for a position.
const gpsType = "GPS"

// VideoRedactor redacts video metadata by same-length in-place overwrite.
type VideoRedactor struct {
	observer      observability.Observer
	outputManager *redactors.OutputStructureManager
}

// NewVideoRedactor creates a redactor for video files.
func NewVideoRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *VideoRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}
	return &VideoRedactor{observer: observer, outputManager: outputManager}
}

// GetName returns the name of the redactor.
func (r *VideoRedactor) GetName() string { return "video_metadata_redactor" }

// GetComponentName returns the component name for observability.
func (r *VideoRedactor) GetComponentName() string { return "video_metadata_redactor" }

// GetSupportedTypes returns the video types this redactor handles.
//
// Both bare and dotted spellings, matching every other redactor: the manager is called with
// each form in different code paths.
//
// .mkv and .webm are absent deliberately. They are EBML, not atom-based, and nothing scans them
// today — the file-extension validator admits exactly these three — so claiming them here would
// register a redactor for a file type that never reaches it.
func (r *VideoRedactor) GetSupportedTypes() []string {
	return []string{
		"mp4", ".mp4",
		"m4v", ".m4v",
		"mov", ".mov",
	}
}

// GetSupportedStrategies reports which strategies this redactor can honour.
//
// Synthetic is excluded deliberately — see the package comment: it cannot preserve length, and
// this redactor cannot change one.
func (r *VideoRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
	}
}

// tagBlock is one udta payload: where it lives in the file, and its bytes once modified.
type tagBlock struct {
	span     isobmff.Span
	buf      []byte
	coords   []isobmff.Span // coordinate payloads, buffer-relative
	scrubbed bool           // a coordinate payload in this block was scrubbed
}

// RedactDocument writes a redacted copy of a video file to outputPath.
func (r *VideoRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
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
	name := filepath.Base(originalPath)

	src, err := os.Open(filepath.Clean(originalPath)) // #nosec G304 -- path vetted by the router
	if err != nil {
		return nil, fmt.Errorf("failed to open video file: %w", err)
	}
	defer func() { _ = src.Close() }()

	info, err := src.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat video file: %w", err)
	}
	size := info.Size()

	var head [8]byte
	if _, err := io.ReadFull(src, head[:]); err != nil || !isobmff.HasHeader(head[:]) {
		// Magic, not the extension. The extension is the caller's claim; the bytes are the
		// file, and a container this package cannot walk is a container whose values it cannot
		// remove.
		return nil, fmt.Errorf("not a recognised video container: %s", name)
	}

	spans, err := isobmff.MetadataSpans(src, size)
	if err != nil {
		// A partial walk cannot support a claim about the whole file.
		return nil, fmt.Errorf("could not walk the atom tree of %s: %w", name, err)
	}
	if len(spans) == 0 {
		// No tag region located. Returning success here would write a byte-identical copy and
		// report it as redacted, which is the exact failure #358 is about.
		return nil, fmt.Errorf("no video metadata region found in %s, so its findings could not be removed", name)
	}

	total := int64(0)
	for _, sp := range spans {
		total += sp.Len()
	}
	if total > maxTagBytes {
		return nil, fmt.Errorf("%s declares %d bytes of metadata, above the %d-byte limit; refusing rather than redacting part of it",
			name, total, int64(maxTagBytes))
	}

	// Normalize the match set before reading any Text, as every other redactor now does: a
	// consolidated cluster's Text is a rendered summary that appears in no file, and a bounded
	// display text is truncated. See redactors.ExpandClusterMatches and #289.
	matches = redactors.ExpandClusterMatches(matches)
	matches = redactors.RestoreBoundedMatchText(matches)

	blocks, perMatch, err := r.planBlocks(src, spans, matches, strategy)
	if err != nil {
		return nil, err
	}

	// Coordinates first, because their absence from the text search is expected rather than a
	// miss, and because whether the remaining unlocated matches are tolerable depends on it.
	gpsHandled := r.scrubCoordinates(blocks, matches, perMatch)

	if err := r.refuseIfAnythingUnlocated(name, matches, perMatch, gpsHandled); err != nil {
		return nil, err
	}

	// FAIL CLOSED, before a single byte is written. Counting replacements is not enough: a value
	// can occur twice in one region, or in a region the search skipped, or in an encoding it did
	// not try, and every one of those looks like success from the mapping count alone.
	if residual := r.residual(blocks, matches); residual > 0 {
		return nil, fmt.Errorf("%d reported value(s) remain in the metadata of %s after redaction; refusing to write a file that would look redacted",
			residual, name)
	}
	if err := verifyCoordinatesScrubbed(blocks); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	if err := r.write(originalPath, outputPath, size, blocks, name); err != nil {
		return nil, err
	}

	mappings := r.mappings(matches, perMatch, gpsHandled, strategy)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     mappings,
		ProcessingTime:   time.Since(start),
		Confidence:       tagmeta.OverallConfidence(mappings),
		Error:            nil,
	}, nil
}

// planBlocks reads each tag payload and computes its overwrites, without writing anything.
//
// Only these payloads are read. The media stream — which is all but a few kilobytes of a real
// video — is never loaded, which is the whole point of walking the file rather than reading it.
func (r *VideoRedactor) planBlocks(src io.ReaderAt, spans []isobmff.Span, matches []detector.Match, strategy redactors.RedactionStrategy) ([]*tagBlock, []int, error) {
	blocks := make([]*tagBlock, 0, len(spans))
	perMatch := make([]int, len(matches))

	for _, sp := range spans {
		length := sp.Len()
		if length <= 0 {
			continue
		}
		buf := make([]byte, length)
		if _, err := src.ReadAt(buf, sp.Start); err != nil {
			return nil, nil, fmt.Errorf("failed to read metadata at offset %d: %w", sp.Start, err)
		}

		region := []tagmeta.Region{{Start: 0, End: len(buf), Label: sp.Label}}
		plan, found := tagmeta.Plan(buf, region, matches, strategy)
		tagmeta.Apply(buf, plan)
		for i, n := range found {
			perMatch[i] += n
		}

		blocks = append(blocks, &tagBlock{span: sp, buf: buf, coords: isobmff.Coordinates(buf)})
	}
	return blocks, perMatch, nil
}

// scrubCoordinates overwrites every coordinate payload when a position was reported, and
// returns whether it did.
//
// Driven by a reported finding rather than applied unconditionally: redaction removes what was
// reported. A position nobody flagged is not this redactor's to delete.
//
// Zero bytes, not the '*' this tool masks text with, because '*' IS a valid fixed-point number:
// 0x2A2A2A2A decodes to 10794.66°, so masking a position replaces it with another one. Measured
// on a real ffmpeg-written .mov, where the extractor reads the same payload as binary and
// reported "18.335022, 11059.211639" — a '*' fill there leaves the first coordinate untouched and
// the redacted file still reports GPS. Zero is the one fill no reader turns back into a location.
func (r *VideoRedactor) scrubCoordinates(blocks []*tagBlock, matches []detector.Match, perMatch []int) bool {
	reported := false
	for i, m := range matches {
		if strings.EqualFold(m.Type, gpsType) && m.Text != "" && perMatch[i] == 0 {
			reported = true
			break
		}
	}
	if !reported {
		return false
	}

	scrubbed := 0
	for _, b := range blocks {
		for _, c := range b.coords {
			if c.Start < 0 || c.End > int64(len(b.buf)) || c.Start >= c.End {
				continue
			}
			for i := c.Start; i < c.End; i++ {
				b.buf[i] = 0
			}
			b.scrubbed = true
			scrubbed++
		}
	}
	if scrubbed > 0 {
		r.logEvent("video_coordinate_atom_scrubbed", true, map[string]interface{}{
			"payloads": scrubbed,
			"blocks":   len(blocks),
		})
	}
	return scrubbed > 0
}

// refuseIfAnythingUnlocated stops the redaction when a reported value was not found in the tag
// bytes and was not handled structurally.
//
// Strict on purpose. The alternative — log it and write the file anyway — is what makes a
// redacted file that still holds a reported value while the audit trail says 0 failures, which
// is the defect class this package exists to close. Refusing costs nothing that the caller had
// before: with no redactor at all, the outcome for this file was already no output plus the
// "values remain in cleartext" disclosure.
//
// Only the TYPE is named, never the value: a diagnostic that echoes the match would leak it into
// logs that are not treated as sensitive.
func (r *VideoRedactor) refuseIfAnythingUnlocated(name string, matches []detector.Match, perMatch []int, gpsHandled bool) error {
	var unlocated []string
	for i, m := range matches {
		if m.Text == "" || perMatch[i] > 0 {
			continue
		}
		if strings.EqualFold(m.Type, gpsType) && gpsHandled {
			continue
		}
		unlocated = append(unlocated, m.Type)
	}
	if len(unlocated) == 0 {
		return nil
	}
	r.logEvent("video_match_not_located", false, map[string]interface{}{
		"types": strings.Join(unlocated, ","),
		"count": len(unlocated),
	})
	return fmt.Errorf("%d reported value(s) of type %s could not be located in the metadata of %s, so they could not be removed",
		len(unlocated), strings.Join(unlocated, ","), name)
}

// residual re-checks every tag payload for reported values after the overwrites were applied.
//
// Counted per MATCH across all blocks rather than per block, so a value surviving in a second
// udta is counted once and a value surviving in two of them does not report as one. Taking the
// maximum of per-block counts would undercount two different values in two different blocks.
func (r *VideoRedactor) residual(blocks []*tagBlock, matches []detector.Match) int {
	residual := 0
	for _, m := range matches {
		one := []detector.Match{m}
		for _, b := range blocks {
			region := []tagmeta.Region{{Start: 0, End: len(b.buf), Label: b.span.Label}}
			if tagmeta.Residual(b.buf, region, one) > 0 {
				residual++
				break
			}
		}
	}
	return residual
}

// verifyCoordinatesScrubbed asserts the structural half of the redaction actually happened.
//
// Needed because the text residue check cannot see it: the reported coordinate string is absent
// from the file whether or not the position was scrubbed, so that check passes either way. This
// is the assertion a partial coordinate scrub cannot satisfy.
//
// Checked by re-running the coordinate finder on the modified bytes rather than by comparing
// against what was written. That way the assertion is "no position remains", which is the
// property that matters, instead of "the fill byte was applied", which a wrong fill byte would
// also satisfy.
func verifyCoordinatesScrubbed(blocks []*tagBlock) error {
	for _, b := range blocks {
		if !b.scrubbed {
			continue
		}
		for _, c := range isobmff.Coordinates(b.buf) {
			if c.Start < 0 || c.End > int64(len(b.buf)) || c.Start >= c.End {
				continue
			}
			for i := c.Start; i < c.End; i++ {
				if b.buf[i] != 0 {
					return fmt.Errorf("a coordinate payload at file offset %d was not cleared; refusing to write a file whose position survived",
						b.span.Start+c.Start)
				}
			}
		}
	}
	return nil
}

// write copies the file and overwrites the modified tag payloads in place.
//
// A copy plus fixed-length patches, rather than assembling a new file: the media stream is
// copied straight through without being interpreted, so nothing this code gets wrong can move
// a sample offset.
func (r *VideoRedactor) write(originalPath, outputPath string, size int64, blocks []*tagBlock, name string) error {
	if r.outputManager != nil {
		if err := r.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	src, err := os.Open(filepath.Clean(originalPath)) // #nosec G304 -- path vetted by the router
	if err != nil {
		return fmt.Errorf("failed to reopen video file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// #nosec G304 G302 -- output path comes from the output manager; 0600 keeps the redacted
	// copy as restricted as every other redactor's.
	dst, err := os.OpenFile(filepath.Clean(outputPath), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create redacted file: %w", err)
	}

	fail := func(err error) error {
		_ = dst.Close()
		// A half-written file at the output path is the worst possible outcome: the caller
		// treats that path as sanitized. Remove it rather than leave it behind.
		_ = os.Remove(outputPath)
		return err
	}

	if _, err := io.Copy(dst, src); err != nil {
		return fail(fmt.Errorf("failed to copy video file: %w", err))
	}
	for _, b := range blocks {
		if _, err := dst.WriteAt(b.buf, b.span.Start); err != nil {
			return fail(fmt.Errorf("failed to write redacted metadata at offset %d: %w", b.span.Start, err))
		}
	}
	if err := dst.Sync(); err != nil {
		return fail(fmt.Errorf("failed to flush redacted file: %w", err))
	}

	// Structural invariant. Same-length overwrite is the entire reason the container stays
	// playable, so a size change means a bug that would ship a corrupt file.
	if info, err := dst.Stat(); err != nil {
		return fail(fmt.Errorf("failed to stat redacted file: %w", err))
	} else if info.Size() != size {
		return fail(fmt.Errorf("internal error: video redaction changed file size from %d to %d bytes", size, info.Size()))
	}

	// Verify the OUTPUT, not just the buffers that were meant to become it. The pre-write check
	// proves the plan was complete; this proves the plan is what landed on disk.
	if err := verifyWritten(dst, blocks); err != nil {
		return fail(fmt.Errorf("%s: %w", name, err))
	}

	if err := dst.Close(); err != nil {
		_ = os.Remove(outputPath)
		return fmt.Errorf("failed to close redacted file: %w", err)
	}
	return nil
}

// verifyWritten re-reads the tag payloads from the written file and compares them with the
// bytes that were supposed to be there.
//
// Bounded by maxTagBytes, so this costs a re-read of the metadata and not of the movie.
func verifyWritten(dst io.ReaderAt, blocks []*tagBlock) error {
	for _, b := range blocks {
		got := make([]byte, len(b.buf))
		if _, err := dst.ReadAt(got, b.span.Start); err != nil {
			return fmt.Errorf("failed to re-read redacted metadata at offset %d: %w", b.span.Start, err)
		}
		for i := range got {
			if got[i] != b.buf[i] {
				return fmt.Errorf("the redacted metadata at offset %d is not what was written", b.span.Start+int64(i))
			}
		}
	}
	return nil
}

// mappings records one entry per value this redactor actually wrote over — never one it merely
// tried.
func (r *VideoRedactor) mappings(matches []detector.Match, perMatch []int, gpsHandled bool, strategy redactors.RedactionStrategy) []redactors.RedactionMapping {
	var mappings []redactors.RedactionMapping
	for i, m := range matches {
		if m.Text == "" {
			continue
		}
		method := "video_tag_same_length_overwrite"
		occurrences := perMatch[i]
		if occurrences == 0 {
			if !gpsHandled || !strings.EqualFold(m.Type, gpsType) {
				continue
			}
			// Scrubbed structurally rather than by matching its text, and recorded as such so
			// the audit trail does not imply a text replacement that never happened.
			method = "video_coordinate_atom_scrubbed"
			occurrences = 1
		}
		mappings = append(mappings, redactors.RedactionMapping{
			RedactedText: tagmeta.SameLengthReplacement(m.Text, m.Type, strategy),
			DataType:     m.Type,
			Strategy:     strategy,
			Confidence:   m.Confidence,
			Metadata: map[string]interface{}{
				"occurrences":     occurrences,
				"position_method": method,
			},
		})
	}
	return mappings
}

func (r *VideoRedactor) logEvent(op string, success bool, meta map[string]interface{}) {
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

// compile-time check that this satisfies the interface the manager requires.
var _ redactors.Redactor = (*VideoRedactor)(nil)
