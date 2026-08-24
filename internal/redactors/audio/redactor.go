// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package audio redacts tag metadata in audio files (.mp3/.wav/.m4a/.flac).
//
// Before this package audio had no redactor at all. The read side is complete — there is a
// dedicated preprocessor and four extractors, and audio is admitted as an embedded part too —
// so a voice memo's ID3 comment holding a phone number was found, scored, and printed. Then
// --enable-redaction produced no output file, and the run exited 0. A reported value that
// cannot be removed is the same leak as an undetected one, dressed as a success. See #306.
//
// # Why in-place same-length overwrite
//
// Every one of these containers stores tag text behind a length: a RIFF chunk size, an ID3v2
// synchsafe frame size, a FLAC 24-bit block length, an MP4 atom size. Writing a replacement
// of a different length means rewriting every enclosing size — and in MP4 also every sample
// offset in stco, because moving bytes moves the audio. Getting that wrong yields a file a
// player refuses, and a corrupt file that looks redacted is worse than an honest refusal,
// which is why the PDF redactor declines rather than guessing.
//
// So the replacement is always exactly len(original) bytes. No length changes, so no size
// field anywhere needs recomputing, and the audio stream is never moved. This is the same
// technique internal/redactors/legacyole uses on OLE compound files, for the same reason.
//
// # The strategy constraint that creates
//
// Synthetic is declined: it generates a plausible value whose length is unrelated to the
// original. Claiming support and silently masking instead would misreport what the output
// contains.
package audio

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/tagmeta"
)

// audioFormat identifies which container's metadata layout applies.
type audioFormat int

const (
	formatUnknown audioFormat = iota
	formatWAV
	formatMP3
	formatFLAC
	formatM4A
)

func (f audioFormat) String() string {
	switch f {
	case formatWAV:
		return "wav"
	case formatMP3:
		return "mp3"
	case formatFLAC:
		return "flac"
	case formatM4A:
		return "m4a"
	}
	return "unknown"
}

// AudioRedactor redacts audio tag metadata by same-length in-place overwrite.
type AudioRedactor struct {
	observer      observability.Observer
	outputManager *redactors.OutputStructureManager
}

// NewAudioRedactor creates a redactor for audio files.
func NewAudioRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *AudioRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}
	return &AudioRedactor{observer: observer, outputManager: outputManager}
}

// GetName returns the name of the redactor.
func (r *AudioRedactor) GetName() string { return "audio_metadata_redactor" }

// GetComponentName returns the component name for observability.
func (r *AudioRedactor) GetComponentName() string { return "audio_metadata_redactor" }

// GetSupportedTypes returns the audio types this redactor handles.
//
// Both bare and dotted spellings, matching every other redactor: the manager is called with
// each form in different code paths.
func (r *AudioRedactor) GetSupportedTypes() []string {
	return []string{
		"mp3", ".mp3",
		"wav", ".wav",
		"m4a", ".m4a",
		"flac", ".flac",
	}
}

// GetSupportedStrategies reports which strategies this redactor can honour.
//
// Synthetic is excluded deliberately — see the package comment: it cannot preserve length,
// and this redactor cannot change one.
func (r *AudioRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
	}
}

// RedactDocument writes a redacted copy of an audio file to outputPath.
func (r *AudioRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
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

	raw, err := os.ReadFile(originalPath) // #nosec G304 -- path vetted by the router
	if err != nil {
		return nil, fmt.Errorf("failed to read audio file: %w", err)
	}

	format := detectFormat(originalPath, raw)
	if format == formatUnknown {
		return nil, fmt.Errorf("not a recognised audio container: %s", filepath.Base(originalPath))
	}

	ranges := metadataRanges(raw, format)
	if len(ranges) == 0 {
		// No tag region located. Returning success here would write a byte-identical copy and
		// report it as redacted, which is the exact failure #306 is about.
		return nil, fmt.Errorf("no %s metadata region found in %s, so its findings could not be removed",
			format, filepath.Base(originalPath))
	}

	// Normalize the match set before reading any Text, as every other redactor now does: a
	// consolidated cluster's Text is a rendered summary that appears in no file, and a
	// bounded display text is truncated. See redactors.ExpandClusterMatches and #289.
	matches = redactors.ExpandClusterMatches(matches)
	matches = redactors.RestoreBoundedMatchText(matches)

	// Locate every occurrence against the ORIGINAL bytes and resolve overlaps BEFORE writing
	// anything. Reported matches overlap — an AUTHOR_INFO field value contains the SSN
	// reported separately — and a sequential replace loses whichever one it handles second.
	// See planOverwrites.
	plan, perMatch := tagmeta.Plan(raw, ranges, matches, strategy)

	modified := append([]byte(nil), raw...)
	tagmeta.Apply(modified, plan)

	var mappings []redactors.RedactionMapping
	for i, m := range matches {
		if m.Text == "" {
			continue
		}
		if perMatch[i] == 0 {
			// Not every reported value appears verbatim in the tag bytes: the extractor
			// renders fields into a text block, so a match may span a label or be
			// normalised. Recorded as an event rather than a mapping, so the count never
			// claims a replacement that did not happen. The residue check below is what
			// decides whether the file is safe to hand over.
			r.logEvent("audio_match_not_located", false, map[string]interface{}{
				"match_type":   m.Type,
				"match_length": len(m.Text),
				"format":       format.String(),
			})
			continue
		}
		mappings = append(mappings, redactors.RedactionMapping{
			RedactedText: tagmeta.SameLengthReplacement(m.Text, m.Type, strategy),
			DataType:     m.Type,
			Strategy:     strategy,
			Confidence:   m.Confidence,
			Metadata: map[string]interface{}{
				"occurrences":     perMatch[i],
				"position_method": "audio_tag_same_length_overwrite",
			},
		})
	}

	// Structural invariant. Same-length overwrite is the entire reason the container stays
	// playable, so a size change means a bug that would ship a corrupt file.
	if len(modified) != len(raw) {
		return nil, fmt.Errorf("internal error: audio redaction changed file size from %d to %d bytes",
			len(raw), len(modified))
	}

	// FAIL CLOSED. Re-read the tag regions and refuse if any reported value is still there.
	//
	// This is the check that makes the redactor trustworthy rather than merely active. Counting
	// replacements is not enough: a value can occur twice in one region, or in a second region,
	// or in an encoding the search did not try, and every one of those looks like a success
	// from the mapping count alone. Verifying the OUTPUT is the only assertion that cannot be
	// satisfied by a partial job.
	// ResidualAnywhere, not Residual: the latter searches only `ranges`, which are the spans this
	// pass already rewrote, so a value surviving OUTSIDE them cannot be seen. Measured on a real
	// .m4a whose Artist tag existed in two places — the copy inside the mapped udta span was
	// overwritten, the copy at offset 11613 was not, and this check returned 0 and wrote a file
	// still containing a reported credit card number while reporting success (#449).
	if residual := tagmeta.ResidualAnywhere(modified, matches); residual > 0 {
		return nil, fmt.Errorf("%d reported value(s) remain anywhere in %s after redaction; refusing to write a file that would look redacted",
			residual, filepath.Base(originalPath))
	}

	// And the same question asked of XML, where the check above is structurally blind.
	//
	// A value inside an XMP packet may be entity-encoded — exiftool writes an apostrophe as
	// `&#39;` — so it is not present as the bytes that were reported and ResidualAnywhere cannot
	// see it. Measured: a .m4a tagged `Patrick O'Connor` plus a card number was written with
	// `Patrick O&#39;Connor` still in the packet at exit 0 and no warning, and exiftool read the
	// name back out of the "redacted" file. Its own refusal message names the cause, because
	// "remains anywhere" would send an operator looking for bytes that are genuinely absent.
	if residual := tagmeta.ResidualEncoded(modified, ranges, matches); residual > 0 {
		return nil, fmt.Errorf("%d reported value(s) remain in %s as XML-encoded text after redaction (e.g. an apostrophe written as &#39;), which a raw search cannot mask; refusing to write a file that would look redacted",
			residual, filepath.Base(originalPath))
	}

	if r.outputManager != nil {
		if err := r.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return nil, fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}
	// #nosec G306 -- 0600 keeps the redacted copy as restricted as every other redactor's.
	if err := os.WriteFile(outputPath, modified, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write redacted file: %w", err)
	}

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     mappings,
		ProcessingTime:   time.Since(start),
		Confidence:       tagmeta.OverallConfidence(mappings),
		Error:            nil,
	}, nil
}

// detectFormat identifies the container from its magic bytes, falling back to the extension.
//
// Magic first, because the extension is the caller's claim and the bytes are the file. A .wav
// that is really an MP3 would otherwise be walked as RIFF, find no chunks, and be refused
// even though its ID3 tag is perfectly redactable.
func detectFormat(path string, buf []byte) audioFormat {
	switch {
	case len(buf) >= 12 && bytes.Equal(buf[0:4], []byte("RIFF")) && bytes.Equal(buf[8:12], []byte("WAVE")):
		return formatWAV
	case len(buf) >= 4 && bytes.Equal(buf[0:4], []byte("fLaC")):
		return formatFLAC
	case len(buf) >= 12 && bytes.Equal(buf[4:8], []byte("ftyp")):
		return formatM4A
	case len(buf) >= 3 && bytes.Equal(buf[0:3], []byte("ID3")):
		return formatMP3
	case len(buf) >= 2 && buf[0] == 0xFF && buf[1]&0xE0 == 0xE0:
		// A bare MPEG frame sync: an MP3 with no ID3v2 header. It may still carry ID3v1.
		return formatMP3
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".mp3":
		return formatMP3
	case ".wav":
		return formatWAV
	case ".flac":
		return formatFLAC
	case ".m4a":
		return formatM4A
	}
	return formatUnknown
}

func (r *AudioRedactor) logEvent(op string, success bool, meta map[string]interface{}) {
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
var _ redactors.Redactor = (*AudioRedactor)(nil)
