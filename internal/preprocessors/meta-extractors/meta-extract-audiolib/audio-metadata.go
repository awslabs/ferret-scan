// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// AudioMetadata represents extracted audio file metadata
type AudioMetadata struct {
	// File information
	Filename string
	FileSize int64
	ModTime  time.Time
	MimeType string

	// Audio-specific metadata
	Duration   time.Duration
	Bitrate    int
	SampleRate int
	Channels   int
	Codec      string

	// ID3/Tag metadata
	Title       string
	Artist      string
	Album       string
	AlbumArtist string
	Year        int
	Genre       string
	Track       int
	Comment     string

	// Extended metadata
	Composer  string
	Conductor string
	Publisher string
	Copyright string

	// Recording information
	RecordingDate time.Time
	Location      string
	Studio        string
	Engineer      string

	// Additional properties
	Properties map[string]string

	// ExtractionWarning is a short, payload-free note that extraction completed but
	// may be INCOMPLETE — for example a RIFF chunk layout that could not be walked to
	// the end, so metadata beyond that point was never read.
	//
	// It exists because the failure is otherwise invisible. A WAV whose chunk walk goes
	// wrong yields an empty result and no error, so the run prints "No matches found."
	// and exits 0 — byte-identical output to a genuinely clean file, with nothing for an
	// operator to distinguish "no metadata" from "could not be read". Same shape as the
	// corrupt-PDF disclosure. See #312.
	//
	// Payload-free by contract: it names the condition and the chunk kind, never a value.
	ExtractionWarning string
}

// AudioMetadataExtractor interface for audio metadata extraction
type AudioMetadataExtractor interface {
	ExtractMetadata(filePath string) (*AudioMetadata, error)
	CanProcess(filePath string) bool
	GetSupportedFormats() []string
}

// AudioMetadataExtractorWithContext interface for context-aware audio metadata extraction
type AudioMetadataExtractorWithContext interface {
	AudioMetadataExtractor
	ExtractMetadataWithContext(ctx context.Context, filePath string) (*AudioMetadata, error)
}

// ToProcessedContent converts AudioMetadata to ProcessedContent format
func (am *AudioMetadata) ToProcessedContent() string {
	var content strings.Builder

	// File information (excluding file system details per requirements)
	if am.MimeType != "" {
		content.WriteString(fmt.Sprintf("MimeType: %s\n", am.MimeType))
	}

	// Audio technical specifications
	if am.Duration > 0 {
		content.WriteString(fmt.Sprintf("Duration: %s\n", am.Duration.String()))
	}
	if am.Bitrate > 0 {
		content.WriteString(fmt.Sprintf("Bitrate: %d\n", am.Bitrate))
	}
	if am.SampleRate > 0 {
		content.WriteString(fmt.Sprintf("SampleRate: %d\n", am.SampleRate))
	}
	if am.Channels > 0 {
		content.WriteString(fmt.Sprintf("Channels: %d\n", am.Channels))
	}
	if am.Codec != "" {
		content.WriteString(fmt.Sprintf("Codec: %s\n", am.Codec))
	}

	// ID3/Tag metadata (privacy-sensitive information)
	if am.Title != "" {
		content.WriteString(fmt.Sprintf("Title: %s\n", am.Title))
	}
	if am.Artist != "" {
		content.WriteString(fmt.Sprintf("Artist: %s\n", am.Artist))
	}
	if am.Album != "" {
		content.WriteString(fmt.Sprintf("Album: %s\n", am.Album))
	}
	if am.AlbumArtist != "" && am.AlbumArtist != am.Artist {
		content.WriteString(fmt.Sprintf("AlbumArtist: %s\n", am.AlbumArtist))
	}
	if am.Year > 0 {
		content.WriteString(fmt.Sprintf("Year: %d\n", am.Year))
	}
	if am.Genre != "" {
		content.WriteString(fmt.Sprintf("Genre: %s\n", am.Genre))
	}
	if am.Track > 0 {
		content.WriteString(fmt.Sprintf("Track: %d\n", am.Track))
	}
	if am.Comment != "" {
		content.WriteString(fmt.Sprintf("Comment: %s\n", am.Comment))
	}

	// Extended metadata (privacy-sensitive)
	if am.Composer != "" {
		content.WriteString(fmt.Sprintf("Composer: %s\n", am.Composer))
	}
	if am.Conductor != "" {
		content.WriteString(fmt.Sprintf("Conductor: %s\n", am.Conductor))
	}
	if am.Publisher != "" {
		content.WriteString(fmt.Sprintf("Publisher: %s\n", am.Publisher))
	}
	if am.Copyright != "" {
		content.WriteString(fmt.Sprintf("Copyright: %s\n", am.Copyright))
	}

	// Recording information (privacy-sensitive)
	if !am.RecordingDate.IsZero() {
		content.WriteString(fmt.Sprintf("RecordingDate: %s\n", am.RecordingDate.Format("2006:01:02 15:04:05-07:00")))
	}
	if am.Location != "" {
		content.WriteString(fmt.Sprintf("Location: %s\n", am.Location))
	}
	if am.Studio != "" {
		content.WriteString(fmt.Sprintf("Studio: %s\n", am.Studio))
	}
	if am.Engineer != "" {
		content.WriteString(fmt.Sprintf("Engineer: %s\n", am.Engineer))
	}

	// Additional properties, emitted in sorted key order. Ranging over the map
	// directly made the extracted text (and therefore every finding's line
	// number, and the byte-for-byte redaction output) vary run to run — verified
	// on a real .m4a where EncodingTool jumped lines between runs. The image
	// metadata path already sorts its keys for exactly this reason.
	propKeys := make([]string, 0, len(am.Properties))
	for key := range am.Properties {
		propKeys = append(propKeys, key)
	}
	sort.Strings(propKeys)
	for _, key := range propKeys {
		if value := am.Properties[key]; value != "" {
			content.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	return content.String()
}

// noteTruncatedComments records that a FLAC VORBIS_COMMENT block declared more than it held.
//
// A method rather than an assignment at each site so the wording exists once, and so the
// first-warning-wins rule is not restated three times. It mirrors the WAV path, which says the same
// thing about a WAV INFO field (#423) -- the two containers have the same defect shape, and an
// operator should not have to learn two vocabularies for it.
//
// Payload-free by construction (BSC4): it names the STRUCTURE, never the field, its keyword or its
// value. A warning that quoted the field would put the value it is warning about into the log.
func (m *AudioMetadata) noteTruncatedComments() {
	if m == nil || m.ExtractionWarning != "" {
		return
	}
	m.ExtractionWarning = "audio metadata may be incomplete: a FLAC VORBIS_COMMENT field declares " +
		"more data than its block holds, so it was read only to the end of the block and any later " +
		"field in that block was not read"
}

// noteTruncatedBlock records that a FLAC metadata block held fewer bytes than its header declared.
//
// Distinct from noteTruncatedComments, which is about a FIELD over-declaring inside a block that is
// itself complete -- a tagger bug rather than a truncated file. The remedies differ: a short block
// means the file is cut short or corrupt, while a short field means one tag is unreliable.
//
// Payload-free (BSC4): names the structure, never a field name or value.
func (m *AudioMetadata) noteTruncatedBlock() {
	if m == nil || m.ExtractionWarning != "" {
		return
	}
	m.ExtractionWarning = "audio metadata may be incomplete: a FLAC metadata block holds fewer " +
		"bytes than its header declares, so the file is truncated or corrupt and any metadata in or " +
		"after that block was not fully read"
}
