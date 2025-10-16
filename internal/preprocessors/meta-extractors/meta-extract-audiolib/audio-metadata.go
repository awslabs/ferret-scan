// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"fmt"
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

	// Additional properties
	for key, value := range am.Properties {
		if value != "" {
			content.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	return content.String()
}
