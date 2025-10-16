// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FLACExtractor handles FLAC file metadata extraction
type FLACExtractor struct{}

// FLACMetadataBlockHeader represents a FLAC metadata block header
type FLACMetadataBlockHeader struct {
	LastBlock bool
	BlockType byte
	Length    uint32
}

// FLAC metadata block types
const (
	FLACBlockTypeStreamInfo    = 0
	FLACBlockTypePadding       = 1
	FLACBlockTypeApplication   = 2
	FLACBlockTypeSeekTable     = 3
	FLACBlockTypeVorbisComment = 4
	FLACBlockTypeCueSheet      = 5
	FLACBlockTypePicture       = 6
)

// ExtractMetadata extracts metadata from a FLAC file
func (e *FLACExtractor) ExtractMetadata(filePath string) (*AudioMetadata, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open FLAC file: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	metadata := &AudioMetadata{
		Filename:   stat.Name(),
		FileSize:   stat.Size(),
		ModTime:    stat.ModTime(),
		MimeType:   "audio/flac",
		Properties: make(map[string]string),
	}

	// Check FLAC signature
	signature := make([]byte, 4)
	if _, err := file.Read(signature); err != nil {
		return nil, fmt.Errorf("failed to read FLAC signature: %w", err)
	}

	if string(signature) != "fLaC" {
		return nil, fmt.Errorf("not a valid FLAC file")
	}

	// Parse metadata blocks
	if err := e.parseMetadataBlocks(file, metadata); err != nil {
		return metadata, fmt.Errorf("failed to parse metadata blocks: %w", err)
	}

	return metadata, nil
}

// parseMetadataBlocks parses FLAC metadata blocks
func (e *FLACExtractor) parseMetadataBlocks(file *os.File, metadata *AudioMetadata) error {
	for {
		// Read metadata block header
		headerBytes := make([]byte, 4)
		if _, err := file.Read(headerBytes); err != nil {
			return err
		}

		header := FLACMetadataBlockHeader{
			LastBlock: (headerBytes[0] & 0x80) != 0,
			BlockType: headerBytes[0] & 0x7F,
			Length:    uint32(headerBytes[1])<<16 | uint32(headerBytes[2])<<8 | uint32(headerBytes[3]),
		}

		// Read block data
		blockData := make([]byte, header.Length)
		if _, err := file.Read(blockData); err != nil {
			return err
		}

		// Process specific block types
		switch header.BlockType {
		case FLACBlockTypeStreamInfo:
			e.parseStreamInfo(blockData, metadata)
		case FLACBlockTypeVorbisComment:
			e.parseVorbisComments(blockData, metadata)
		}

		// Stop if this was the last metadata block
		if header.LastBlock {
			break
		}
	}

	return nil
}

// parseStreamInfo parses FLAC STREAMINFO block
func (e *FLACExtractor) parseStreamInfo(data []byte, metadata *AudioMetadata) {
	if len(data) < 34 {
		return
	}

	// Extract audio properties from STREAMINFO
	// Bytes 10-11: Sample rate (20 bits)
	// Bytes 12: Channels (3 bits) and bits per sample (5 bits)
	// Bytes 13-17: Total samples (36 bits)

	sampleRate := (uint32(data[10])<<12 | uint32(data[11])<<4 | uint32(data[12])>>4) & 0xFFFFF
	channels := ((data[12] >> 1) & 0x07) + 1
	bitsPerSample := ((data[12] & 0x01) << 4) | ((data[13] >> 4) & 0x0F) + 1

	metadata.SampleRate = int(sampleRate)
	metadata.Channels = int(channels)

	// Calculate duration from total samples
	totalSamples := uint64(data[13]&0x0F)<<32 | uint64(data[14])<<24 | uint64(data[15])<<16 | uint64(data[16])<<8 | uint64(data[17])
	if sampleRate > 0 {
		durationSeconds := float64(totalSamples) / float64(sampleRate)
		metadata.Duration = time.Duration(durationSeconds * float64(time.Second))
	}

	// Store additional properties
	metadata.Properties["BitsPerSample"] = strconv.Itoa(int(bitsPerSample))
}

// parseVorbisComments parses FLAC Vorbis comment block
func (e *FLACExtractor) parseVorbisComments(data []byte, metadata *AudioMetadata) {
	if len(data) < 8 {
		return
	}

	offset := 0

	// Read vendor string length (little-endian)
	vendorLength := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Skip vendor string
	if offset+int(vendorLength) > len(data) {
		return
	}
	offset += int(vendorLength)

	// Read number of comments
	if offset+4 > len(data) {
		return
	}
	commentCount := binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Parse each comment
	for i := uint32(0); i < commentCount && offset < len(data); i++ {
		// Read comment length
		if offset+4 > len(data) {
			break
		}
		commentLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Read comment data
		if offset+int(commentLength) > len(data) {
			break
		}
		comment := string(data[offset : offset+int(commentLength)])
		offset += int(commentLength)

		// Parse comment field
		e.parseVorbisComment(comment, metadata)
	}
}

// parseVorbisComment parses a single Vorbis comment field
func (e *FLACExtractor) parseVorbisComment(comment string, metadata *AudioMetadata) {
	parts := strings.SplitN(comment, "=", 2)
	if len(parts) != 2 {
		return
	}

	field := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	if value == "" {
		return
	}

	switch field {
	case "TITLE":
		metadata.Title = value
	case "ARTIST":
		metadata.Artist = value
	case "ALBUM":
		metadata.Album = value
	case "ALBUMARTIST":
		metadata.AlbumArtist = value
	case "DATE", "YEAR":
		if year := parseYear(value); year > 0 {
			metadata.Year = year
		}
	case "GENRE":
		metadata.Genre = value
	case "TRACKNUMBER":
		if track := parseTrackNumber(value); track > 0 {
			metadata.Track = track
		}
	case "COMMENT", "DESCRIPTION":
		metadata.Comment = value
	case "COMPOSER":
		metadata.Composer = value
	case "CONDUCTOR":
		metadata.Conductor = value
	case "PUBLISHER":
		metadata.Publisher = value
	case "COPYRIGHT":
		metadata.Copyright = value
	case "LOCATION":
		metadata.Location = value
	case "ORGANIZATION":
		metadata.Studio = value
	case "CONTACT":
		metadata.Properties["Contact"] = value
	default:
		// Store unknown fields in properties
		metadata.Properties[field] = value
	}
}

// CanProcess checks if the file can be processed as FLAC
func (e *FLACExtractor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".flac"
}

// GetSupportedFormats returns supported file formats
func (e *FLACExtractor) GetSupportedFormats() []string {
	return []string{".flac"}
}
