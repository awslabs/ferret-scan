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

		// Read block data, clamped to the bytes the FILE holds rather than to header.Length.
		// The length is 24 bits read out of the block header, so it tops out at 16MiB — smaller
		// than the .m4a case but the same defect: an 8-byte .flac declaring 0xFFFFFF allocated
		// 16MB (#457). Both block consumers below already bound their reads by len(data).
		blockData, err := readDeclaredPayload(file, header.Length)
		if err != nil {
			return err
		}

		// A block that holds fewer bytes than its header declares is lost coverage, and it has to be
		// said HERE rather than inside a per-block parser.
		//
		// #476 replaced a `file.Read` into a declared-size buffer with a read clamped to the file. That
		// removed the allocation bomb, correctly -- but it also removed the only signal that anything
		// was wrong: the old code's read returned io.EOF when ZERO bytes were available, which
		// propagated out of ExtractMetadata as a parse failure and produced "cannot parse" with rc 3.
		// Clamping returns a short buffer and no error, so three fixtures moved from
		// disclosed-incomplete to silently-complete:
		//
		//	46-byte .flac, VORBIS_COMMENT header present with zero payload   pre rc 3 -> merged rc 0
		//	8-byte .flac declaring a 16MiB STREAMINFO (the #457 bomb)        pre rc 3 -> merged rc 0
		//
		// Checked at the block level so it covers EVERY block type. The per-field check in
		// parseVorbisComments cannot: a payload that is entirely absent never reaches it, because the
		// parser returns early on a short buffer.
		if int64(len(blockData)) < int64(header.Length) {
			metadata.noteTruncatedBlock()
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

	// Skip vendor string, bounded by the bytes present.
	//
	// A truncated vendor string means the comments that would follow it are past the end of the
	// block, so there is nothing to recover here -- but it is still lost coverage and must be said
	// rather than returned from silently.
	if int64(vendorLength) > int64(len(data)-offset) {
		metadata.noteTruncatedComments()
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
			metadata.noteTruncatedComments()
			break
		}
		commentLength := binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4

		// Read comment data, bounded by the bytes actually present.
		//
		// A field length is producer-chosen like every other length in this container, so it may
		// declare more than the block holds -- in a file truncated mid-block, or one a tagger cut
		// short. Discarding such a field was a silent CLEARTEXT LEAK, because the value may be
		// complete inside the bytes that ARE there and only the padding after it is missing.
		//
		// Measured on a real libFLAC encode (ffmpeg, from /System/Library/Sounds/Submarine.aiff)
		// with PADDING dropped so VORBIS_COMMENT is genuinely last, then truncated five bytes past
		// an SSN in the COMMENT field. exiftool, ffprobe and ffmpeg all read the untruncated file
		// cleanly, and the SSN is present in the truncated one:
		//
		//	before #476   PERSON_NAME + SSN reported; redacted copy holds 0 cleartext SSN
		//	after  #476   PERSON_NAME only;           redacted copy holds 1 cleartext SSN
		//
		// #476 is what exposed it, and correctly: it stopped sizing the buffer to the DECLARED block
		// length, so `data` is now only the bytes present rather than a declared-size buffer with a
		// zeroed tail. The old bound then passed for the wrong reason -- it was comparing against
		// invented zeroes. The right fix is the same principle #476 applied one layer up: clamp to
		// what exists, and use it.
		//
		// Every LATER comment was lost too, because this was a `break`. That is why one truncated
		// field cost the whole tail of the block.
		avail := len(data) - offset
		truncated := int64(commentLength) > int64(avail)
		end := offset + int(commentLength)
		if truncated {
			end = len(data)
			metadata.noteTruncatedComments()
		}
		comment := string(data[offset:end])
		offset = end

		// Parse comment field
		e.parseVorbisComment(comment, metadata)

		if truncated {
			// Nothing follows a field that ran to the end of the block.
			break
		}
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
