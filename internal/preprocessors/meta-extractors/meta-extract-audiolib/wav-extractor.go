// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// WAVExtractor handles WAV file metadata extraction
type WAVExtractor struct{}

// WAVChunkHeader represents a WAV chunk header
type WAVChunkHeader struct {
	ID   [4]byte
	Size uint32
}

// WAVFormatChunk represents the WAV format chunk
type WAVFormatChunk struct {
	AudioFormat   uint16
	NumChannels   uint16
	SampleRate    uint32
	ByteRate      uint32
	BlockAlign    uint16
	BitsPerSample uint16
}

// ExtractMetadata extracts metadata from a WAV file
func (e *WAVExtractor) ExtractMetadata(filePath string) (*AudioMetadata, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open WAV file: %w", err)
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
		MimeType:   "audio/wav",
		Properties: make(map[string]string),
	}

	// Check RIFF header
	riffHeader := make([]byte, 12)
	if _, err := file.Read(riffHeader); err != nil {
		return nil, fmt.Errorf("failed to read RIFF header: %w", err)
	}

	if string(riffHeader[0:4]) != "RIFF" || string(riffHeader[8:12]) != "WAVE" {
		return nil, fmt.Errorf("not a valid WAV file")
	}

	// Parse chunks
	if err := e.parseChunks(file, metadata); err != nil {
		return metadata, fmt.Errorf("failed to parse WAV chunks: %w", err)
	}

	return metadata, nil
}

// parseChunks parses WAV chunks
func (e *WAVExtractor) parseChunks(file *os.File, metadata *AudioMetadata) error {
	for {
		var header WAVChunkHeader
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		chunkID := string(header.ID[:])

		switch chunkID {
		case "fmt ":
			if err := e.parseFormatChunk(file, header.Size, metadata); err != nil {
				return err
			}
		case "LIST":
			if err := e.parseListChunk(file, header.Size, metadata); err != nil {
				// Don't fail on LIST chunk errors, just skip
				if _, err := file.Seek(int64(header.Size), io.SeekCurrent); err != nil {
					return err
				}
			}
		default:
			// Skip unknown chunks
			if _, err := file.Seek(int64(header.Size), io.SeekCurrent); err != nil {
				return err
			}
		}

		// Align to even byte boundary
		if header.Size%2 == 1 {
			file.Seek(1, io.SeekCurrent)
		}
	}

	return nil
}

// parseFormatChunk parses the WAV format chunk
func (e *WAVExtractor) parseFormatChunk(file *os.File, size uint32, metadata *AudioMetadata) error {
	var format WAVFormatChunk
	if err := binary.Read(file, binary.LittleEndian, &format); err != nil {
		return err
	}

	metadata.SampleRate = int(format.SampleRate)
	metadata.Channels = int(format.NumChannels)
	metadata.Bitrate = int(format.ByteRate * 8 / 1000) // Convert to kbps

	// Store additional format information
	metadata.Properties["AudioFormat"] = fmt.Sprintf("%d", format.AudioFormat)
	metadata.Properties["BitsPerSample"] = fmt.Sprintf("%d", format.BitsPerSample)
	metadata.Properties["BlockAlign"] = fmt.Sprintf("%d", format.BlockAlign)

	// Skip any remaining format chunk data
	remaining := size - 16 // 16 bytes already read
	if remaining > 0 {
		if _, err := file.Seek(int64(remaining), io.SeekCurrent); err != nil {
			return err
		}
	}

	return nil
}

// parseListChunk parses LIST chunks which may contain INFO metadata
func (e *WAVExtractor) parseListChunk(file *os.File, size uint32, metadata *AudioMetadata) error {
	// Read LIST type
	listType := make([]byte, 4)
	if _, err := file.Read(listType); err != nil {
		return err
	}

	if string(listType) != "INFO" {
		// Skip non-INFO LIST chunks
		remaining := size - 4
		if _, err := file.Seek(int64(remaining), io.SeekCurrent); err != nil {
			return err
		}
		return nil
	}

	// Parse INFO chunks
	remaining := size - 4 // 4 bytes for LIST type already read
	return e.parseInfoChunks(file, remaining, metadata)
}

// parseInfoChunks parses INFO chunks within a LIST chunk
func (e *WAVExtractor) parseInfoChunks(file *os.File, totalSize uint32, metadata *AudioMetadata) error {
	bytesRead := uint32(0)

	for bytesRead < totalSize {
		var header WAVChunkHeader
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			return err
		}
		bytesRead += 8

		// Read chunk data
		chunkData := make([]byte, header.Size)
		if _, err := file.Read(chunkData); err != nil {
			return err
		}
		bytesRead += header.Size

		// Parse INFO field
		e.parseInfoField(string(header.ID[:]), chunkData, metadata)

		// Align to even byte boundary
		if header.Size%2 == 1 {
			file.Seek(1, io.SeekCurrent)
			bytesRead++
		}
	}

	return nil
}

// parseInfoField parses a specific INFO field
func (e *WAVExtractor) parseInfoField(fieldID string, data []byte, metadata *AudioMetadata) {
	// Remove null terminator and clean up
	value := strings.TrimRight(string(data), "\x00")
	if value == "" {
		return
	}

	switch fieldID {
	case "INAM": // Title
		metadata.Title = value
	case "IART": // Artist
		metadata.Artist = value
	case "IPRD": // Album/Product
		metadata.Album = value
	case "ICRD": // Creation date
		if year := parseYear(value); year > 0 {
			metadata.Year = year
		}
	case "IGNR": // Genre
		metadata.Genre = value
	case "ICMT": // Comment
		metadata.Comment = value
	case "ICOP": // Copyright
		metadata.Copyright = value
	case "IENG": // Engineer
		metadata.Engineer = value
	case "ISFT": // Software
		metadata.Properties["Software"] = value
	case "ISBJ": // Subject
		metadata.Properties["Subject"] = value
	case "ISRC": // Source
		metadata.Properties["Source"] = value
	case "ITCH": // Technician
		metadata.Properties["Technician"] = value
	default:
		// Store unknown INFO fields
		metadata.Properties[fieldID] = value
	}
}

// CanProcess checks if the file can be processed as WAV
func (e *WAVExtractor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".wav"
}

// GetSupportedFormats returns supported file formats
func (e *WAVExtractor) GetSupportedFormats() []string {
	return []string{".wav"}
}
