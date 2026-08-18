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
	// sawMissingPad records that an odd-length chunk was not followed by the pad byte RIFF
	// requires, so the walk had to realign. Reported after the loop rather than on the spot
	// because recovery succeeds and the note belongs to the file, not to one chunk.
	sawMissingPad := false

	for {
		var header WAVChunkHeader
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		chunkID := string(header.ID[:])

		// A RIFF chunk ID is four printable ASCII characters. Anything else means the
		// reader is no longer on a chunk boundary, and continuing would walk garbage: the
		// default branch below would "skip" by a nonsense size, land somewhere arbitrary,
		// and eventually hit EOF — at which point the loop breaks and reports success on a
		// file it never read. Stop and say so instead.
		if !isPrintableChunkID(header.ID) {
			metadata.ExtractionWarning = "audio metadata may be incomplete: the WAV chunk " +
				"layout could not be followed past an unrecognized chunk header, so any " +
				"metadata after that point was not read"
			return nil
		}

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

		// Align to even byte boundary.
		//
		// RIFF requires an odd-length chunk to be followed by a pad byte, but a truncated
		// download or a non-compliant writer can omit it. Seeking past it unconditionally
		// then lands the reader ONE BYTE PAST the next chunk header, so every subsequent
		// chunk ID is garbage — which used to be skipped silently, ending the walk at EOF
		// with a nil error and an empty result. Measured on two fixtures identical but for
		// this single byte: 1 finding versus 0, the second with no disclosure at all.
		//
		// The two cases are unambiguous, so the pad byte is detected rather than assumed:
		// a pad is always 0x00, and a chunk ID's first byte is printable ASCII.
		if header.Size%2 == 1 {
			var pad [1]byte
			n, err := file.Read(pad[:])
			switch {
			case err != nil || n == 0:
				// EOF right after an odd chunk: nothing follows, so nothing is missed.
			case pad[0] == 0x00:
				// A real pad byte, already consumed by the read above.
			default:
				// Not a pad byte — it is the first byte of the next chunk ID. Put it back
				// so the walk stays aligned, and note the file is non-compliant.
				if _, err := file.Seek(-1, io.SeekCurrent); err != nil {
					return err
				}
				sawMissingPad = true
			}
		}
	}

	// Recovered, but say so: the file is not RIFF-compliant, and an operator who cares
	// whether their corpus is intact should know the tool had to compensate. Never
	// overwrite a more specific warning already set above.
	if sawMissingPad && metadata.ExtractionWarning == "" {
		metadata.ExtractionWarning = "the WAV chunk layout omits a required pad byte after " +
			"an odd-length chunk; metadata was recovered by realigning, but the file is " +
			"malformed and may be truncated"
	}

	return nil
}

// isPrintableChunkID reports whether id is four printable ASCII characters, which every
// RIFF chunk ID is. It is the cheapest available test for "the reader is still on a chunk
// boundary".
func isPrintableChunkID(id [4]byte) bool {
	for _, b := range id {
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
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
