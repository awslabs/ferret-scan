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

// padByteNote is the disclosure for a file that omits RIFF's required pad byte. Shared
// by both chunk walks so the two cannot describe the same condition differently.
const padByteNote = "the WAV chunk layout omits a required pad byte after an odd-length " +
	"chunk; metadata was recovered by realigning, but the file is malformed and may be " +
	"truncated"

// consumePadByte applies RIFF's even-alignment rule after a chunk of the given size,
// DETECTING the pad byte rather than assuming it, and reports how many bytes it consumed.
//
// RIFF requires an odd-length chunk to be followed by a pad byte, but a truncated download
// or a non-compliant writer can omit it. Seeking past it unconditionally then lands the
// reader ONE BYTE PAST the next chunk header, so every subsequent ID is garbage — read
// silently, ending the walk at EOF with a nil error and a short result. Measured on two
// fixtures identical but for this single byte: 1 finding versus 0, the second with no
// disclosure at all.
//
// The two cases are unambiguous, so the pad is detected: a pad is always 0x00, and a chunk
// ID's first byte is printable ASCII.
//
// This lives in one function because it is needed in two places and diverged once already:
// the outer walk detected the pad while parseInfoChunks — the loop that reads the
// PII-bearing INFO fields — still assumed it, so the fix covered the metadata an operator
// cares least about and missed the fields that carry names, comments and copyright.
func consumePadByte(file *os.File, size uint32) (consumed int, missing bool, err error) {
	if size%2 == 0 {
		return 0, false, nil
	}
	var pad [1]byte
	n, rerr := file.Read(pad[:])
	switch {
	case rerr != nil || n == 0:
		// EOF right after an odd chunk: nothing follows, so nothing is missed.
		return 0, false, nil
	case pad[0] == 0x00:
		return 1, false, nil
	default:
		// Not a pad byte — it is the first byte of the next chunk ID. Put it back so the
		// walk stays aligned, and report the file as non-compliant.
		if _, serr := file.Seek(-1, io.SeekCurrent); serr != nil {
			return 0, false, serr
		}
		return 0, true, nil
	}
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
		// reader is no longer on a chunk boundary, and continuing would walk garbage:
		// the walk would "skip" by a nonsense size, land somewhere arbitrary, and
		// eventually hit EOF — at which point the loop breaks and reports success on a
		// file it never read. Stop and say so instead.
		if !isPrintableChunkID(header.ID) {
			metadata.ExtractionWarning = "audio metadata may be incomplete: the WAV chunk " +
				"layout could not be followed past an unrecognized chunk header, so any " +
				"metadata after that point was not read"
			return nil
		}

		// Where this chunk's DATA starts, so the walk can reposition AUTHORITATIVELY
		// after parsing it.
		//
		// Every derailment this extractor has produced came from the same assumption:
		// that each chunk parser consumes exactly header.Size bytes and leaves the
		// reader on the next boundary. They do not. parseFormatChunk reads a fixed 16
		// bytes even when the chunk declares fewer, parseListChunk's skip arithmetic
		// underflows for a size below 4, and its error path used to seek header.Size
		// FURTHER from a position already inside the chunk. Each of those silently moved
		// the walk somewhere arbitrary.
		//
		// Seeking to a computed absolute offset makes the header the single source of
		// truth for where the next chunk begins, so a parser that reads too much or too
		// little can no longer derail anything after it.
		dataStart, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}

		switch chunkID {
		case "fmt ":
			if err := e.parseFormatChunk(file, header.Size, metadata); err != nil {
				return err
			}
		case "LIST":
			// A malformed LIST costs its own metadata, not the rest of the file: the
			// absolute reposition below puts the walk back on the next chunk boundary
			// regardless of where this parse stopped.
			if err := e.parseListChunk(file, header.Size, metadata); err != nil &&
				metadata.ExtractionWarning == "" {
				metadata.ExtractionWarning = "audio metadata may be incomplete: a WAV " +
					"LIST chunk could not be parsed, so the fields it holds were not read"
			}
		default:
			// Unknown chunk. Nothing to read; the reposition below skips it.
		}

		if _, err := file.Seek(dataStart+int64(header.Size), io.SeekStart); err != nil {
			return err
		}

		_, missing, err := consumePadByte(file, header.Size)
		if err != nil {
			return err
		}
		if missing {
			sawMissingPad = true
		}
	}

	// Recovered, but say so: the file is not RIFF-compliant, and an operator who cares
	// whether their corpus is intact should know the tool had to compensate. Never
	// overwrite a more specific warning already set above.
	if sawMissingPad && metadata.ExtractionWarning == "" {
		metadata.ExtractionWarning = padByteNote
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

// fmtChunkBodySize is the number of bytes WAVFormatChunk occupies on disk. binary.Read
// consumes exactly this many, so a chunk declaring fewer would be read past its own end
// and produce format values assembled partly from whatever follows.
const fmtChunkBodySize = 16

// parseFormatChunk parses the WAV format chunk.
//
// The caller repositions to the end of this chunk afterwards, so this function does not
// skip any trailing bytes itself; it only needs to avoid reading values it cannot trust.
func (e *WAVExtractor) parseFormatChunk(file *os.File, size uint32, metadata *AudioMetadata) error {
	if size < fmtChunkBodySize {
		// A short fmt chunk is malformed. Reading it anyway would report a sample rate and
		// bitrate partly composed of the next chunk's bytes, which is worse than reporting
		// nothing: the numbers look plausible and nothing marks them as invented.
		if metadata.ExtractionWarning == "" {
			metadata.ExtractionWarning = "audio metadata may be incomplete: the WAV format " +
				"chunk is shorter than the format record it declares, so the technical " +
				"properties were not read"
		}
		return nil
	}

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

	return nil
}

// listTypeSize is the four-byte form type ("INFO") that opens a LIST chunk's data.
const listTypeSize = 4

// parseListChunk parses LIST chunks which may contain INFO metadata.
func (e *WAVExtractor) parseListChunk(file *os.File, size uint32, metadata *AudioMetadata) error {
	// size is a uint32 straight from the file, so `size - listTypeSize` underflows to
	// roughly 4GB for any size below 4 and every length derived from it is nonsense.
	if size < listTypeSize {
		return fmt.Errorf("LIST chunk size %d is smaller than its form type", size)
	}

	listType := make([]byte, listTypeSize)
	if _, err := io.ReadFull(file, listType); err != nil {
		return err
	}

	if string(listType) != "INFO" {
		// Not INFO, so there is nothing here to extract. The caller repositions past the
		// chunk, so no skip is needed.
		return nil
	}

	return e.parseInfoChunks(file, size-listTypeSize, metadata)
}

// infoHeaderSize is the per-field ID+size header inside a LIST/INFO chunk.
const infoHeaderSize = 8

// parseInfoChunks parses INFO chunks within a LIST chunk.
//
// These are the fields that carry personal data — IART (artist), ICMT (comment), ICOP
// (copyright), IENG (engineer) — so a walk that derails here loses exactly the metadata
// the scan exists to find, and loses it silently.
func (e *WAVExtractor) parseInfoChunks(file *os.File, totalSize uint32, metadata *AudioMetadata) error {
	bytesRead := uint32(0)
	sawMissingPad := false

	// A trailing remainder too small to hold a header is malformed, not a field; reading
	// it would consume bytes belonging to the next chunk.
	for totalSize-bytesRead >= infoHeaderSize {
		var header WAVChunkHeader
		if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
			return err
		}
		bytesRead += infoHeaderSize

		// header.Size is attacker-controlled and reached make() unchecked. A 60-byte
		// fixture declaring 0xC0000000 drove 6.1GB of peak RSS at exit 0, and the same
		// allocation is reachable by accident: one missing pad byte misaligns the reader
		// so a size field is assembled from a field ID and its data, which measured
		// 1.7GB from a 102-byte file. Bounding it by the bytes actually left in the LIST
		// makes the allocation proportional to the file and costs nothing on valid input.
		if header.Size > totalSize-bytesRead {
			if metadata.ExtractionWarning == "" {
				metadata.ExtractionWarning = "audio metadata may be incomplete: a WAV INFO " +
					"field declares more data than its containing chunk holds, so that " +
					"field and any after it were not read"
			}
			return nil
		}

		chunkData := make([]byte, header.Size)
		// ReadFull, not Read: a short Read returns n<len with a nil error, which used to
		// leave the walk misaligned by however many bytes were missing while looking like
		// a clean parse.
		if _, err := io.ReadFull(file, chunkData); err != nil {
			return err
		}
		bytesRead += header.Size

		e.parseInfoField(string(header.ID[:]), chunkData, metadata)

		consumed, missing, err := consumePadByte(file, header.Size)
		if err != nil {
			return err
		}
		bytesRead += uint32(consumed)
		if missing {
			sawMissingPad = true
		}
	}

	if sawMissingPad && metadata.ExtractionWarning == "" {
		metadata.ExtractionWarning = padByteNote
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
