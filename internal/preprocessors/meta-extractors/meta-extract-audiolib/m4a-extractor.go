// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// M4AExtractor handles M4A (MPEG-4 Audio) file metadata extraction
type M4AExtractor struct{}

// ExtractMetadata extracts metadata from M4A files
func (e *M4AExtractor) ExtractMetadata(filePath string) (*AudioMetadata, error) {
	return e.ExtractMetadataWithContext(context.Background(), filePath)
}

// CanProcess checks if the file can be processed by this extractor
func (e *M4AExtractor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".m4a"
}

// GetSupportedFormats returns supported file formats
func (e *M4AExtractor) GetSupportedFormats() []string {
	return []string{".m4a"}
}

// ExtractMetadataWithContext extracts metadata from M4A files with context support
func (e *M4AExtractor) ExtractMetadataWithContext(ctx context.Context, filePath string) (*AudioMetadata, error) {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, NewAudioProcessingError(filePath, "file_access", "failed to get file info", err)
	}

	// Initialize metadata with basic file information
	metadata := &AudioMetadata{
		Filename: filepath.Base(filePath),
		FileSize: fileInfo.Size(),
		ModTime:  fileInfo.ModTime(),
		MimeType: "audio/mp4",
		Codec:    "AAC",
	}

	// Open file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return nil, NewAudioProcessingError(filePath, "file_access", "failed to open file", err)
	}
	defer file.Close()

	// Parse M4A container (similar to MP4 but focus on audio metadata)
	err = e.parseM4AContainer(ctx, file, metadata)
	if err != nil {
		return nil, NewAudioProcessingError(filePath, "tag_extraction", "failed to parse M4A container", err)
	}

	// If no title was found in metadata, use filename as fallback (common for voice recordings)
	if metadata.Title == "" {
		// Remove extension and use as title
		filename := filepath.Base(filePath)
		if ext := filepath.Ext(filename); ext != "" {
			metadata.Title = filename[:len(filename)-len(ext)]
		} else {
			metadata.Title = filename
		}
	}

	return metadata, nil
}

// parseM4AContainer parses the M4A container structure for metadata
func (e *M4AExtractor) parseM4AContainer(ctx context.Context, file *os.File, metadata *AudioMetadata) error {
	// M4A files use the same container format as MP4
	// We'll parse the basic structure to extract metadata atoms

	buffer := make([]byte, 8) // For reading box headers

	boxCount := 0
	for {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read box header (size + type)
		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break // End of file or error
		}

		// Parse box size (big-endian)
		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		boxCount++

		// Handle extended size (64-bit)
		if boxSize == 1 {
			// Read the 64-bit size
			extSizeBuffer := make([]byte, 8)
			n, err := file.Read(extSizeBuffer)
			if err != nil || n < 8 {
				break
			}

			// Parse 64-bit size
			extSize := uint64(extSizeBuffer[0])<<56 | uint64(extSizeBuffer[1])<<48 |
				uint64(extSizeBuffer[2])<<40 | uint64(extSizeBuffer[3])<<32 |
				uint64(extSizeBuffer[4])<<24 | uint64(extSizeBuffer[5])<<16 |
				uint64(extSizeBuffer[6])<<8 | uint64(extSizeBuffer[7])

			// Convert to 32-bit for processing (subtract the 16 bytes for headers)
			// Additional safety: ensure the subtraction result fits in uint32
			if extSize > 16 && extSize < 100*1024*1024 {
				adjustedSize := extSize - 16
				if adjustedSize <= math.MaxUint32 {
					boxSize = uint32(adjustedSize) // Subtract 8 bytes box header + 8 bytes extended size
				} else {
					break
				}
			} else {
				break
			}
		} else if boxSize == 0 {
			// Box extends to end of file - skip for safety
			break
		} else if boxSize < 8 {
			break
		} else {
			// Normal size, subtract the 8-byte header
			boxSize -= 8
		}

		// Handle specific box types
		switch boxType {
		case "moov":
			// Movie box - contains metadata
			err = e.parseMoovBox(ctx, file, boxSize, metadata)
			if err != nil {
				return err
			}
		case "ftyp":
			// File type box - skip but validate
			_, err = file.Seek(int64(boxSize), 1)
			if err != nil {
				return err
			}
		case "mdat":
			// Media data - skip
			_, err = file.Seek(int64(boxSize), 1)
			if err != nil {
				return err
			}
		default:
			// Skip unknown boxes
			_, err = file.Seek(int64(boxSize), 1)
			if err != nil {
				return err
			}
		}

		// Safety check to prevent infinite loops
		if boxCount > 100 {
			break
		}
	}

	return nil
}

// parseMoovBox parses the movie box for metadata
func (e *M4AExtractor) parseMoovBox(ctx context.Context, file *os.File, size uint32, metadata *AudioMetadata) error {
	startPos, err := file.Seek(0, 1) // Get current position
	if err != nil {
		return err
	}

	endPos := startPos + int64(size)
	buffer := make([]byte, 8)

	for {
		// Check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentPos, err := file.Seek(0, 1)
		if err != nil || currentPos >= endPos {
			break
		}

		// Read sub-box header
		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break
		}

		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		if boxSize < 8 {
			break
		}

		switch boxType {
		case "mvhd":
			// Movie header - contains duration and timestamps
			err = e.parseMvhdBox(file, boxSize-8, metadata)
		case "udta":
			// User data - contains metadata tags
			err = e.parseUdtaBox(ctx, file, boxSize-8, metadata)
		case "trak":
			// Track - may contain audio format info
			err = e.parseTrakBox(ctx, file, boxSize-8, metadata)
		default:
			// Skip unknown boxes
			_, err = file.Seek(int64(boxSize-8), 1)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

// parseMvhdBox parses movie header for duration and timestamps
func (e *M4AExtractor) parseMvhdBox(file *os.File, size uint32, metadata *AudioMetadata) error {
	if size < 24 {
		return fmt.Errorf("mvhd box too small")
	}

	buffer := make([]byte, size)
	_, err := file.Read(buffer)
	if err != nil {
		return err
	}

	// Parse version and flags (4 bytes)
	version := buffer[0]

	var creationTime, timeScale, duration uint32

	if version == 0 {
		// Version 0: 32-bit values
		if size >= 24 {
			creationTime = uint32(buffer[4])<<24 | uint32(buffer[5])<<16 | uint32(buffer[6])<<8 | uint32(buffer[7])
			_ = uint32(buffer[8])<<24 | uint32(buffer[9])<<16 | uint32(buffer[10])<<8 | uint32(buffer[11]) // modificationTime (unused)
			timeScale = uint32(buffer[12])<<24 | uint32(buffer[13])<<16 | uint32(buffer[14])<<8 | uint32(buffer[15])
			duration = uint32(buffer[16])<<24 | uint32(buffer[17])<<16 | uint32(buffer[18])<<8 | uint32(buffer[19])
		}
	}

	// Convert MP4 time to Unix time (MP4 epoch is 1904-01-01)
	if creationTime > 2082844800 { // Valid MP4 timestamp
		unixTime := int64(creationTime - 2082844800)
		metadata.RecordingDate = time.Unix(unixTime, 0)
	}

	// Calculate duration
	if timeScale > 0 && duration > 0 {
		metadata.Duration = time.Duration(duration) * time.Second / time.Duration(timeScale)
	}

	return nil
}

// parseUdtaBox parses user data box for metadata tags
func (e *M4AExtractor) parseUdtaBox(ctx context.Context, file *os.File, size uint32, metadata *AudioMetadata) error {
	startPos, err := file.Seek(0, 1)
	if err != nil {
		return err
	}

	endPos := startPos + int64(size)
	buffer := make([]byte, 8)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentPos, err := file.Seek(0, 1)
		if err != nil || currentPos >= endPos {
			break
		}

		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break
		}

		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		if boxSize < 8 || currentPos+int64(boxSize) > endPos {
			break
		}

		// Adjust box size to exclude header
		contentSize := boxSize - 8

		// Parse metadata atoms
		switch boxType {
		case "meta":
			// iTunes-style metadata container
			err = e.parseMetaBox(ctx, file, contentSize, metadata)
			if err != nil {
				return err
			}
		case "©nam": // Title (legacy format)
			value := e.readStringAtom(file, contentSize)
			if value != "" {
				metadata.Title = value
			}
		case "©ART": // Artist (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Artist = value
		case "©alb": // Album (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Album = value
		case "©day": // Year (legacy format)
			yearStr := e.readStringAtom(file, contentSize)
			if len(yearStr) >= 4 {
				if year := parseInt(yearStr[:4]); year > 0 {
					metadata.Year = year
				}
			}
		case "©gen": // Genre (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Genre = value
		case "©cmt": // Comment (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Comment = value
		case "©wrt": // Composer (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Composer = value
		case "©cpy": // Copyright (legacy format)
			value := e.readStringAtom(file, contentSize)
			metadata.Copyright = value
		case "date": // Date (legacy format - different from ©day)
			value := e.readStringAtom(file, contentSize)
			if metadata.Properties == nil {
				metadata.Properties = make(map[string]string)
			}
			metadata.Properties["date"] = value
		default:
			// Store unknown atoms in properties for potential sensitive data
			value := e.readStringAtom(file, contentSize)
			if metadata.Properties == nil {
				metadata.Properties = make(map[string]string)
			}
			// Store all atoms with values, using cleaned box type names
			if len(boxType) == 4 && value != "" {
				cleanBoxType := e.cleanBoxType(boxType)
				metadata.Properties[cleanBoxType] = value
			} else {
				// Skip if we couldn't read the value
				_, err = file.Seek(int64(contentSize), 1)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// parseMetaBox parses iTunes-style metadata container
func (e *M4AExtractor) parseMetaBox(ctx context.Context, file *os.File, size uint32, metadata *AudioMetadata) error {
	if size < 4 {
		return fmt.Errorf("meta box too small")
	}

	// Skip version and flags (4 bytes)
	versionBuffer := make([]byte, 4)
	_, err := file.Read(versionBuffer)
	if err != nil {
		return err
	}

	remainingSize := size - 4
	startPos, err := file.Seek(0, 1)
	if err != nil {
		return err
	}

	endPos := startPos + int64(remainingSize)
	buffer := make([]byte, 8)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentPos, err := file.Seek(0, 1)
		if err != nil || currentPos >= endPos {
			break
		}

		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break
		}

		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		if boxSize < 8 || currentPos+int64(boxSize) > endPos {
			break
		}

		switch boxType {
		case "hdlr":
			// Handler reference - skip
			_, err = file.Seek(int64(boxSize-8), 1)
			if err != nil {
				return err
			}
		case "ilst":
			// iTunes metadata list - this contains the actual metadata
			err = e.parseIlstBox(ctx, file, boxSize-8, metadata)
			if err != nil {
				return err
			}
		default:
			// Skip other boxes
			_, err = file.Seek(int64(boxSize-8), 1)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// parseIlstBox parses iTunes metadata list
func (e *M4AExtractor) parseIlstBox(ctx context.Context, file *os.File, size uint32, metadata *AudioMetadata) error {
	startPos, err := file.Seek(0, 1)
	if err != nil {
		return err
	}

	endPos := startPos + int64(size)
	buffer := make([]byte, 8)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		currentPos, err := file.Seek(0, 1)
		if err != nil || currentPos >= endPos {
			break
		}

		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break
		}

		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		if boxSize < 8 || currentPos+int64(boxSize) > endPos {
			break
		}

		// Parse iTunes metadata tags
		value := e.readItunesTag(file, boxSize-8)

		if value != "" {
			// Clean the box type to handle non-printable characters
			cleanBoxType := e.cleanBoxType(boxType)

			// Handle atoms by byte comparison for proper Unicode handling
			atomBytes := []byte(boxType)

			switch {
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'n' && atomBytes[2] == 'a' && atomBytes[3] == 'm': // ©nam
				if value != "" {
					metadata.Title = value
				}
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'A' && atomBytes[2] == 'R' && atomBytes[3] == 'T': // ©ART
				metadata.Artist = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'a' && atomBytes[2] == 'l' && atomBytes[3] == 'b': // ©alb
				metadata.Album = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'd' && atomBytes[2] == 'a' && atomBytes[3] == 'y': // ©day
				if len(value) >= 4 {
					if year := parseInt(value[:4]); year > 0 {
						metadata.Year = year
					}
				}
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'g' && atomBytes[2] == 'e' && atomBytes[3] == 'n': // ©gen
				metadata.Genre = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'c' && atomBytes[2] == 'm' && atomBytes[3] == 't': // ©cmt
				metadata.Comment = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'w' && atomBytes[2] == 'r' && atomBytes[3] == 't': // ©wrt
				metadata.Composer = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'c' && atomBytes[2] == 'p' && atomBytes[3] == 'y': // ©cpy
				metadata.Copyright = value
			case boxType == "aART":
				metadata.AlbumArtist = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'g' && atomBytes[2] == 'r' && atomBytes[3] == 'p': // ©grp
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["Grouping"] = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'l' && atomBytes[2] == 'y' && atomBytes[3] == 'r': // ©lyr
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["Lyrics"] = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 't' && atomBytes[2] == 'o' && atomBytes[3] == 'o': // ©too
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["EncodingTool"] = value
			case len(atomBytes) == 4 && atomBytes[0] == 0xA9 && atomBytes[1] == 'e' && atomBytes[2] == 'n' && atomBytes[3] == 'c': // ©enc
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["EncodedBy"] = value
			case boxType == "cprt":
				if metadata.Copyright == "" {
					metadata.Copyright = value
				}
			case boxType == "desc":
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["Description"] = value
			case boxType == "ldes":
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["LongDescription"] = value
			case boxType == "----": // Custom/freeform metadata
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				metadata.Properties["CustomField"] = value
			default:
				// Store unknown tags in properties for potential sensitive data
				if metadata.Properties == nil {
					metadata.Properties = make(map[string]string)
				}
				// Only store if the box type contains printable characters
				if value != "" {
					metadata.Properties[cleanBoxType] = value
				}
			}
		} else {
			// Skip if we couldn't read the value
			_, err = file.Seek(int64(boxSize-8), 1)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// readItunesTag reads an iTunes-style metadata tag value
func (e *M4AExtractor) readItunesTag(file *os.File, size uint32) string {
	if size == 0 || size > 10240 { // Limit to 10KB per tag
		return ""
	}

	startPos, err := file.Seek(0, 1)
	if err != nil {
		return ""
	}

	endPos := startPos + int64(size)
	buffer := make([]byte, 8)

	for {
		currentPos, err := file.Seek(0, 1)
		if err != nil || currentPos >= endPos {
			break
		}

		n, err := file.Read(buffer)
		if err != nil || n < 8 {
			break
		}

		boxSize := uint32(buffer[0])<<24 | uint32(buffer[1])<<16 | uint32(buffer[2])<<8 | uint32(buffer[3])
		boxType := string(buffer[4:8])

		if boxSize < 8 || currentPos+int64(boxSize) > endPos {
			break
		}

		if boxType == "data" {
			// This is the actual data container
			if boxSize >= 16 { // 8 bytes header + 8 bytes data header minimum
				dataHeader := make([]byte, 8)
				_, err := file.Read(dataHeader)
				if err != nil {
					break
				}

				// Read the actual string data
				textSize := boxSize - 16 // Total size - box header - data header
				if textSize > 0 && textSize < 10240 {
					textData := make([]byte, textSize)
					n, err := file.Read(textData)
					if err == nil && n > 0 {
						// Return the string, trimming null bytes and whitespace
						result := strings.TrimSpace(string(textData[:n]))
						result = strings.Trim(result, "\x00")
						return result
					}
				}
			}
			break
		} else {
			// Skip non-data boxes
			_, err = file.Seek(int64(boxSize-8), 1)
			if err != nil {
				break
			}
		}
	}

	// If we couldn't find a data box, seek to the end of this tag
	file.Seek(endPos, 0)
	return ""
}

// parseTrakBox parses track box for audio format information
func (e *M4AExtractor) parseTrakBox(ctx context.Context, file *os.File, size uint32, metadata *AudioMetadata) error {
	// For now, just skip the track box
	// In a full implementation, we would parse the track header and media info
	_, err := file.Seek(int64(size), 1)
	return err
}

// readStringAtom reads a string value from an atom
func (e *M4AExtractor) readStringAtom(file *os.File, size uint32) string {
	if size == 0 || size > 1024 { // Limit string size
		return ""
	}

	buffer := make([]byte, size)
	n, err := file.Read(buffer)
	if err != nil || n == 0 {
		return ""
	}

	// M4A strings are typically UTF-8, clean up the string
	result := string(buffer[:n])
	// Remove null bytes and control characters
	cleaned := ""
	for _, r := range result {
		if r >= 32 && r < 127 || r > 127 { // Printable ASCII or Unicode
			cleaned += string(r)
		}
	}
	return strings.TrimSpace(cleaned)
}

// parseInt safely parses an integer from a string
func parseInt(s string) int {
	if len(s) == 0 {
		return 0
	}

	result := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int(r-'0')
		} else {
			break
		}
	}
	return result
}

// cleanBoxType cleans box type strings to remove non-printable characters
func (e *M4AExtractor) cleanBoxType(boxType string) string {
	// Handle known iTunes metadata atoms with proper names using byte comparison
	atomBytes := []byte(boxType)

	if len(atomBytes) == 4 {
		switch {
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'n' && atomBytes[2] == 'a' && atomBytes[3] == 'm': // ©nam
			return "Title"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'A' && atomBytes[2] == 'R' && atomBytes[3] == 'T': // ©ART
			return "Artist"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'a' && atomBytes[2] == 'l' && atomBytes[3] == 'b': // ©alb
			return "Album"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'd' && atomBytes[2] == 'a' && atomBytes[3] == 'y': // ©day
			return "Date"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'g' && atomBytes[2] == 'e' && atomBytes[3] == 'n': // ©gen
			return "Genre"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'c' && atomBytes[2] == 'm' && atomBytes[3] == 't': // ©cmt
			return "Comment"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'w' && atomBytes[2] == 'r' && atomBytes[3] == 't': // ©wrt
			return "Composer"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'c' && atomBytes[2] == 'p' && atomBytes[3] == 'y': // ©cpy
			return "Copyright"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 't' && atomBytes[2] == 'o' && atomBytes[3] == 'o': // ©too
			return "EncodingTool"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'e' && atomBytes[2] == 'n' && atomBytes[3] == 'c': // ©enc
			return "EncodedBy"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'g' && atomBytes[2] == 'r' && atomBytes[3] == 'p': // ©grp
			return "Grouping"
		case atomBytes[0] == 0xA9 && atomBytes[1] == 'l' && atomBytes[2] == 'y' && atomBytes[3] == 'r': // ©lyr
			return "Lyrics"
		}
	}

	// Handle other known atoms
	switch boxType {
	case "aART":
		return "AlbumArtist"
	case "----":
		return "CustomField"
	}

	// For unknown atoms, create a readable name
	cleaned := ""
	for _, r := range boxType {
		if r >= 32 && r <= 126 { // Printable ASCII characters
			cleaned += string(r)
		} else {
			cleaned += fmt.Sprintf("\\x%02x", r)
		}
	}
	return cleaned
}

// isPrintableBoxType checks if a box type contains only printable characters
func (e *M4AExtractor) isPrintableBoxType(boxType string) bool {
	for _, r := range boxType {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// Ensure M4AExtractor implements the required interfaces
var _ AudioMetadataExtractor = (*M4AExtractor)(nil)
var _ AudioMetadataExtractorWithContext = (*M4AExtractor)(nil)
