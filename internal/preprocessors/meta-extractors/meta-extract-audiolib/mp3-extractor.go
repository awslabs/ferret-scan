// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Constants for MP3 processing
const (
	MaxID3v2Size = 1024 * 1024 // 1MB limit for ID3v2 tags
)

// MP3Extractor handles MP3 file metadata extraction
type MP3Extractor struct{}

// ID3v2Header represents the ID3v2 tag header
type ID3v2Header struct {
	Version [2]byte
	Flags   byte
	Size    uint32
}

// ID3v2Frame represents an ID3v2 frame
type ID3v2Frame struct {
	ID    [4]byte
	Size  uint32
	Flags [2]byte
	Data  []byte
}

// ID3v1Tag represents the legacy ID3v1 tag structure
type ID3v1Tag struct {
	Header  [3]byte // "TAG" signature
	Title   [30]byte
	Artist  [30]byte
	Album   [30]byte
	Year    [4]byte
	Comment [30]byte
	Genre   byte
}

// ExtractMetadata extracts metadata from an MP3 file
func (e *MP3Extractor) ExtractMetadata(filePath string) (*AudioMetadata, error) {
	return e.ExtractMetadataWithContext(context.Background(), filePath)
}

// ExtractMetadataWithContext extracts metadata from an MP3 file with context and resource limits
func (e *MP3Extractor) ExtractMetadataWithContext(ctx context.Context, filePath string) (*AudioMetadata, error) {
	// Check file size first
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, NewAudioProcessingError(filePath, "file_access", "failed to get file stats", err)
	}

	if stat.Size() > MaxAudioFileSize {
		return nil, NewAudioProcessingError(filePath, "file_size",
			fmt.Sprintf("file too large: %d bytes (max %d)", stat.Size(), MaxAudioFileSize), nil)
	}

	metadata := &AudioMetadata{
		Filename:   stat.Name(),
		FileSize:   stat.Size(),
		ModTime:    stat.ModTime(),
		MimeType:   "audio/mpeg",
		Properties: make(map[string]string),
	}

	// Use optimized reader for better performance
	reader, err := NewOptimizedMP3Reader(filePath)
	if err != nil {
		return nil, NewAudioProcessingError(filePath, "file_access", "failed to create optimized reader", err)
	}
	defer reader.Close()

	// Try ID3v2 first (at beginning of file) with context and optimized reading
	if err := e.extractID3v2Optimized(ctx, reader, metadata); err != nil {
		// If ID3v2 fails, try ID3v1 (at end of file) with context and optimized reading
		if err := e.extractID3v1Optimized(ctx, reader, metadata); err != nil {
			return metadata, NewAudioProcessingError(filePath, "tag_extraction", "failed to extract ID3 tags", err)
		}
	}

	return metadata, nil
}

// extractID3v2 extracts ID3v2 tags from the beginning of the file
func (e *MP3Extractor) extractID3v2(file *os.File, metadata *AudioMetadata) error {
	return e.extractID3v2WithContext(context.Background(), file, metadata)
}

// extractID3v2WithContext extracts ID3v2 tags from the beginning of the file with context
func (e *MP3Extractor) extractID3v2WithContext(ctx context.Context, file *os.File, metadata *AudioMetadata) error {
	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Seek to beginning
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Read ID3v2 header
	var header [10]byte
	if _, err := file.Read(header[:]); err != nil {
		return err
	}

	// Check for ID3v2 signature
	if string(header[0:3]) != "ID3" {
		return fmt.Errorf("no ID3v2 header found")
	}

	id3Header := ID3v2Header{
		Version: [2]byte{header[3], header[4]},
		Flags:   header[5],
		Size:    synchsafeToUint32(header[6:10]),
	}

	// Check tag size limit
	if id3Header.Size > MaxID3v2Size {
		return fmt.Errorf("ID3v2 tag too large: %d bytes (max %d)", id3Header.Size, MaxID3v2Size)
	}

	// Check context before reading tag data
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Read tag data
	tagData := make([]byte, id3Header.Size)
	if _, err := file.Read(tagData); err != nil {
		return err
	}

	// Parse frames with context
	return e.parseID3v2FramesWithContext(ctx, tagData, metadata, id3Header.Version[0])
}

// parseID3v2Frames parses ID3v2 frames from tag data
func (e *MP3Extractor) parseID3v2Frames(data []byte, metadata *AudioMetadata, version byte) error {
	return e.parseID3v2FramesWithContext(context.Background(), data, metadata, version)
}

// parseID3v2FramesWithContext parses ID3v2 frames from tag data with context
func (e *MP3Extractor) parseID3v2FramesWithContext(ctx context.Context, data []byte, metadata *AudioMetadata, version byte) error {
	offset := 0

	for offset < len(data)-10 {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check for padding (null bytes)
		if data[offset] == 0 {
			break
		}

		// Read frame header
		frameID := string(data[offset : offset+4])
		offset += 4

		var frameSize uint32
		if version >= 4 {
			// ID3v2.4 uses synchsafe integers
			frameSize = synchsafeToUint32(data[offset : offset+4])
		} else {
			// ID3v2.3 uses regular integers
			frameSize = binary.BigEndian.Uint32(data[offset : offset+4])
		}
		offset += 4

		// Skip frame flags
		offset += 2

		// Ensure we don't read beyond data bounds
		if offset+int(frameSize) > len(data) {
			break
		}

		frameData := data[offset : offset+int(frameSize)]
		offset += int(frameSize)

		// Parse frame content
		e.parseFrameContent(frameID, frameData, metadata)
	}

	return nil
}

// parseFrameContent parses the content of a specific ID3v2 frame
func (e *MP3Extractor) parseFrameContent(frameID string, data []byte, metadata *AudioMetadata) {
	if len(data) == 0 {
		return
	}

	// Skip text encoding byte for text frames
	textData := data
	if len(data) > 1 && (data[0] == 0 || data[0] == 1 || data[0] == 2 || data[0] == 3) {
		textData = data[1:]
	}

	// Convert to string and clean up
	content := strings.TrimRight(string(textData), "\x00")

	switch frameID {
	case "TIT2": // Title
		metadata.Title = content
	case "TPE1": // Artist
		metadata.Artist = content
	case "TALB": // Album
		metadata.Album = content
	case "TPE2": // Album Artist
		metadata.AlbumArtist = content
	case "TYER", "TDRC": // Year/Recording Date
		if year := parseYear(content); year > 0 {
			metadata.Year = year
		}
	case "TCON": // Genre
		metadata.Genre = content
	case "TRCK": // Track number
		if track := parseTrackNumber(content); track > 0 {
			metadata.Track = track
		}
	case "COMM": // Comment
		metadata.Comment = content
	case "TCOM": // Composer
		metadata.Composer = content
	case "TPE3": // Conductor
		metadata.Conductor = content
	case "TPUB": // Publisher
		metadata.Publisher = content
	case "TCOP": // Copyright
		metadata.Copyright = content
	default:
		// Store unknown frames in properties
		if content != "" {
			metadata.Properties[frameID] = content
		}
	}
}

// extractID3v1 extracts ID3v1 tags from the end of the file
func (e *MP3Extractor) extractID3v1(file *os.File, metadata *AudioMetadata) error {
	return e.extractID3v1WithContext(context.Background(), file, metadata)
}

// extractID3v1WithContext extracts ID3v1 tags from the end of the file with context
func (e *MP3Extractor) extractID3v1WithContext(ctx context.Context, file *os.File, metadata *AudioMetadata) error {
	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Seek to 128 bytes from end
	if _, err := file.Seek(-128, io.SeekEnd); err != nil {
		return err
	}

	var tag ID3v1Tag
	if err := binary.Read(file, binary.LittleEndian, &tag); err != nil {
		return err
	}

	// Check for TAG signature using the Header field
	if string(tag.Header[:]) != "TAG" {
		return fmt.Errorf("no ID3v1 tag found")
	}

	// Extract fields (only if not already set by ID3v2)
	if metadata.Title == "" {
		metadata.Title = strings.TrimRight(string(tag.Title[:]), "\x00")
	}
	if metadata.Artist == "" {
		metadata.Artist = strings.TrimRight(string(tag.Artist[:]), "\x00")
	}
	if metadata.Album == "" {
		metadata.Album = strings.TrimRight(string(tag.Album[:]), "\x00")
	}
	if metadata.Year == 0 {
		if year := parseYear(strings.TrimRight(string(tag.Year[:]), "\x00")); year > 0 {
			metadata.Year = year
		}
	}
	if metadata.Comment == "" {
		metadata.Comment = strings.TrimRight(string(tag.Comment[:]), "\x00")
	}

	return nil
}

// CanProcess checks if the file can be processed as MP3
func (e *MP3Extractor) CanProcess(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".mp3"
}

// GetSupportedFormats returns supported file formats
func (e *MP3Extractor) GetSupportedFormats() []string {
	return []string{".mp3"}
}

// OptimizedMP3Reader provides optimized reading for MP3 files
type OptimizedMP3Reader struct {
	file     *os.File
	fileSize int64
	position int64
}

// NewOptimizedMP3Reader creates a new optimized MP3 reader
func NewOptimizedMP3Reader(filePath string) (*OptimizedMP3Reader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	return &OptimizedMP3Reader{
		file:     file,
		fileSize: stat.Size(),
		position: 0,
	}, nil
}

// ReadID3v2Header reads ID3v2 header efficiently
func (omr *OptimizedMP3Reader) ReadID3v2Header() (*ID3v2Header, error) {
	// Seek to beginning
	if _, err := omr.file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	omr.position = 0

	// Read ID3v2 header
	var header [10]byte
	if _, err := omr.file.Read(header[:]); err != nil {
		return nil, err
	}
	omr.position += 10

	// Check for ID3v2 signature
	if string(header[0:3]) != "ID3" {
		return nil, fmt.Errorf("no ID3v2 header found")
	}

	return &ID3v2Header{
		Version: [2]byte{header[3], header[4]},
		Flags:   header[5],
		Size:    synchsafeToUint32(header[6:10]),
	}, nil
}

// ReadID3v2Data reads ID3v2 tag data with size limit
func (omr *OptimizedMP3Reader) ReadID3v2Data(size uint32) ([]byte, error) {
	// Check size limit
	if size > MaxID3v2Size {
		return nil, fmt.Errorf("ID3v2 tag too large: %d bytes (max %d)", size, MaxID3v2Size)
	}

	// Only read up to MaxMetadataRead to avoid reading entire large files
	readSize := size
	if int64(readSize) > MaxMetadataRead {
		readSize = uint32(MaxMetadataRead)
	}

	data := make([]byte, readSize)
	n, err := omr.file.Read(data)
	if err != nil {
		return nil, err
	}

	omr.position += int64(n)
	return data[:n], nil
}

// SeekToID3v1 seeks to ID3v1 tag at end of file
func (omr *OptimizedMP3Reader) SeekToID3v1() error {
	// Seek to 128 bytes from end
	if _, err := omr.file.Seek(-128, io.SeekEnd); err != nil {
		return err
	}
	omr.position = omr.fileSize - 128
	return nil
}

// ReadID3v1Tag reads ID3v1 tag
func (omr *OptimizedMP3Reader) ReadID3v1Tag() (*ID3v1Tag, error) {
	var tag ID3v1Tag
	if err := binary.Read(omr.file, binary.LittleEndian, &tag); err != nil {
		return nil, err
	}
	omr.position += 128
	return &tag, nil
}

// GetPosition returns current position
func (omr *OptimizedMP3Reader) GetPosition() int64 {
	return omr.position
}

// GetFileSize returns file size
func (omr *OptimizedMP3Reader) GetFileSize() int64 {
	return omr.fileSize
}

// Close closes the reader
func (omr *OptimizedMP3Reader) Close() error {
	return omr.file.Close()
}

// extractID3v2Optimized extracts ID3v2 tags using optimized reader
func (e *MP3Extractor) extractID3v2Optimized(ctx context.Context, reader *OptimizedMP3Reader, metadata *AudioMetadata) error {
	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Read ID3v2 header
	header, err := reader.ReadID3v2Header()
	if err != nil {
		return err
	}

	// Check context before reading tag data
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Read tag data with size limit
	tagData, err := reader.ReadID3v2Data(header.Size)
	if err != nil {
		return err
	}

	// Parse frames with context
	return e.parseID3v2FramesWithContext(ctx, tagData, metadata, header.Version[0])
}

// extractID3v1Optimized extracts ID3v1 tags using optimized reader
func (e *MP3Extractor) extractID3v1Optimized(ctx context.Context, reader *OptimizedMP3Reader, metadata *AudioMetadata) error {
	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Seek to ID3v1 tag
	if err := reader.SeekToID3v1(); err != nil {
		return err
	}

	// Read ID3v1 tag
	tag, err := reader.ReadID3v1Tag()
	if err != nil {
		return err
	}

	// Check for TAG signature using the Header field
	if string(tag.Header[:]) != "TAG" {
		return fmt.Errorf("no ID3v1 tag found")
	}

	// Extract fields (only if not already set by ID3v2)
	if metadata.Title == "" {
		metadata.Title = strings.TrimRight(string(tag.Title[:]), "\x00")
	}
	if metadata.Artist == "" {
		metadata.Artist = strings.TrimRight(string(tag.Artist[:]), "\x00")
	}
	if metadata.Album == "" {
		metadata.Album = strings.TrimRight(string(tag.Album[:]), "\x00")
	}
	if metadata.Year == 0 {
		if year := parseYear(strings.TrimRight(string(tag.Year[:]), "\x00")); year > 0 {
			metadata.Year = year
		}
	}
	if metadata.Comment == "" {
		metadata.Comment = strings.TrimRight(string(tag.Comment[:]), "\x00")
	}

	return nil
}

// synchsafeToUint32 converts a synchsafe integer to uint32
func synchsafeToUint32(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return uint32(data[0])<<21 | uint32(data[1])<<14 | uint32(data[2])<<7 | uint32(data[3])
}

// parseYear extracts year from various date formats
func parseYear(dateStr string) int {
	if dateStr == "" {
		return 0
	}

	// Try parsing as just year
	if year, err := strconv.Atoi(dateStr); err == nil && year > 1900 && year < 3000 {
		return year
	}

	// Try parsing ISO date format (YYYY-MM-DD)
	if len(dateStr) >= 4 {
		if year, err := strconv.Atoi(dateStr[:4]); err == nil && year > 1900 && year < 3000 {
			return year
		}
	}

	return 0
}

// parseTrackNumber extracts track number from track string (e.g., "3/12" -> 3)
func parseTrackNumber(trackStr string) int {
	if trackStr == "" {
		return 0
	}

	// Handle "track/total" format
	parts := strings.Split(trackStr, "/")
	trackPart := strings.TrimSpace(parts[0])

	if track, err := strconv.Atoi(trackPart); err == nil && track > 0 {
		return track
	}

	return 0
}
