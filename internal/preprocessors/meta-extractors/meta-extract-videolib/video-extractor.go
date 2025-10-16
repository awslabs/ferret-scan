// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// VideoMetadata represents extracted video file metadata
type VideoMetadata struct {
	// File information
	Filename string
	FileSize int64
	ModTime  time.Time
	MimeType string

	// Video-specific metadata
	Duration  time.Duration
	Width     int
	Height    int
	FrameRate float64
	Codec     string

	// Common metadata fields
	Title        string
	Description  string
	Author       string
	Creator      string
	Copyright    string
	CreatedDate  time.Time
	ModifiedDate time.Time

	// Location data
	GPSLatitude  float64
	GPSLongitude float64
	GPSAltitude  float64
	Location     string

	// Device information
	CameraMake  string
	CameraModel string
	Software    string

	// Additional properties
	Properties map[string]string
}

// MP4Box represents an MP4 atom/box structure
type MP4Box struct {
	Size   uint32
	Type   [4]byte
	Data   []byte
	Offset int64
}

// Constants for MP4 parsing
const (
	MaxFileSize       = 500 * 1024 * 1024 // 500MB limit
	MaxBoxSize        = 100 * 1024 * 1024 // 100MB per box limit
	BoxHeaderSize     = 8                 // 4 bytes size + 4 bytes type
	ExtendedBoxSize   = 16                // For 64-bit size boxes
	MaxMetadataRead   = 10 * 1024 * 1024  // Only read first 10MB for metadata
	ProcessingTimeout = 30 * time.Second  // 30 second timeout
)

// ExtractVideoMetadata extracts metadata from video files with resource limits
func ExtractVideoMetadata(filePath string) (*VideoMetadata, error) {
	cleanPath := filepath.Clean(filePath)
	if !filepath.IsAbs(cleanPath) {
		return nil, errors.New("relative paths are not allowed")
	}
	return ExtractVideoMetadataWithContext(context.Background(), cleanPath)
}

// ExtractVideoMetadataWithContext extracts metadata from video files with context and resource limits
func ExtractVideoMetadataWithContext(ctx context.Context, filePath string) (*VideoMetadata, error) {
	// Create processing context with timeout
	processCtx, cancel := context.WithTimeout(ctx, ProcessingTimeout)
	defer cancel()

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, NewVideoProcessingError(filePath, "file_access", "failed to get file info", err)
	}

	// Check file size limit
	if fileInfo.Size() > MaxFileSize {
		return nil, NewVideoProcessingError(filePath, "file_size",
			fmt.Sprintf("file too large: %d bytes (max %d)", fileInfo.Size(), MaxFileSize), nil)
	}

	// Initialize metadata structure
	metadata := &VideoMetadata{
		Filename:   filepath.Base(filePath),
		FileSize:   fileInfo.Size(),
		ModTime:    fileInfo.ModTime(),
		Properties: make(map[string]string),
	}

	// Determine MIME type based on extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".mp4", ".m4v":
		metadata.MimeType = "video/mp4"
	case ".mov":
		metadata.MimeType = "video/quicktime"
	default:
		metadata.MimeType = "video/unknown"
	}

	// Use optimized reader for better performance
	optimizedReader, err := NewOptimizedVideoReader(filePath)
	if err != nil {
		return nil, NewVideoProcessingError(filePath, "file_access", "failed to create optimized reader", err)
	}
	defer optimizedReader.Close()

	// Parse MP4/MOV container with optimized reading
	err = parseMP4ContainerOptimized(processCtx, optimizedReader, metadata)
	if err != nil {
		if processCtx.Err() == context.DeadlineExceeded {
			return nil, NewVideoProcessingError(filePath, "timeout", "processing timeout exceeded", err)
		}
		return nil, NewVideoProcessingError(filePath, "parsing", "failed to parse container", err)
	}

	// Enhanced metadata extraction for comprehensive analysis
	searchForGPSInMetadata(metadata)
	searchForCombinedMetadata(filePath, metadata)

	return metadata, nil
}

// searchForGPSInMetadata searches for GPS data in all metadata properties and values
func searchForGPSInMetadata(metadata *VideoMetadata) {
	// Search in existing properties
	for key, value := range metadata.Properties {
		if strings.Contains(strings.ToLower(key), "location") ||
			strings.Contains(strings.ToLower(key), "gps") ||
			strings.Contains(strings.ToLower(value), "location") ||
			strings.Contains(strings.ToLower(value), "deg") {
			parseGPSString(value, metadata)
		}

		// Check for ISO 6709 format (±DD.DDDD±DDD.DDDD±AAA.AAA)
		if strings.Contains(value, "+") && strings.Contains(value, "-") &&
			(strings.Count(value, "+")+strings.Count(value, "-")) >= 2 {
			parseISO6709Location(value, metadata)
		}
	}
}

// searchForCombinedMetadata searches for both Apple QuickTime and additional metadata patterns in raw file data
func searchForCombinedMetadata(filePath string, metadata *VideoMetadata) {
	processFileChunks(filePath, 5*1024*1024, func(data []byte) {
		if isValidUTF8Subset(data) {
			dataStr := string(data)
			searchAppleMetadataInData(dataStr, metadata)
			searchMetadataPatternsInData(dataStr, metadata)
		}
	})
}

// processFileChunks reads a file in chunks and applies a processing function to each chunk
func processFileChunks(filePath string, maxSearchBytes int64, processFunc func([]byte)) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	buffer := make([]byte, 64*1024) // 64KB chunks
	var accumulated []byte
	totalRead := int64(0)

	for {
		if totalRead >= maxSearchBytes {
			break
		}

		n, err := file.Read(buffer)
		if n == 0 {
			break
		}

		totalRead += int64(n)
		accumulated = append(accumulated, buffer[:n]...)

		if len(accumulated) > 32*1024 {
			accumulated = accumulated[len(accumulated)-32*1024:]
		}

		processFunc(accumulated)

		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}
}

// VideoProcessingError represents an error during video processing
type VideoProcessingError struct {
	FilePath    string
	ErrorType   string
	Message     string
	Err         error
	Recoverable bool
	Context     map[string]any
}

func (e *VideoProcessingError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("video processing failed for %s (%s): %s - %v",
			e.FilePath, e.ErrorType, e.Message, e.Err)
	}
	return fmt.Sprintf("video processing failed for %s (%s): %s",
		e.FilePath, e.ErrorType, e.Message)
}

func (e *VideoProcessingError) Unwrap() error {
	return e.Err
}

func (e *VideoProcessingError) IsRecoverable() bool {
	return e.Recoverable
}

func (e *VideoProcessingError) WithContext(key string, value any) *VideoProcessingError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// NewVideoProcessingError creates a new video processing error
func NewVideoProcessingError(filePath, errorType, message string, err error) *VideoProcessingError {
	return &VideoProcessingError{
		FilePath:    filePath,
		ErrorType:   errorType,
		Message:     message,
		Err:         err,
		Recoverable: isVideoErrorRecoverable(errorType),
		Context:     make(map[string]any),
	}
}

// isVideoErrorRecoverable determines if a video error is recoverable
func isVideoErrorRecoverable(errorType string) bool {
	switch errorType {
	case "file_access", "timeout":
		return true
	case "file_size", "unsupported_format", "parsing":
		return false
	default:
		return false
	}
}

// parseMP4ContainerWithContext parses the MP4/MOV container structure with context
func parseMP4ContainerWithContext(ctx context.Context, file *os.File, metadata *VideoMetadata) error {
	bytesRead := int64(0)

	for {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Stop reading if we've read too much metadata
		if bytesRead > MaxMetadataRead {
			break
		}

		box, err := readMP4BoxWithContext(ctx, file)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read box: %w", err)
		}

		bytesRead += int64(box.Size) + BoxHeaderSize

		// Process specific box types
		switch string(box.Type[:]) {
		case "moov":
			err = parseMoovBoxWithContext(ctx, box.Data, metadata)
			if err != nil {
				return fmt.Errorf("failed to parse moov box: %w", err)
			}
		case "ftyp":
			err = parseFtypBox(box.Data, metadata)
			if err != nil {
				// Non-fatal error for ftyp parsing
				continue
			}
		case "mdat":
			// Skip media data - we only need metadata
			continue
		}
	}

	return nil
}

// readMP4BoxWithContext reads an MP4 box from the file with context
func readMP4BoxWithContext(ctx context.Context, file *os.File) (*MP4Box, error) {
	// Check context before reading
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var header [BoxHeaderSize]byte
	n, err := file.Read(header[:])
	if err != nil {
		return nil, err
	}
	if n != BoxHeaderSize {
		return nil, io.EOF
	}

	// Parse box header
	size := binary.BigEndian.Uint32(header[0:4])
	var boxType [4]byte
	copy(boxType[:], header[4:8])

	// Handle extended size (64-bit)
	if size == 1 {
		var extSize [8]byte
		n, err := file.Read(extSize[:])
		if err != nil {
			return nil, err
		}
		if n != 8 {
			return nil, io.EOF
		}
		size64 := binary.BigEndian.Uint64(extSize[:])
		if size64 > MaxBoxSize {
			return nil, fmt.Errorf("box too large: %d bytes", size64)
		}
		// Safe conversion with bounds checking
		if size64 < ExtendedBoxSize {
			return nil, fmt.Errorf("invalid box size: %d is less than extended box size %d", size64, ExtendedBoxSize)
		}
		adjustedSize := size64 - ExtendedBoxSize
		if adjustedSize > math.MaxUint32 {
			return nil, fmt.Errorf("box size too large for uint32: %d", adjustedSize)
		}
		size = uint32(adjustedSize)
	} else if size == 0 {
		// Box extends to end of file - skip for safety
		return nil, io.EOF
	} else {
		size -= BoxHeaderSize
	}

	// Safety check for box size
	if size > MaxBoxSize {
		return nil, fmt.Errorf("box too large: %d bytes", size)
	}

	// Check context before reading data
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Read box data efficiently
	data := make([]byte, size)
	if size > 0 {
		n, err := file.Read(data)
		if err != nil {
			return nil, err
		}
		// Safe comparison with bounds checking
		if n < 0 || n > math.MaxUint32 || uint32(n) != size {
			return nil, fmt.Errorf("incomplete box read: expected %d, got %d", size, n)
		}
	}

	return &MP4Box{
		Size: size,
		Type: boxType,
		Data: data,
	}, nil
}

// parseFtypBox parses the file type box
func parseFtypBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 8 {
		return fmt.Errorf("ftyp box too small")
	}

	majorBrand := string(data[0:4])
	metadata.Properties["MajorBrand"] = majorBrand

	// Set codec based on major brand
	switch majorBrand {
	case "mp41", "mp42":
		metadata.Codec = "MPEG-4"
	case "qt  ":
		metadata.Codec = "QuickTime"
	case "M4V ":
		metadata.Codec = "iTunes Video"
	default:
		metadata.Codec = majorBrand
	}

	return nil
}

// parseMoovBox parses the movie box containing metadata
func parseMoovBox(data []byte, metadata *VideoMetadata) error {
	return parseMoovBoxWithContext(context.Background(), data, metadata)
}

// parseMoovBoxWithContext parses the movie box containing metadata with context
func parseMoovBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "mvhd":
			err := parseMvhdBox(boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		case "udta":
			err := parseUdtaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		case "trak":
			err := parseTrakBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMvhdBox parses the movie header box
func parseMvhdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 24 {
		return fmt.Errorf("mvhd box too small")
	}

	version := data[0]
	var timeScale, duration uint32
	var creationTime uint32

	if version == 0 {
		// 32-bit version
		if len(data) < 32 {
			return fmt.Errorf("mvhd v0 box too small")
		}
		creationTime = binary.BigEndian.Uint32(data[4:8])
		timeScale = binary.BigEndian.Uint32(data[12:16])
		duration = binary.BigEndian.Uint32(data[16:20])
	} else {
		// 64-bit version
		if len(data) < 44 {
			return fmt.Errorf("mvhd v1 box too small")
		}
		creationTime64 := binary.BigEndian.Uint64(data[4:12])
		// Safe conversion with bounds checking
		if creationTime64 > math.MaxUint32 {
			return fmt.Errorf("creation time value too large: %d", creationTime64)
		}
		creationTime = uint32(creationTime64)
		timeScale = binary.BigEndian.Uint32(data[20:24])
		duration64 := binary.BigEndian.Uint64(data[24:32])
		// Safe conversion with bounds checking
		if duration64 > math.MaxUint32 {
			return fmt.Errorf("duration value too large: %d", duration64)
		}
		duration = uint32(duration64)
	}

	// Calculate duration
	if timeScale > 0 {
		metadata.Duration = time.Duration(duration) * time.Second / time.Duration(timeScale)
	}

	// Convert creation time (seconds since 1904-01-01)
	if creationTime > 0 {
		// MP4 epoch is 1904-01-01, Unix epoch is 1970-01-01
		// Difference is 66 years = 2082844800 seconds
		const mp4Epoch = 2082844800
		if creationTime > mp4Epoch {
			unixTime := creationTime - mp4Epoch
			metadata.CreatedDate = time.Unix(int64(unixTime), 0)
		}
	}

	return nil
}

// parseUdtaBoxWithContext parses the user data box containing metadata with context
func parseUdtaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "meta":
			err := parseMetaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		case "©nam":
			metadata.Title = parseStringBox(boxData)
		case "©ART":
			metadata.Author = parseStringBox(boxData)
		case "©day":
			dateStr := parseStringBox(boxData)
			if date, err := parseDate(dateStr); err == nil {
				metadata.CreatedDate = date
			}
		case "©xyz":
			parseGPSBox(boxData, metadata)
		case "©cpy":
			metadata.Copyright = parseStringBox(boxData)
		case "©des":
			metadata.Description = parseStringBox(boxData)
		case "©mak":
			metadata.CameraMake = parseStringBox(boxData)
		case "©mod":
			metadata.CameraModel = parseStringBox(boxData)
		case "©swr":
			metadata.Software = parseStringBox(boxData)
		// QuickTime-specific metadata atoms
		case "©cmt":
			metadata.Description = parseStringBox(boxData)
		case "©wrt":
			metadata.Creator = parseStringBox(boxData)
		case "©prd":
			metadata.Properties["Producer"] = parseStringBox(boxData)
		case "©dir":
			metadata.Properties["Director"] = parseStringBox(boxData)
		case "©gen":
			metadata.Properties["Genre"] = parseStringBox(boxData)
		case "©alb":
			metadata.Properties["Album"] = parseStringBox(boxData)
		case "©grp":
			metadata.Properties["Grouping"] = parseStringBox(boxData)
		case "©lyr":
			metadata.Properties["Lyrics"] = parseStringBox(boxData)
		case "©req":
			metadata.Properties["Requirements"] = parseStringBox(boxData)
		case "©src":
			metadata.Properties["Source"] = parseStringBox(boxData)
		case "©fmt":
			metadata.Properties["Format"] = parseStringBox(boxData)
		case "©inf":
			metadata.Properties["Information"] = parseStringBox(boxData)
		case "©dis":
			metadata.Properties["Disclaimer"] = parseStringBox(boxData)
		case "©wrn":
			metadata.Properties["Warning"] = parseStringBox(boxData)
		case "©url":
			metadata.Properties["URL"] = parseStringBox(boxData)
		case "©ed1", "©ed2", "©ed3", "©ed4", "©ed5", "©ed6", "©ed7", "©ed8", "©ed9":
			// Edit dates
			editNum := boxType[3:]
			dateStr := parseStringBox(boxData)
			if date, err := parseDate(dateStr); err == nil {
				metadata.Properties["EditDate"+string(editNum)] = date.Format("2006-01-02 15:04:05")
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMetaBoxWithContext parses the metadata box containing iTunes-style tags with context
func parseMetaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	if len(data) < 4 {
		return fmt.Errorf("meta box too small")
	}

	// Skip version and flags
	offset := 4

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		if boxType == "ilst" {
			err := parseIlstBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseIlstBoxWithContext parses the iTunes-style metadata list with context
func parseIlstBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		// Parse iTunes metadata tags
		value := parseItunesTag(boxData)
		if value != "" {
			switch boxType {
			case "©nam":
				metadata.Title = value
			case "©ART":
				metadata.Author = value
			case "©day":
				if date, err := parseDate(value); err == nil {
					metadata.CreatedDate = date
				}
			case "©cpy":
				metadata.Copyright = value
			case "©des", "desc":
				metadata.Description = value
			case "©mak":
				metadata.CameraMake = value
			case "©mod":
				metadata.CameraModel = value
			case "©swr":
				metadata.Software = value
			case "©xyz":
				parseGPSString(value, metadata)
			default:
				// Store unknown tags in properties
				if len(boxType) == 4 {
					metadata.Properties[boxType] = value
				}
			}
		}

		offset += int(size)
	}

	return nil
}

// parseItunesTag parses an iTunes-style metadata tag
func parseItunesTag(data []byte) string {
	offset := 0

	for offset < len(data) {
		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		if boxType == "data" && len(boxData) >= 8 {
			// Skip type and locale (8 bytes)
			textData := boxData[8:]
			return strings.TrimSpace(string(textData))
		}

		offset += int(size)
	}

	return ""
}

// parseStringBox parses a simple string box
func parseStringBox(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// parseGPSBox parses GPS coordinates from binary data
func parseGPSBox(data []byte, metadata *VideoMetadata) {
	if len(data) < 12 {
		return
	}

	// GPS coordinates are stored as 32-bit fixed-point numbers
	// Read as uint32 first, then convert to int32 safely
	latUint := binary.BigEndian.Uint32(data[0:4])
	lonUint := binary.BigEndian.Uint32(data[4:8])
	altUint := binary.BigEndian.Uint32(data[8:12])

	// Safe conversion from uint32 to int32 using type conversion
	lat := int32(latUint)
	lon := int32(lonUint)
	alt := int32(altUint)

	// Convert fixed-point to float (divide by 65536)
	metadata.GPSLatitude = float64(lat) / 65536.0
	metadata.GPSLongitude = float64(lon) / 65536.0
	metadata.GPSAltitude = float64(alt) / 65536.0
}

// parseGPSString parses GPS coordinates from string format
func parseGPSString(gpsStr string, metadata *VideoMetadata) {
	gpsStr = strings.TrimSpace(gpsStr)

	// Handle DMS format (e.g., "36 deg 21' 2.16" N, 82 deg 41' 54.60" W, 447.403 m Above Sea Level")
	if strings.Contains(gpsStr, "deg") {
		parseDMSCoordinates(gpsStr, metadata)
		return
	}

	// Handle decimal degrees format (e.g., "36.350600, -82.698500, 447.403")
	parts := strings.Split(gpsStr, ",")
	if len(parts) >= 2 {
		if lat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
			metadata.GPSLatitude = lat
		}
		if lon, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
			metadata.GPSLongitude = lon
		}
		if len(parts) >= 3 {
			if alt, err := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64); err == nil {
				metadata.GPSAltitude = alt
			}
		}
	}
}

// parseDate parses various date formats found in video metadata
func parseDate(dateStr string) (time.Time, error) {
	dateStr = strings.TrimSpace(dateStr)

	// Try common date formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

// CanProcessVideo checks if the file can be processed as a video
func CanProcessVideo(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	supportedExtensions := map[string]bool{
		".mp4": true,
		".m4v": true,
		".mov": true,
	}
	return supportedExtensions[ext]
}

// parseTrakBoxWithContext parses track boxes to extract video technical details with context
func parseTrakBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "tkhd":
			err := parseTkhdBox(boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		case "mdia":
			err := parseMdiaBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseTkhdBox parses track header box for video dimensions
func parseTkhdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 32 {
		return fmt.Errorf("tkhd box too small")
	}

	version := data[0]
	var width, height uint32

	if version == 0 {
		// 32-bit version
		if len(data) < 84 {
			return fmt.Errorf("tkhd v0 box too small")
		}
		width = binary.BigEndian.Uint32(data[76:80]) >> 16  // Fixed-point 16.16
		height = binary.BigEndian.Uint32(data[80:84]) >> 16 // Fixed-point 16.16
	} else {
		// 64-bit version
		if len(data) < 96 {
			return fmt.Errorf("tkhd v1 box too small")
		}
		width = binary.BigEndian.Uint32(data[88:92]) >> 16  // Fixed-point 16.16
		height = binary.BigEndian.Uint32(data[92:96]) >> 16 // Fixed-point 16.16
	}

	// Only update if we haven't set dimensions yet and they're reasonable
	if metadata.Width == 0 && width > 0 && width < 10000 {
		metadata.Width = int(width)
	}
	if metadata.Height == 0 && height > 0 && height < 10000 {
		metadata.Height = int(height)
	}

	return nil
}

// parseMdiaBoxWithContext parses media box for codec information with context
func parseMdiaBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "minf":
			err := parseMinfBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseMinfBoxWithContext parses media information box with context
func parseMinfBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "stbl":
			err := parseStblBoxWithContext(ctx, boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseStblBoxWithContext parses sample table box for codec details with context
func parseStblBoxWithContext(ctx context.Context, data []byte, metadata *VideoMetadata) error {
	offset := 0

	for offset < len(data) {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if offset+BoxHeaderSize > len(data) {
			break
		}

		size := binary.BigEndian.Uint32(data[offset : offset+4])
		boxType := string(data[offset+4 : offset+8])

		if size < BoxHeaderSize || offset+int(size) > len(data) {
			break
		}

		boxData := data[offset+BoxHeaderSize : offset+int(size)]

		switch boxType {
		case "stsd":
			err := parseStsdBox(boxData, metadata)
			if err != nil {
				// Non-fatal error
				continue
			}
		}

		offset += int(size)
	}

	return nil
}

// parseStsdBox parses sample description box for codec information
func parseStsdBox(data []byte, metadata *VideoMetadata) error {
	if len(data) < 8 {
		return fmt.Errorf("stsd box too small")
	}

	// Skip version, flags, and entry count
	offset := 8

	if offset+BoxHeaderSize > len(data) {
		return fmt.Errorf("stsd entry too small")
	}

	// Read first sample description entry
	size := binary.BigEndian.Uint32(data[offset : offset+4])
	codecType := string(data[offset+4 : offset+8])

	if size < BoxHeaderSize || offset+int(size) > len(data) {
		return fmt.Errorf("invalid stsd entry size")
	}

	// Map codec types to readable names
	switch codecType {
	case "avc1", "avc3":
		metadata.Codec = "H.264/AVC"
	case "hev1", "hvc1":
		metadata.Codec = "H.265/HEVC"
	case "mp4v":
		metadata.Codec = "MPEG-4 Visual"
	case "jpeg":
		metadata.Codec = "Motion JPEG"
	case "png ":
		metadata.Codec = "PNG"
	default:
		if metadata.Codec == "" || metadata.Codec == "QuickTime" {
			metadata.Codec = codecType
		}
	}

	return nil
}

// ToProcessedContent converts VideoMetadata to ProcessedContent format
func (vm *VideoMetadata) ToProcessedContent() string {
	var content strings.Builder

	// File information (excluding file system details per requirements)
	if vm.MimeType != "" {
		content.WriteString(fmt.Sprintf("MimeType: %s\n", vm.MimeType))
	}

	// Video technical specifications
	if vm.Duration > 0 {
		content.WriteString(fmt.Sprintf("Duration: %s\n", vm.Duration.String()))
	}
	if vm.Width > 0 {
		content.WriteString(fmt.Sprintf("Width: %d\n", vm.Width))
	}
	if vm.Height > 0 {
		content.WriteString(fmt.Sprintf("Height: %d\n", vm.Height))
	}
	if vm.FrameRate > 0 {
		content.WriteString(fmt.Sprintf("FrameRate: %.2f\n", vm.FrameRate))
	}
	if vm.Codec != "" {
		content.WriteString(fmt.Sprintf("Codec: %s\n", vm.Codec))
	}

	// Metadata fields
	if vm.Title != "" {
		content.WriteString(fmt.Sprintf("Title: %s\n", vm.Title))
	}
	if vm.Description != "" {
		content.WriteString(fmt.Sprintf("Description: %s\n", vm.Description))
	}
	if vm.Author != "" {
		content.WriteString(fmt.Sprintf("Author: %s\n", vm.Author))
	}
	if vm.Creator != "" && vm.Creator != vm.Author {
		content.WriteString(fmt.Sprintf("Creator: %s\n", vm.Creator))
	}
	if vm.Copyright != "" {
		content.WriteString(fmt.Sprintf("Copyright: %s\n", vm.Copyright))
	}

	// Dates
	if !vm.CreatedDate.IsZero() {
		content.WriteString(fmt.Sprintf("CreationDate: %s\n", vm.CreatedDate.Format("2006:01:02 15:04:05-07:00")))
	}
	if !vm.ModifiedDate.IsZero() {
		content.WriteString(fmt.Sprintf("ModificationDate: %s\n", vm.ModifiedDate.Format("2006:01:02 15:04:05-07:00")))
	}

	// GPS and location data (high priority for privacy detection)
	// Consolidate GPS coordinates into a single field for consistency with image metadata
	if vm.GPSLatitude != 0 || vm.GPSLongitude != 0 {
		consolidatedGPS := fmt.Sprintf("%.6f, %.6f", vm.GPSLatitude, vm.GPSLongitude)
		if vm.GPSAltitude != 0 {
			consolidatedGPS = fmt.Sprintf("%s, %.2f", consolidatedGPS, vm.GPSAltitude)
		}
		content.WriteString(fmt.Sprintf("GPS_Coordinates: %s\n", consolidatedGPS))
	}
	if vm.Location != "" {
		content.WriteString(fmt.Sprintf("Location: %s\n", vm.Location))
	}

	// Device information (privacy-sensitive)
	if vm.CameraMake != "" {
		content.WriteString(fmt.Sprintf("CameraMake: %s\n", vm.CameraMake))
	}
	if vm.CameraModel != "" {
		content.WriteString(fmt.Sprintf("CameraModel: %s\n", vm.CameraModel))
	}
	if vm.Software != "" {
		content.WriteString(fmt.Sprintf("Software: %s\n", vm.Software))
	}

	// Additional properties
	for key, value := range vm.Properties {
		if value != "" {
			content.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}
	}

	return content.String()
}

// GetSupportedVideoFormats returns the list of supported video formats
func GetSupportedVideoFormats() []string {
	return []string{".mp4", ".m4v", ".mov"}
}

// OptimizedVideoReader provides optimized reading for video files
type OptimizedVideoReader struct {
	file       *os.File
	fileSize   int64
	position   int64
	bufferSize int
}

// NewOptimizedVideoReader creates a new optimized video reader
func NewOptimizedVideoReader(filePath string) (*OptimizedVideoReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	return &OptimizedVideoReader{
		file:       file,
		fileSize:   stat.Size(),
		position:   0,
		bufferSize: 64 * 1024, // 64KB buffer
	}, nil
}

// ReadBoxHeader reads a box header efficiently
func (ovr *OptimizedVideoReader) ReadBoxHeader() (*MP4Box, error) {
	var header [BoxHeaderSize]byte
	n, err := ovr.file.Read(header[:])
	if err != nil {
		return nil, err
	}
	if n != BoxHeaderSize {
		return nil, io.EOF
	}

	ovr.position += BoxHeaderSize

	// Parse box header
	size := binary.BigEndian.Uint32(header[0:4])
	var boxType [4]byte
	copy(boxType[:], header[4:8])

	// Handle extended size (64-bit)
	if size == 1 {
		var extSize [8]byte
		n, err := ovr.file.Read(extSize[:])
		if err != nil {
			return nil, err
		}
		if n != 8 {
			return nil, io.EOF
		}
		ovr.position += 8
		size64 := binary.BigEndian.Uint64(extSize[:])
		if size64 > MaxBoxSize {
			return nil, fmt.Errorf("box too large: %d bytes", size64)
		}
		// Safe conversion with bounds checking
		if size64 < ExtendedBoxSize {
			return nil, fmt.Errorf("invalid box size: %d is less than extended box size %d", size64, ExtendedBoxSize)
		}
		adjustedSize := size64 - ExtendedBoxSize
		if adjustedSize > math.MaxUint32 {
			return nil, fmt.Errorf("box size too large for uint32: %d", adjustedSize)
		}
		size = uint32(adjustedSize)
	} else if size == 0 {
		// Box extends to end of file - skip for safety
		return nil, io.EOF
	} else {
		size -= BoxHeaderSize
	}

	// Safety check for box size
	if size > MaxBoxSize {
		return nil, fmt.Errorf("box too large: %d bytes", size)
	}

	return &MP4Box{
		Size: size,
		Type: boxType,
		Data: nil, // Data will be read on demand
	}, nil
}

// ReadBoxData reads box data efficiently
func (ovr *OptimizedVideoReader) ReadBoxData(size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}

	data := make([]byte, size)
	n, err := ovr.file.Read(data)
	if err != nil {
		return nil, err
	}
	// Safe comparison with bounds checking
	if n < 0 || n > math.MaxUint32 || uint32(n) != size {
		return nil, fmt.Errorf("incomplete box read: expected %d, got %d", size, n)
	}

	ovr.position += int64(size)
	return data, nil
}

// SkipBoxData skips box data without reading it
func (ovr *OptimizedVideoReader) SkipBoxData(size uint32) error {
	if size == 0 {
		return nil
	}

	_, err := ovr.file.Seek(int64(size), io.SeekCurrent)
	if err != nil {
		return err
	}

	ovr.position += int64(size)
	return nil
}

// GetPosition returns the current position
func (ovr *OptimizedVideoReader) GetPosition() int64 {
	return ovr.position
}

// GetFileSize returns the file size
func (ovr *OptimizedVideoReader) GetFileSize() int64 {
	return ovr.fileSize
}

// Close closes the reader
func (ovr *OptimizedVideoReader) Close() error {
	return ovr.file.Close()
}

// parseMP4ContainerOptimized parses MP4 container with optimized reading
func parseMP4ContainerOptimized(ctx context.Context, reader *OptimizedVideoReader, metadata *VideoMetadata) error {
	bytesRead := int64(0)

	for {
		// Check context for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Stop reading if we've read too much metadata
		if bytesRead > MaxMetadataRead {
			break
		}

		// Read box header
		box, err := reader.ReadBoxHeader()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read box header: %w", err)
		}

		boxType := string(box.Type[:])
		bytesRead += int64(box.Size) + BoxHeaderSize

		// Process specific box types
		switch boxType {
		case "moov":
			// Read moov box data for metadata
			data, err := reader.ReadBoxData(box.Size)
			if err != nil {
				return fmt.Errorf("failed to read moov box data: %w", err)
			}
			box.Data = data

			err = parseMoovBoxWithContext(ctx, box.Data, metadata)
			if err != nil {
				return fmt.Errorf("failed to parse moov box: %w", err)
			}
		case "ftyp":
			// Read ftyp box data for file type info
			data, err := reader.ReadBoxData(box.Size)
			if err != nil {
				// Non-fatal error for ftyp reading
				reader.SkipBoxData(box.Size)
				continue
			}
			box.Data = data

			err = parseFtypBox(box.Data, metadata)
			if err != nil {
				// Non-fatal error for ftyp parsing
				continue
			}
		case "mdat":
			// Skip media data - we only need metadata
			err = reader.SkipBoxData(box.Size)
			if err != nil {
				return fmt.Errorf("failed to skip mdat box: %w", err)
			}
		case "free", "skip":
			// Skip free space boxes
			err = reader.SkipBoxData(box.Size)
			if err != nil {
				return fmt.Errorf("failed to skip %s box: %w", boxType, err)
			}
		default:
			// Skip unknown boxes to save time and memory
			err = reader.SkipBoxData(box.Size)
			if err != nil {
				return fmt.Errorf("failed to skip %s box: %w", boxType, err)
			}
		}
	}

	return nil
}

// Helper functions for enhanced metadata extraction

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// isValidUTF8Subset checks if data contains mostly valid UTF-8 text
func isValidUTF8Subset(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Sample first 1KB to check if it's mostly text
	sampleSize := min(len(data), 1024)
	sample := data[:sampleSize]

	validChars := 0
	for _, b := range sample {
		// Count printable ASCII and common UTF-8 chars
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			validChars++
		}
	}

	// Require at least 30% valid text characters
	return float64(validChars)/float64(sampleSize) > 0.3
}

// searchAppleMetadataInData searches for Apple QuickTime metadata in text data
func searchAppleMetadataInData(data string, metadata *VideoMetadata) {
	// Apple QuickTime metadata keys to search for
	appleMetadataKeys := map[string]string{
		"com.apple.quicktime.location.ISO6709":          "GPS_Location",
		"com.apple.quicktime.creationdate":              "CreationDate_Apple",
		"com.apple.quicktime.make":                      "CameraMake_Apple",
		"com.apple.quicktime.model":                     "CameraModel_Apple",
		"com.apple.quicktime.software":                  "Software_Apple",
		"com.apple.quicktime.author":                    "Author_Apple",
		"com.apple.quicktime.description":               "Description_Apple",
		"com.apple.quicktime.title":                     "Title_Apple",
		"com.apple.quicktime.copyright":                 "Copyright_Apple",
		"com.apple.quicktime.comment":                   "Comment_Apple",
		"com.apple.quicktime.artist":                    "Artist_Apple",
		"com.apple.quicktime.location.name":             "LocationName_Apple",
		"com.apple.quicktime.location.body":             "LocationBody_Apple",
		"com.apple.quicktime.camera.identifier":         "CameraIdentifier_Apple",
		"com.apple.quicktime.live-photo.auto":           "LivePhotoAuto_Apple",
		"com.apple.quicktime.content.identifier":        "ContentIdentifier_Apple",
		"com.apple.quicktime.user.rating":               "UserRating_Apple",
		"com.apple.quicktime.encoding.tool":             "EncodingTool_Apple",
		"com.apple.quicktime.network.sharing":           "NetworkSharing_Apple",
		"com.apple.quicktime.cloud.identifier":          "CloudIdentifier_Apple",
		"com.apple.quicktime.accessibility.description": "AccessibilityDescription_Apple",
	}

	// Handle keywords separately with environment variable for sensitive data
	keywordsKey := os.Getenv("APPLE_KEYWORDS_KEY")
	if keywordsKey == "" {
		keywordsKey = "Keywords_Apple" // Default fallback
	}
	appleMetadataKeys["com.apple.quicktime.keywords"] = keywordsKey

	// Search for each metadata key
	for metadataKey, propertyName := range appleMetadataKeys {
		if strings.Contains(data, metadataKey) {
			if idx := strings.Index(data, metadataKey); idx >= 0 {
				// Extract the metadata value
				value := extractAppleMetadataValue(data[idx:min(idx+300, len(data))], metadataKey)
				if value != "" && isValidMetadataValue(value) {
					// Handle special cases first
					switch propertyName {
					case "GPS_Location":
						parseISO6709Location(value, metadata)
						if metadata.GPSLatitude != 0 || metadata.GPSLongitude != 0 {
							metadata.Properties["GPS_SOURCE"] = "Apple QuickTime Location"
						}
						// Don't add GPS_Location to Properties to avoid duplication with GPS_Coordinates
						continue
					}

					// Add to properties for non-GPS cases
					metadata.Properties[propertyName] = value

					// Handle other special cases
					switch propertyName {
					case "CreationDate_Apple":
						if date, err := parseDate(value); err == nil && metadata.CreatedDate.IsZero() {
							metadata.CreatedDate = date
						}
					case "CameraMake_Apple":
						if metadata.CameraMake == "" {
							metadata.CameraMake = value
						}
					case "CameraModel_Apple":
						if metadata.CameraModel == "" {
							metadata.CameraModel = value
						}
					case "Software_Apple":
						if metadata.Software == "" {
							metadata.Software = value
						}
					}
				}
			}
		}
	}
}

// searchMetadataPatternsInData searches for various metadata patterns in text data
func searchMetadataPatternsInData(data string, metadata *VideoMetadata) {
	// Common metadata patterns to search for
	metadataPatterns := map[string]string{
		"EXIF":      "EXIF_Data",
		"XMP":       "XMP_Data",
		"IPTC":      "IPTC_Data",
		"Canon":     "Canon_Metadata",
		"Nikon":     "Nikon_Metadata",
		"Sony":      "Sony_Metadata",
		"iPhone":    "iPhone_Metadata",
		"Android":   "Android_Metadata",
		"QuickTime": "QuickTime_Metadata",
		"user":      "User_Reference",
		"location":  "Location_Reference",
	}

	// Search for each pattern
	for pattern, propertyName := range metadataPatterns {
		if strings.Contains(strings.ToLower(data), strings.ToLower(pattern)) {
			lowerData := strings.ToLower(data)
			if idx := strings.Index(lowerData, strings.ToLower(pattern)); idx >= 0 {
				// Extract context around the pattern
				start := max(0, idx-50)
				end := min(len(data), idx+len(pattern)+50)

				if start < len(data) && end <= len(data) && start < end {
					context := data[start:end]
					// Clean up the context (remove non-printable characters)
					cleanContext := ""
					for _, c := range context {
						if c >= 32 && c <= 126 { // Printable ASCII
							cleanContext += string(c)
						} else {
							cleanContext += " "
						}
					}
					metadata.Properties[propertyName] = strings.TrimSpace(cleanContext)
				}
			}
		}
	}
}

// extractAppleMetadataValue extracts the value for an Apple QuickTime metadata key
func extractAppleMetadataValue(searchArea, metadataKey string) string {
	// For GPS location, look for ISO 6709 pattern
	if strings.Contains(metadataKey, "location.ISO6709") {
		for i := 0; i < len(searchArea)-20; i++ {
			if (searchArea[i] == '+' || searchArea[i] == '-') && i+20 < len(searchArea) {
				// Extract potential GPS string
				gpsCandidate := ""
				for j := i; j < len(searchArea) && j < i+50; j++ {
					c := searchArea[j]
					if (c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-' {
						gpsCandidate += string(c)
					} else if len(gpsCandidate) > 10 {
						break
					}
				}

				// Check if this looks like ISO 6709 format
				if len(gpsCandidate) > 15 &&
					strings.Count(gpsCandidate, "+")+strings.Count(gpsCandidate, "-") >= 2 {
					return gpsCandidate
				}
			}
		}
	}

	// For other metadata, look for printable text after the key
	keyIndex := strings.Index(searchArea, metadataKey)
	if keyIndex >= 0 {
		// Look for text data after the key
		startSearch := keyIndex + len(metadataKey) + 10
		if startSearch < len(searchArea) {
			// Find the start of printable text
			for i := startSearch; i < len(searchArea)-5; i++ {
				if searchArea[i] >= 32 && searchArea[i] <= 126 { // Printable ASCII
					// Extract the text value
					value := ""
					for j := i; j < len(searchArea) && j < i+200; j++ {
						c := searchArea[j]
						if c >= 32 && c <= 126 { // Printable ASCII
							value += string(c)
						} else if len(value) > 3 {
							break
						} else {
							value = "" // Reset if we hit non-printable too early
						}
					}

					// Clean up the value
					value = strings.TrimSpace(value)
					if len(value) > 3 && len(value) < 500 { // Reasonable length
						return value
					}
				}
			}
		}
	}

	return ""
}

// parseISO6709Location parses GPS coordinates in ISO 6709 format
func parseISO6709Location(iso6709Str string, metadata *VideoMetadata) {
	// ISO 6709 format: ±DD.DDDD±DDD.DDDD±AAA.AAA/
	// Example: +36.3506-082.6985+447.403/

	iso6709Str = strings.TrimSpace(iso6709Str)
	if len(iso6709Str) == 0 {
		return
	}

	// Remove trailing slash if present
	iso6709Str = strings.TrimSuffix(iso6709Str, "/")

	// Parse latitude (first coordinate)
	if len(iso6709Str) > 0 {
		// Find the second sign (longitude start)
		lonStart := -1
		for i := 1; i < len(iso6709Str); i++ {
			if iso6709Str[i] == '+' || iso6709Str[i] == '-' {
				lonStart = i
				break
			}
		}

		if lonStart > 0 {
			latStr := iso6709Str[:lonStart]
			if lat, err := strconv.ParseFloat(latStr, 64); err == nil {
				metadata.GPSLatitude = lat
			}

			// Parse longitude (second coordinate)
			remaining := iso6709Str[lonStart:]
			altStart := -1
			for i := 1; i < len(remaining); i++ {
				if remaining[i] == '+' || remaining[i] == '-' {
					altStart = i
					break
				}
			}

			if altStart > 0 {
				lonStr := remaining[:altStart]
				if lon, err := strconv.ParseFloat(lonStr, 64); err == nil {
					metadata.GPSLongitude = lon
				}

				// Parse altitude (third coordinate)
				altStr := remaining[altStart:]
				if alt, err := strconv.ParseFloat(altStr, 64); err == nil {
					metadata.GPSAltitude = alt
				}
			} else {
				// No altitude, just longitude
				if lon, err := strconv.ParseFloat(remaining, 64); err == nil {
					metadata.GPSLongitude = lon
				}
			}
		}
	}
}

// parseDMSCoordinates parses GPS coordinates in degrees/minutes/seconds format
func parseDMSCoordinates(gpsStr string, metadata *VideoMetadata) {
	// Split by comma to get lat, lon, and altitude parts
	parts := strings.Split(gpsStr, ",")

	for i, part := range parts {
		part = strings.TrimSpace(part)

		if i == 0 || i == 1 {
			// Parse latitude or longitude
			coord := parseDMSCoordinate(part)
			if i == 0 {
				metadata.GPSLatitude = coord
			} else {
				metadata.GPSLongitude = coord
			}
		} else if i == 2 && strings.Contains(part, "m") {
			// Parse altitude (e.g., "447.403 m Above Sea Level")
			fields := strings.Fields(part)
			if len(fields) > 0 {
				if alt, err := strconv.ParseFloat(fields[0], 64); err == nil {
					metadata.GPSAltitude = alt
				}
			}
		}
	}
}

// parseDMSCoordinate parses a single coordinate in DMS format
func parseDMSCoordinate(coordStr string) float64 {
	// Example: "36 deg 21' 2.16" N" or "82 deg 41' 54.60" W"
	coordStr = strings.TrimSpace(coordStr)

	// Extract direction (N, S, E, W)
	direction := ""
	if strings.HasSuffix(coordStr, " N") || strings.HasSuffix(coordStr, " S") ||
		strings.HasSuffix(coordStr, " E") || strings.HasSuffix(coordStr, " W") {
		direction = coordStr[len(coordStr)-1:]
		coordStr = strings.TrimSpace(coordStr[:len(coordStr)-2])
	}

	// Parse degrees, minutes, seconds
	var degrees, minutes, seconds float64

	// Split by "deg" to get degrees
	if strings.Contains(coordStr, "deg") {
		parts := strings.Split(coordStr, "deg")
		if len(parts) >= 1 {
			if deg, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
				degrees = deg
			}
		}

		if len(parts) >= 2 {
			remainder := strings.TrimSpace(parts[1])

			// Parse minutes and seconds
			if strings.Contains(remainder, "'") {
				minSecParts := strings.Split(remainder, "'")
				if len(minSecParts) >= 1 {
					if min, err := strconv.ParseFloat(strings.TrimSpace(minSecParts[0]), 64); err == nil {
						minutes = min
					}
				}

				if len(minSecParts) >= 2 {
					secStr := strings.TrimSpace(minSecParts[1])
					secStr = strings.Trim(secStr, "\" ")
					if sec, err := strconv.ParseFloat(secStr, 64); err == nil {
						seconds = sec
					}
				}
			}
		}
	}

	// Convert to decimal degrees
	result := degrees + minutes/60.0 + seconds/3600.0

	// Apply direction (negative for South and West)
	if direction == "S" || direction == "W" {
		result = -result
	}

	return result
}

// isValidMetadataValue checks if a metadata value is valid and not corrupted
func isValidMetadataValue(value string) bool {
	// Reject empty or very short values
	if len(value) < 2 {
		return false
	}

	// Reject values that are mostly non-printable characters
	printableCount := 0
	for _, c := range value {
		if c >= 32 && c <= 126 {
			printableCount++
		}
	}

	// Require at least 70% printable characters
	if float64(printableCount)/float64(len(value)) < 0.7 {
		return false
	}

	// Reject values that look like corrupted data
	corruptedPatterns := []string{
		"*data", "*", "\\x", "\x00", "\xff", "????", "NULL", "null",
	}

	lowerValue := strings.ToLower(value)
	for _, pattern := range corruptedPatterns {
		if strings.Contains(lowerValue, pattern) {
			return false
		}
	}

	// Reject values that are just repeated characters
	if len(value) > 3 {
		firstChar := rune(value[0])
		allSame := true
		for _, c := range value {
			if c != firstChar {
				allSame = false
				break
			}
		}
		if allSame {
			return false
		}
	}

	return true
}

// Remove the unnecessary safeUint32ToSignedInt64 function as uint32 to int64 conversion is always safe
