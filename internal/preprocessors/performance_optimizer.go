// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
)

// PerformanceOptimizer provides optimized reading strategies for media files
type PerformanceOptimizer struct {
	bufferSize int
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer() *PerformanceOptimizer {
	return &PerformanceOptimizer{
		bufferSize: 64 * 1024, // 64KB buffer
	}
}

// OptimizedReader provides efficient reading for large media files
type OptimizedReader struct {
	file       *os.File
	reader     *bufio.Reader
	position   int64
	fileSize   int64
	bufferSize int
}

// NewOptimizedReader creates a new optimized reader for a file
func NewOptimizedReader(filePath string, bufferSize int) (*OptimizedReader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	return &OptimizedReader{
		file:       file,
		reader:     bufio.NewReaderSize(file, bufferSize),
		position:   0,
		fileSize:   stat.Size(),
		bufferSize: bufferSize,
	}, nil
}

// Read reads data from the optimized reader
func (or *OptimizedReader) Read(p []byte) (int, error) {
	n, err := or.reader.Read(p)
	or.position += int64(n)
	return n, err
}

// Seek seeks to a position in the file
func (or *OptimizedReader) Seek(offset int64, whence int) (int64, error) {
	pos, err := or.file.Seek(offset, whence)
	if err != nil {
		return pos, err
	}

	// Reset the buffered reader after seeking
	or.reader.Reset(or.file)
	or.position = pos
	return pos, nil
}

// ReadAt reads data at a specific offset without changing the current position
func (or *OptimizedReader) ReadAt(p []byte, offset int64) (int, error) {
	return or.file.ReadAt(p, offset)
}

// GetPosition returns the current position in the file
func (or *OptimizedReader) GetPosition() int64 {
	return or.position
}

// GetFileSize returns the total file size
func (or *OptimizedReader) GetFileSize() int64 {
	return or.fileSize
}

// Close closes the optimized reader
func (or *OptimizedReader) Close() error {
	return or.file.Close()
}

// MetadataSeeker provides efficient seeking to metadata sections
type MetadataSeeker struct {
	reader *OptimizedReader
}

// NewMetadataSeeker creates a new metadata seeker
func NewMetadataSeeker(reader *OptimizedReader) *MetadataSeeker {
	return &MetadataSeeker{
		reader: reader,
	}
}

// SeekToMetadataSection seeks to the beginning of metadata sections
func (ms *MetadataSeeker) SeekToMetadataSection(ctx context.Context, sectionType string) (int64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	switch sectionType {
	case "mp4_moov":
		return ms.seekToMP4MoovBox(ctx)
	case "mp3_id3v2":
		return ms.seekToMP3ID3v2(ctx)
	case "flac_metadata":
		return ms.seekToFLACMetadata(ctx)
	default:
		return 0, fmt.Errorf("unsupported metadata section type: %s", sectionType)
	}
}

// seekToMP4MoovBox seeks to the moov box in MP4 files
func (ms *MetadataSeeker) seekToMP4MoovBox(ctx context.Context) (int64, error) {
	// Start from beginning
	if _, err := ms.reader.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		// Read box header (8 bytes)
		var header [8]byte
		n, err := ms.reader.Read(header[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if n != 8 {
			break
		}

		// Parse box size and type
		size := uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3])
		boxType := string(header[4:8])

		if boxType == "moov" {
			// Found moov box, return position at start of box
			return ms.reader.GetPosition() - 8, nil
		}

		// Skip to next box
		if size < 8 {
			break
		}
		skipSize := int64(size - 8)
		if _, err := ms.reader.Seek(ms.reader.GetPosition()+skipSize, io.SeekStart); err != nil {
			return 0, err
		}
	}

	return 0, fmt.Errorf("moov box not found")
}

// seekToMP3ID3v2 seeks to ID3v2 tag in MP3 files
func (ms *MetadataSeeker) seekToMP3ID3v2(ctx context.Context) (int64, error) {
	// ID3v2 is always at the beginning of MP3 files
	if _, err := ms.reader.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	// Read ID3v2 header
	var header [10]byte
	n, err := ms.reader.Read(header[:])
	if err != nil {
		return 0, err
	}
	if n != 10 {
		return 0, fmt.Errorf("incomplete ID3v2 header")
	}

	// Check for ID3v2 signature
	if string(header[0:3]) != "ID3" {
		return 0, fmt.Errorf("no ID3v2 header found")
	}

	// Return position at start of header
	return 0, nil
}

// seekToFLACMetadata seeks to FLAC metadata blocks
func (ms *MetadataSeeker) seekToFLACMetadata(ctx context.Context) (int64, error) {
	// FLAC metadata starts after the FLAC signature
	if _, err := ms.reader.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}

	// Read FLAC signature
	var signature [4]byte
	n, err := ms.reader.Read(signature[:])
	if err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, fmt.Errorf("incomplete FLAC signature")
	}

	if string(signature[:]) != "fLaC" {
		return 0, fmt.Errorf("not a FLAC file")
	}

	// Return position after signature (start of metadata blocks)
	return 4, nil
}

// ChunkedReader provides chunked reading for large files
type ChunkedReader struct {
	reader    *OptimizedReader
	chunkSize int
}

// NewChunkedReader creates a new chunked reader
func NewChunkedReader(reader *OptimizedReader, chunkSize int) *ChunkedReader {
	return &ChunkedReader{
		reader:    reader,
		chunkSize: chunkSize,
	}
}

// ReadChunk reads a chunk of data
func (cr *ChunkedReader) ReadChunk(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	chunk := make([]byte, cr.chunkSize)
	n, err := cr.reader.Read(chunk)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return chunk[:n], err
}

// ReadChunks reads multiple chunks with a callback
func (cr *ChunkedReader) ReadChunks(ctx context.Context, callback func([]byte) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunk, err := cr.ReadChunk(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(chunk) == 0 {
			break
		}

		if err := callback(chunk); err != nil {
			return err
		}
	}

	return nil
}

// MemoryEfficientParser provides memory-efficient parsing for large metadata sections
type MemoryEfficientParser struct {
	maxMemoryUsage int64
	currentUsage   int64
}

// NewMemoryEfficientParser creates a new memory-efficient parser
func NewMemoryEfficientParser(maxMemoryUsage int64) *MemoryEfficientParser {
	return &MemoryEfficientParser{
		maxMemoryUsage: maxMemoryUsage,
		currentUsage:   0,
	}
}

// AllocateMemory allocates memory and tracks usage
func (mep *MemoryEfficientParser) AllocateMemory(size int64) ([]byte, error) {
	if mep.currentUsage+size > mep.maxMemoryUsage {
		return nil, fmt.Errorf("memory limit exceeded: requested %d, current %d, max %d",
			size, mep.currentUsage, mep.maxMemoryUsage)
	}

	data := make([]byte, size)
	mep.currentUsage += size
	return data, nil
}

// FreeMemory frees allocated memory and updates usage tracking
func (mep *MemoryEfficientParser) FreeMemory(size int64) {
	mep.currentUsage -= size
	if mep.currentUsage < 0 {
		mep.currentUsage = 0
	}
}

// GetMemoryUsage returns current memory usage
func (mep *MemoryEfficientParser) GetMemoryUsage() int64 {
	return mep.currentUsage
}

// GetAvailableMemory returns available memory
func (mep *MemoryEfficientParser) GetAvailableMemory() int64 {
	return mep.maxMemoryUsage - mep.currentUsage
}
