// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ferret-scan/internal/observability"
)

// StreamingProcessor handles large files by processing them in chunks
type StreamingProcessor struct {
	observer    *observability.StandardObserver
	chunkSize   int64 // Size in bytes for each chunk
	maxFileSize int64 // Maximum file size to process
	overlapSize int   // Number of bytes to overlap between chunks
}

// StreamingConfig holds configuration for streaming processing
type StreamingConfig struct {
	ChunkSizeMB   int64 `json:"chunk_size_mb"`    // Chunk size in MB
	MaxFileSizeMB int64 `json:"max_file_size_mb"` // Max file size in MB
	OverlapBytes  int   `json:"overlap_bytes"`    // Overlap between chunks
}

// DefaultStreamingConfig returns sensible defaults
func DefaultStreamingConfig() StreamingConfig {
	return StreamingConfig{
		ChunkSizeMB:   10,   // 10MB chunks
		MaxFileSizeMB: 500,  // 500MB max file size
		OverlapBytes:  1024, // 1KB overlap
	}
}

// NewStreamingProcessor creates a new streaming processor
func NewStreamingProcessor(config StreamingConfig, observer *observability.StandardObserver) *StreamingProcessor {
	return &StreamingProcessor{
		observer:    observer,
		chunkSize:   config.ChunkSizeMB * 1024 * 1024,
		maxFileSize: config.MaxFileSizeMB * 1024 * 1024,
		overlapSize: config.OverlapBytes,
	}
}

// CanProcess checks if this processor can handle the given file
func (sp *StreamingProcessor) CanProcess(filePath string) bool {
	// Check file size
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	// Only process files larger than chunk size but within max file size
	return info.Size() > sp.chunkSize && info.Size() <= sp.maxFileSize
}

// Process processes a large file in streaming chunks
func (sp *StreamingProcessor) Process(filePath string) (*ProcessedContent, error) {
	var finishTiming func(bool, map[string]interface{})
	if sp.observer != nil {
		finishTiming = sp.observer.StartTiming("streaming_processor", "process_file", filePath)
	}

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	// Check file size limits
	if info.Size() > sp.maxFileSize {
		err := fmt.Errorf("file too large: %d bytes (max: %d bytes)", info.Size(), sp.maxFileSize)
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error(), "file_size": info.Size()})
		}
		return nil, err
	}

	// Open file for reading
	file, err := os.Open(filePath)
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Process file in chunks
	content, stats, err := sp.processInChunks(file, info.Size())
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, err
	}

	result := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          content,
		Format:        "streaming_text",
		WordCount:     stats.WordCount,
		CharCount:     stats.CharCount,
		LineCount:     stats.LineCount,
		ProcessorType: "streaming",
		Success:       true,
		Metadata: map[string]interface{}{
			"file_size_bytes":  info.Size(),
			"chunks_processed": stats.ChunksProcessed,
			"chunk_size_bytes": sp.chunkSize,
			"overlap_bytes":    sp.overlapSize,
			"processing_mode":  "streaming",
			"memory_efficient": true,
		},
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"file_size":        info.Size(),
			"chunks_processed": stats.ChunksProcessed,
			"content_length":   len(content),
			"lines_processed":  stats.LineCount,
		})
	}

	return result, nil
}

// ChunkStats tracks statistics during chunk processing
type ChunkStats struct {
	ChunksProcessed int
	WordCount       int
	CharCount       int
	LineCount       int
}

// processInChunks processes the file in manageable chunks
func (sp *StreamingProcessor) processInChunks(file *os.File, fileSize int64) (string, ChunkStats, error) {
	var result strings.Builder
	var stats ChunkStats
	var previousOverlap string

	buffer := make([]byte, sp.chunkSize)

	for {
		// Read chunk
		bytesRead, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return "", stats, fmt.Errorf("failed to read chunk: %w", err)
		}

		if bytesRead == 0 {
			break // End of file
		}

		// Convert chunk to string
		chunkContent := string(buffer[:bytesRead])

		// Add previous overlap to the beginning
		if previousOverlap != "" {
			chunkContent = previousOverlap + chunkContent
		}

		// Process this chunk
		processedChunk, overlap := sp.processChunk(chunkContent, err == io.EOF)

		// Add processed content to result
		result.WriteString(processedChunk)

		// Update statistics
		stats.ChunksProcessed++
		stats.CharCount += len(processedChunk)
		stats.LineCount += strings.Count(processedChunk, "\n")
		stats.WordCount += len(strings.Fields(processedChunk))

		// Store overlap for next iteration
		previousOverlap = overlap

		if err == io.EOF {
			break
		}
	}

	return result.String(), stats, nil
}

// processChunk processes a single chunk and returns processed content and overlap
func (sp *StreamingProcessor) processChunk(chunk string, isLastChunk bool) (processedContent string, overlap string) {
	// If this is the last chunk, return everything
	if isLastChunk {
		return chunk, ""
	}

	// Find a good break point (end of line) near the end of the chunk
	// to avoid splitting words or sentences across chunks
	overlapStart := len(chunk) - sp.overlapSize
	if overlapStart < 0 {
		overlapStart = 0
	}

	// Find the last newline before the overlap point
	breakPoint := strings.LastIndex(chunk[:len(chunk)-sp.overlapSize], "\n")
	if breakPoint == -1 {
		// No newline found, use the overlap point
		breakPoint = overlapStart
	} else {
		breakPoint++ // Include the newline
	}

	// Split the chunk
	processedContent = chunk[:breakPoint]
	overlap = chunk[breakPoint:]

	return processedContent, overlap
}

// GetName returns the name of this processor
func (sp *StreamingProcessor) GetName() string {
	return "streaming_processor"
}

// GetSupportedExtensions returns file extensions this processor supports
func (sp *StreamingProcessor) GetSupportedExtensions() []string {
	// Support common text file types that might be large
	return []string{".txt", ".log", ".csv", ".json", ".xml", ".sql", ".md", ".yaml", ".yml"}
}

// SetObserver sets the observability component
func (sp *StreamingProcessor) SetObserver(observer *observability.StandardObserver) {
	sp.observer = observer
}

// StreamingTextProcessor is a specialized processor for large text files
type StreamingTextProcessor struct {
	*StreamingProcessor
	lineBufferSize int
}

// NewStreamingTextProcessor creates a processor optimized for text files
func NewStreamingTextProcessor(config StreamingConfig, observer *observability.StandardObserver) *StreamingTextProcessor {
	return &StreamingTextProcessor{
		StreamingProcessor: NewStreamingProcessor(config, observer),
		lineBufferSize:     8192, // 8KB line buffer
	}
}

// ProcessLineByLine processes a file line by line for memory efficiency
func (stp *StreamingTextProcessor) ProcessLineByLine(filePath string) (*ProcessedContent, error) {
	var finishTiming func(bool, map[string]interface{})
	if stp.observer != nil {
		finishTiming = stp.observer.StartTiming("streaming_text_processor", "process_line_by_line", filePath)
	}

	// Validate and clean the file path to prevent path traversal
	if strings.Contains(filePath, "..") {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": "path traversal not allowed"})
		}
		return nil, fmt.Errorf("path traversal not allowed in file path")
	}
	cleanPath := filepath.Clean(filePath)
	// Open file
	// #nosec G304 - path traversal protection implemented above with strings.Contains check and filepath.Clean
	file, err := os.Open(cleanPath)
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Get file info
	info, err := file.Stat()
	if err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	var result strings.Builder
	scanner := bufio.NewScanner(file)

	// Set up scanner with larger buffer for long lines
	buffer := make([]byte, stp.lineBufferSize)
	scanner.Buffer(buffer, 1024*1024) // 1MB max line length

	lineCount := 0
	charCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		result.WriteString(line)
		result.WriteString("\n")

		lineCount++
		charCount += len(line) + 1 // +1 for newline

		// Yield control periodically for long files
		if lineCount%10000 == 0 {
			// Could add progress reporting here
		}
	}

	if err := scanner.Err(); err != nil {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	content := result.String()
	wordCount := len(strings.Fields(content))

	processedContent := &ProcessedContent{
		OriginalPath:  filePath,
		Filename:      filepath.Base(filePath),
		Text:          content,
		Format:        "line_by_line_text",
		WordCount:     wordCount,
		CharCount:     charCount,
		LineCount:     lineCount,
		ProcessorType: "streaming_text",
		Success:       true,
		Metadata: map[string]interface{}{
			"file_size_bytes":   info.Size(),
			"processing_mode":   "line_by_line",
			"memory_efficient":  true,
			"lines_processed":   lineCount,
			"buffer_size_bytes": stp.lineBufferSize,
		},
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"file_size":       info.Size(),
			"lines_processed": lineCount,
			"content_length":  len(content),
			"words_counted":   wordCount,
		})
	}

	return processedContent, nil
}

// CanProcess checks if this processor can handle the given file
func (stp *StreamingTextProcessor) CanProcess(filePath string) bool {
	// First check the base streaming processor
	if !stp.StreamingProcessor.CanProcess(filePath) {
		return false
	}

	// Check if it's a text file
	ext := strings.ToLower(filepath.Ext(filePath))
	textExtensions := []string{".txt", ".log", ".csv", ".md", ".json", ".xml", ".yaml", ".yml", ".sql"}

	for _, textExt := range textExtensions {
		if ext == textExt {
			return true
		}
	}

	return false
}

// GetName returns the name of this processor
func (stp *StreamingTextProcessor) GetName() string {
	return "streaming_text_processor"
}
