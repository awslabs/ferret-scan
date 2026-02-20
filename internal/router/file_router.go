// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ferret-scan/internal/observability"
	"ferret-scan/internal/preprocessors"
)

// FileRouter handles file routing and preprocessing decisions
type FileRouter struct {
	registry      *PreprocessorRegistry
	preprocessors []preprocessors.Preprocessor
	metrics       *RouterMetrics
	logger        *DebugLogger
	observer      *observability.StandardObserver
}

// MaxFileSize is the default maximum file size the router will process (100 MB).
const MaxFileSize = int64(100 * 1024 * 1024)

// NewFileRouter creates a new file router
func NewFileRouter(debug bool) *FileRouter {
	level := observability.ObservabilityMetrics
	if debug {
		level = observability.ObservabilityDebug
	}
	return &FileRouter{
		registry:      NewPreprocessorRegistry(),
		preprocessors: make([]preprocessors.Preprocessor, 0),
		metrics:       NewRouterMetrics(),
		logger:        NewDebugLogger(debug, os.Stderr),
		observer:      observability.NewStandardObserver(level, os.Stderr),
	}
}

// RegisterPreprocessor adds a preprocessor factory to the registry
func (fr *FileRouter) RegisterPreprocessor(name string, factory PreprocessorFactory) {
	fr.registry.Register(name, factory)
}

// InitializePreprocessors creates and registers all preprocessors
func (fr *FileRouter) InitializePreprocessors(config map[string]interface{}) {
	fr.preprocessors = fr.registry.CreateAll(config)
}

// CanProcessFile determines if a file can be processed
func (fr *FileRouter) CanProcessFile(filePath string, enablePreprocessors, enableGenAI bool) (bool, string) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check file size
	cleanPath := filepath.Clean(filePath)
	if info, err := os.Stat(cleanPath); err == nil {
		maxSize := MaxFileSize
		// GENAI_DISABLED: if isAudioFile(ext) {
		//	maxSize = 500 * 1024 * 1024 // 500MB for audio
		// }
		if info.Size() > maxSize {
			return false, fmt.Sprintf("File too large (max: %dMB)", maxSize/(1024*1024))
		}
	}

	// GENAI_DISABLED: Audio files require GenAI
	// if isAudioFile(ext) {
	//	if enableGenAI {
	//		return true, "Audio file"
	//	}
	//	return false, "Audio file (requires --enable-genai)"
	// }

	// Binary documents require preprocessors
	if isBinaryDocument(ext) {
		if enablePreprocessors {
			return true, "Binary document"
		}
		return false, "Binary document (requires preprocessors)"
	}

	// Check if it's a text file
	if isText, err := isTextFile(filePath); err == nil && isText {
		return true, "Text file"
	}

	return false, "Unsupported file type"
}

// ProcessFileWithContext processes a file through the routing system with full context
func (fr *FileRouter) ProcessFileWithContext(filePath string, config *ProcessingContext) (*preprocessors.ProcessedContent, error) {
	return fr.processFileInternal(filePath, config)
}

// ProcessFile processes a file through the routing system (interface method)
func (fr *FileRouter) ProcessFile(filePath string, config interface{}) (*preprocessors.ProcessedContent, error) {
	if ctx, ok := config.(*ProcessingContext); ok {
		return fr.processFileInternal(filePath, ctx)
	}
	// Create minimal context if none provided
	ctx := &ProcessingContext{FilePath: filePath}
	return fr.processFileInternal(filePath, ctx)
}

// processFileInternal is the actual implementation
func (fr *FileRouter) processFileInternal(filePath string, config *ProcessingContext) (*preprocessors.ProcessedContent, error) {

	// Use standardized observability
	finishTiming := fr.observer.StartTiming("router", "file_evaluation", config.FilePath)
	defer finishTiming(true, map[string]interface{}{
		"file_size": config.FileSize,
		"file_ext":  config.FileExt,
		// GENAI_DISABLED: "enable_genai": config.EnableGenAI,
	})

	// Find capable preprocessors
	var capable []preprocessors.Preprocessor
	for _, p := range fr.preprocessors {
		if p.CanProcess(filePath) {
			capable = append(capable, p)
		}
	}

	if len(capable) == 0 {
		return nil, fmt.Errorf("no preprocessor can handle file: %s", filePath)
	}

	// Run ALL capable preprocessors in parallel
	type preprocessorResult struct {
		name     string
		result   *preprocessors.ProcessedContent
		err      error
		duration time.Duration
	}

	resultChan := make(chan preprocessorResult, len(capable))

	// Start all preprocessors in parallel
	for _, p := range capable {
		go func(processor preprocessors.Preprocessor) {
			processStart := time.Now()

			// Recover from any panics in preprocessors to prevent crashing the whole scan
			var result *preprocessors.ProcessedContent
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("preprocessor panic in %s: %v", processor.GetName(), r)
					}
				}()
				result, err = processor.Process(filePath)
			}()

			processingTime := time.Since(processStart)

			resultChan <- preprocessorResult{
				name:     processor.GetName(),
				result:   result,
				err:      err,
				duration: processingTime,
			}
		}(p)
	}

	// Collect results
	var combinedContent strings.Builder
	var combinedMetadata = make(map[string]interface{})
	var totalWordCount, totalCharCount, totalLineCount int
	var successfulProcessors []string

	for i := 0; i < len(capable); i++ {
		pResult := <-resultChan

		if pResult.err == nil && pResult.result != nil && pResult.result.Success && pResult.result.Text != "" {
			// Add content with separator
			if combinedContent.Len() > 0 {
				combinedContent.WriteString("\n\n--- " + pResult.name + " ---\n")
			}
			combinedContent.WriteString(pResult.result.Text)

			// Accumulate metadata
			for k, v := range pResult.result.Metadata {
				combinedMetadata[pResult.name+"_"+k] = v
			}

			// Accumulate counts
			totalWordCount += pResult.result.WordCount
			totalCharCount += pResult.result.CharCount
			totalLineCount += pResult.result.LineCount

			successfulProcessors = append(successfulProcessors, pResult.name)
		}
	}

	// Return combined results if any preprocessor succeeded
	if len(successfulProcessors) > 0 {
		combinedMetadata["successful_processors"] = successfulProcessors
		result := &preprocessors.ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          combinedContent.String(),
			Format:        "combined",
			WordCount:     totalWordCount,
			CharCount:     totalCharCount,
			LineCount:     totalLineCount,
			ProcessorType: strings.Join(successfulProcessors, "+"),
			Success:       true,
			Metadata:      combinedMetadata,
		}

		return result, nil
	}

	return nil, fmt.Errorf("all preprocessors failed for file: %s", filePath)
}

// GENAI_DISABLED: CreateProcessingContext creates a standardized processing context
func (fr *FileRouter) CreateProcessingContext(filePath string, enableGenAI bool, genaiServices map[string]bool, genaiRegion string, debug bool) (*ProcessingContext, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	requestID := generateRequestID()

	return &ProcessingContext{
		FilePath: filePath,
		FileSize: info.Size(),
		FileExt:  strings.ToLower(filepath.Ext(filePath)),
		// GENAI_DISABLED: EnableGenAI:   enableGenAI,
		// GENAI_DISABLED: GenAIServices: genaiServices,
		// GENAI_DISABLED: GenAIRegion:   genaiRegion,
		MaxFileSize: MaxFileSize,
		RequestID:   requestID,
		StartTime:   time.Now(),
		Debug:       debug,
		metrics:     fr.metrics,
		logger:      fr.logger,
	}, nil
}

// GetMetrics returns current router metrics
func (fr *FileRouter) GetMetrics() *RouterMetrics {
	return fr.metrics
}

// GetPreprocessorCount returns the number of registered preprocessors
func (fr *FileRouter) GetPreprocessorCount() int {
	return len(fr.preprocessors)
}

// CanContainMetadata determines if a file type can contain meaningful metadata
func (fr *FileRouter) CanContainMetadata(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	canContain := isMetadataCapableFile(ext)

	// Debug logging for file type detection decisions
	if fr.observer != nil && fr.observer.DebugObserver != nil {
		fr.observer.DebugObserver.LogDetail("file_type_detection",
			fmt.Sprintf("File: %s, Extension: %s, CanContainMetadata: %t",
				filepath.Base(filePath), ext, canContain))
	}

	return canContain
}

// GetMetadataType returns the preprocessor-specific metadata type for a file
func (fr *FileRouter) GetMetadataType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	metadataType := getMetadataTypeForExtension(ext)

	// Debug logging for metadata type detection
	if fr.observer != nil && fr.observer.DebugObserver != nil {
		fr.observer.DebugObserver.LogDetail("metadata_type_detection",
			fmt.Sprintf("File: %s, Extension: %s, MetadataType: %s",
				filepath.Base(filePath), ext, metadataType))
	}

	return metadataType
}

// Helper functions

func isBinaryDocument(ext string) bool {
	binaryExts := map[string]bool{
		// Office documents
		".docx": true, ".doc": true, ".xlsx": true, ".xls": true, ".pptx": true, ".ppt": true,
		".odt": true, ".ods": true, ".odp": true,
		// PDF documents
		".pdf": true,
		// Image formats
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".tiff": true, ".tif": true,
		".bmp": true, ".webp": true, ".heic": true, ".heif": true, ".raw": true, ".cr2": true, ".nef": true, ".arw": true,
		// Video formats
		".mp4": true, ".mov": true, ".avi": true, ".mkv": true, ".wmv": true, ".flv": true,
		".webm": true, ".m4v": true, ".3gp": true, ".ogv": true,
		// Audio formats
		".mp3": true, ".flac": true, ".wav": true, ".ogg": true, ".m4a": true, ".aac": true, ".wma": true, ".opus": true,
	}
	return binaryExts[ext]
}

// isMetadataCapableFile determines if a file extension indicates metadata capability
// This reuses the existing isBinaryDocument logic as these files can contain metadata
func isMetadataCapableFile(ext string) bool {
	return isBinaryDocument(ext)
}

// getMetadataTypeForExtension returns the specific metadata type for preprocessor routing
func getMetadataTypeForExtension(ext string) string {
	switch ext {
	case ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".odp":
		return "office_metadata"
	case ".pdf":
		return "document_metadata"
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".heic", ".heif", ".raw", ".cr2", ".nef", ".arw":
		return "image_metadata"
	case ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v", ".3gp", ".ogv":
		return "video_metadata"
	case ".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".wma", ".opus":
		return "audio_metadata"
	default:
		return "none"
	}
}

func isTextFile(filePath string) (bool, error) {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return false, err
	}

	buffer = buffer[:n]

	// Check for null bytes
	for _, b := range buffer {
		if b == 0 {
			return false, nil
		}
	}

	// Check printable ratio
	printableCount := 0
	for _, b := range buffer {
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			printableCount++
		}
	}

	printableRatio := float64(printableCount) / float64(len(buffer))
	return printableRatio > 0.95, nil
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
