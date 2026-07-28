// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// FileRouter handles file routing and preprocessing decisions
type FileRouter struct {
	registry      *PreprocessorRegistry
	preprocessors []preprocessors.Preprocessor
	metrics       *RouterMetrics
	logger        *DebugLogger
	observer      observability.Observer
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
func (fr *FileRouter) CanProcessFile(filePath string, enablePreprocessors bool) (bool, string) {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Check file size
	cleanPath := filepath.Clean(filePath)
	if info, err := os.Stat(cleanPath); err == nil {
		if info.Size() > MaxFileSize {
			return false, fmt.Sprintf("File too large (max: %dMB)", MaxFileSize/(1024*1024))
		}
	}

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

	// Sort by name so the assembly order below is a property of the file type,
	// not of how the registry happened to be iterated. For Office and PDF files
	// this puts "Text Extractor" ahead of "office_metadata"/"pdf_metadata", so
	// the document body is the leading section and each metadata block carries
	// an explicit "--- name ---" header.
	sort.Slice(capable, func(i, j int) bool {
		return capable[i].GetName() < capable[j].GetName()
	})

	// Run ALL capable preprocessors in parallel
	type preprocessorResult struct {
		idx      int
		name     string
		result   *preprocessors.ProcessedContent
		err      error
		duration time.Duration
	}

	resultChan := make(chan preprocessorResult, len(capable))

	// Start all preprocessors in parallel
	for i, p := range capable {
		go func(idx int, processor preprocessors.Preprocessor) {
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
				idx:      idx,
				name:     processor.GetName(),
				result:   result,
				err:      err,
				duration: processingTime,
			}
		}(i, p)
	}

	// Collect results.
	//
	// Drain into a slice indexed by LAUNCH position, not by arrival position.
	// Preprocessors run concurrently, so consuming the channel in completion
	// order made the assembled text — and therefore every line number reported
	// against it — depend on which goroutine won the race. For a .docx both
	// "Text Extractor" and "office_metadata" are capable, so the metadata block
	// landed above or below the body at random, and findings shifted by the
	// height of that block between two scans of the same file (issue #179).
	//
	// The overwhelmingly common case is a single successful preprocessor (one
	// file type → one extractor). For that case we must NOT copy the extracted
	// text a second time: a strings.Builder.WriteString duplicates the whole
	// payload into the builder's buffer (a full second copy of, e.g., a 10 MB
	// extracted PDF), even though String() itself is zero-copy. So we keep a
	// direct reference to the sole result's text (firstText) and only fall back
	// to the strings.Builder when a SECOND successful preprocessor arrives and
	// we genuinely have to concatenate with separators. The builder path emits
	// the first successful text, then "\n\n--- name ---\n" + text for each
	// subsequent processor, in sorted-name order; the single-processor path
	// yields Text == firstText exactly, since no separator is prepended to the
	// first write. (v2 gap 2.3: eliminate the combine-step second copy.)
	ordered := make([]preprocessorResult, len(capable))
	for i := 0; i < len(capable); i++ {
		pResult := <-resultChan
		ordered[pResult.idx] = pResult
	}

	var combinedContent strings.Builder
	var firstText string
	var combinedMetadata = make(map[string]interface{})
	var totalWordCount, totalCharCount, totalLineCount int
	var successfulProcessors []string

	for _, pResult := range ordered {
		if pResult.err == nil && pResult.result != nil && pResult.result.Success && pResult.result.Text != "" {
			if len(successfulProcessors) == 0 {
				// First success: reference its text directly (no copy).
				firstText = pResult.result.Text
			} else {
				// Second+ success: we are truly combining. Flush the stashed
				// first text into the builder once, then append this one with a
				// separator.
				if combinedContent.Len() == 0 {
					combinedContent.WriteString(firstText)
				}
				combinedContent.WriteString("\n\n--- " + pResult.name + " ---\n")
				combinedContent.WriteString(pResult.result.Text)
			}

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
		// Single successful processor → use its text directly (zero extra copy);
		// multiple → the builder holds the byte-identical concatenation.
		text := firstText
		if combinedContent.Len() > 0 {
			text = combinedContent.String()
		}
		result := &preprocessors.ProcessedContent{
			OriginalPath:  filePath,
			Filename:      filepath.Base(filePath),
			Text:          text,
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

// CreateProcessingContext creates a standardized processing context for a file.
func (fr *FileRouter) CreateProcessingContext(filePath string, debug bool) (*ProcessingContext, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, err
	}

	requestID := generateRequestID()

	return &ProcessingContext{
		FilePath:    filePath,
		FileSize:    info.Size(),
		FileExt:     strings.ToLower(filepath.Ext(filePath)),
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
	if fr.observer != nil && fr.observer.Debug() != nil {
		fr.observer.Debug().LogDetail("file_type_detection",
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
	if fr.observer != nil && fr.observer.Debug() != nil {
		fr.observer.Debug().LogDetail("metadata_type_detection",
			fmt.Sprintf("File: %s, Extension: %s, MetadataType: %s",
				filepath.Base(filePath), ext, metadataType))
	}

	return metadataType
}

// Helper functions

// extValidator is the SINGLE source of truth for which extensions the metadata
// preprocessors actually handle. The router's routing gate (isBinaryDocument /
// isMetadataCapableFile / getMetadataTypeForExtension) delegates to it so the
// gate can never claim to process an extension that no preprocessor supports.
//
// Previously the router carried its own broader hardcoded list (adding e.g.
// .heic/.doc/.avi/.ogg) that had DRIFTED from what the preprocessors' own
// FileExtensionValidator recognizes. A .heic file passed the gate, then reached
// processFileInternal where every preprocessor's CanProcess returned false,
// producing a mid-pipeline "no preprocessor can handle file" error instead of a
// clean "unsupported file type" skip. Deriving the gate from the same validator
// the preprocessors use removes that drift (v2 gap 5.3).
var extValidator = preprocessors.NewFileExtensionValidator()

// extProbe turns a bare extension (".heic") into a filename the
// FileExtensionValidator's path-based predicates can inspect (its Is*File
// methods run filepath.Ext internally, which returns "" for a bare ".heic").
func extProbe(ext string) string { return "f" + ext }

func isBinaryDocument(ext string) bool {
	p := extProbe(ext)
	return extValidator.IsOfficeFile(p) ||
		extValidator.IsPDFFile(p) ||
		extValidator.IsImageFile(p) ||
		extValidator.IsVideoFile(p) ||
		extValidator.IsAudioFile(p)
}

// isMetadataCapableFile determines if a file extension indicates metadata capability
// This reuses the existing isBinaryDocument logic as these files can contain metadata
func isMetadataCapableFile(ext string) bool {
	return isBinaryDocument(ext)
}

// getMetadataTypeForExtension returns the specific metadata type for preprocessor
// routing, keyed off the shared FileExtensionValidator. The returned strings are
// the same the specialized preprocessors identify with (office/document/image/
// video/audio_metadata); "none" for anything no preprocessor handles.
func getMetadataTypeForExtension(ext string) string {
	p := extProbe(ext)
	switch {
	case extValidator.IsOfficeFile(p):
		return "office_metadata"
	case extValidator.IsPDFFile(p):
		return "document_metadata"
	case extValidator.IsImageFile(p):
		return "image_metadata"
	case extValidator.IsVideoFile(p):
		return "video_metadata"
	case extValidator.IsAudioFile(p):
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

	// Null-byte gating happens inside LooksLikeText, after encoding
	// detection — UTF-16 text carries a null per ASCII character, so a
	// pre-decode null check would (and previously did) classify every
	// UTF-16 file as binary.
	// UTF-8-aware sniff shared with the plaintext preprocessor: the previous
	// ASCII-byte-ratio copy here silently classified short lines containing
	// any multi-byte character (™, em-dash, accents, non-Latin scripts) as
	// binary, skipping the file for every validator in file mode.
	return preprocessors.LooksLikeText(buffer), nil
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
