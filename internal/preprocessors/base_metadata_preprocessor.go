// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// RouterInterface defines the router functionality the metadata preprocessors
// need (set via SetRouter). Defined here alongside its only consumer,
// BaseMetadataPreprocessor and the specialized preprocessors that embed it.
type RouterInterface interface {
	ProcessFile(filePath string, context interface{}) (*ProcessedContent, error)
}

// BaseMetadataPreprocessor provides common functionality for all specialized metadata preprocessors
type BaseMetadataPreprocessor struct {
	name            string
	processorType   string
	observer        observability.Observer
	router          RouterInterface
	resourceManager *MediaResourceManager
	errorHandler    *GracefulDegradationHandler
	errorLogger     *ErrorLogger
	recoveryManager *ErrorRecoveryManager
	utilities       *SharedUtilities
}

// NewBaseMetadataPreprocessor creates a new base metadata preprocessor
func NewBaseMetadataPreprocessor(name, processorType string) *BaseMetadataPreprocessor {
	return &BaseMetadataPreprocessor{
		name:            name,
		processorType:   processorType,
		resourceManager: NewMediaResourceManager(),
		errorHandler:    NewGracefulDegradationHandler(),
		errorLogger:     NewErrorLogger(LogLevelWarn),
		recoveryManager: NewErrorRecoveryManager(),
		utilities:       NewSharedUtilities(),
	}
}

// GetName returns the name of this preprocessor
func (bmp *BaseMetadataPreprocessor) GetName() string {
	return bmp.name
}

// SetObserver sets the observability component
func (bmp *BaseMetadataPreprocessor) SetObserver(observer observability.Observer) {
	bmp.observer = observer
}

// SetRouter sets the router instance for reprocessing embedded media
func (bmp *BaseMetadataPreprocessor) SetRouter(router RouterInterface) {
	bmp.router = router
}

// GetUtilities returns the shared utilities instance
func (bmp *BaseMetadataPreprocessor) GetUtilities() *SharedUtilities {
	return bmp.utilities
}

// GetObserver returns the observer instance
func (bmp *BaseMetadataPreprocessor) GetObserver() observability.Observer {
	return bmp.observer
}

// GetRouter returns the router instance
func (bmp *BaseMetadataPreprocessor) GetRouter() RouterInterface {
	return bmp.router
}

// LogDebugInfo logs debug information if observer is available
func (bmp *BaseMetadataPreprocessor) LogDebugInfo(message string) {
	if bmp.observer != nil && bmp.observer.Debug() != nil {
		bmp.observer.Debug().LogDetail(bmp.name, message)
	}
}

// LogFileSystemInfo logs file system information for observability (excluded from validator content)
func (bmp *BaseMetadataPreprocessor) LogFileSystemInfo(filename string, fileSize int64, mimeType string) {
	if bmp.observer != nil && bmp.observer.Debug() != nil {
		message := fmt.Sprintf("File system info - Name: %s, Size: %d bytes, Type: %s", filename, fileSize, mimeType)
		bmp.observer.Debug().LogDetail(bmp.name, message)
	}
}

// LogSuccessfulProcessing logs successful processing information
func (bmp *BaseMetadataPreprocessor) LogSuccessfulProcessing(filename string, fileSize int64, mimeType string) {
	if bmp.observer != nil && bmp.observer.Debug() != nil {
		message := fmt.Sprintf("Successfully extracted %s metadata - Name: %s, Size: %d bytes, Type: %s",
			bmp.processorType, filename, fileSize, mimeType)
		bmp.observer.Debug().LogDetail(bmp.name, message)
	}
}

// LogRetryAttempt logs retry attempt information
func (bmp *BaseMetadataPreprocessor) LogRetryAttempt(filePath string, attemptCount int) {
	if bmp.observer != nil && bmp.observer.Debug() != nil {
		message := fmt.Sprintf("Retrying %s metadata extraction for %s (attempt %d)",
			bmp.processorType, filePath, attemptCount+1)
		bmp.observer.Debug().LogDetail(bmp.name, message)
	}
}

// ValidateFileSize validates file size based on file type
func (bmp *BaseMetadataPreprocessor) ValidateFileSize(filePath string, isVideo bool) error {
	return bmp.resourceManager.ValidateFileSize(filePath, isVideo)
}

// CreateProcessingContext creates a context with timeout for processing
func (bmp *BaseMetadataPreprocessor) CreateProcessingContext() (context.Context, context.CancelFunc) {
	return bmp.resourceManager.CreateProcessingContext()
}

// HandleError handles processing errors with comprehensive error handling
func (bmp *BaseMetadataPreprocessor) HandleError(filePath, fileType string, err error) *ProcessedContent {
	content := bmp.errorHandler.HandleError(filePath, fileType, err)

	// Update processor type to match this specific preprocessor
	content.ProcessorType = bmp.processorType
	content.Format = fmt.Sprintf("%s_metadata", fileType)

	if mediaErr, ok := content.Error.(*MediaProcessingError); ok {
		bmp.errorLogger.LogError(mediaErr)
	}

	return content
}

// ShouldRetry determines if processing should be retried based on error type and attempt count
func (bmp *BaseMetadataPreprocessor) ShouldRetry(err error, attemptCount int) bool {
	if mediaErr, ok := err.(*MediaProcessingError); ok {
		return bmp.recoveryManager.ShouldRetry(mediaErr.GetErrorType(), attemptCount)
	}

	// For non-MediaProcessingError, classify the error first
	errorType := bmp.errorHandler.classifier.ClassifyError(err)
	return bmp.recoveryManager.ShouldRetry(errorType, attemptCount)
}

// AddRetryDelay adds a small delay before retry attempts
func (bmp *BaseMetadataPreprocessor) AddRetryDelay(attemptCount int) {
	delay := time.Millisecond * 100 * time.Duration(attemptCount+1)
	time.Sleep(delay)
}

// BuildSuccessContent creates a successful ProcessedContent structure
func (bmp *BaseMetadataPreprocessor) BuildSuccessContent(filePath, text, format string, pageCount int) *ProcessedContent {
	return bmp.utilities.ContentBuilder.BuildSuccessContent(filePath, text, format, bmp.processorType, pageCount)
}

// BuildErrorContent creates a failed ProcessedContent structure
func (bmp *BaseMetadataPreprocessor) BuildErrorContent(filePath, format string, err error) *ProcessedContent {
	return bmp.utilities.ContentBuilder.BuildErrorContent(filePath, format, bmp.processorType, err)
}

// ProcessWithRetry provides a generic retry mechanism for metadata processing
func (bmp *BaseMetadataPreprocessor) ProcessWithRetry(filePath string, processFunc func() (*ProcessedContent, error)) (*ProcessedContent, error) {
	return bmp.processWithRetryInternal(filePath, processFunc, 0)
}

// processWithRetryInternal handles the internal retry logic
func (bmp *BaseMetadataPreprocessor) processWithRetryInternal(filePath string, processFunc func() (*ProcessedContent, error), attemptCount int) (*ProcessedContent, error) {
	content, err := processFunc()

	if err != nil && bmp.ShouldRetry(err, attemptCount) {
		bmp.LogRetryAttempt(filePath, attemptCount)
		bmp.AddRetryDelay(attemptCount)
		return bmp.processWithRetryInternal(filePath, processFunc, attemptCount+1)
	}

	return content, err
}

// ProcessEmbeddedMedia processes embedded media through the router if available.
//
// It returns the text to append to the container's own metadata text, AND one
// ContentSection per embedded item describing that text out of band. The sections'
// LineOffset values are relative to the START OF THE RETURNED TEXT; the caller
// shifts them by the length of whatever it puts in front.
//
// The sections matter because an embedded item is a section INSIDE one
// preprocessor's output, and it routes to a DIFFERENT metadata rule set than its
// container: a .wav inside a .docx carries an "Artist:" field, which is on the
// audio rule list but not the office one. Without a declared sub-section the whole
// blob would be labelled office_metadata and that field would report nothing.
// Measured: the AUTHOR_INFO finding for an embedded clip's artist address
// disappeared until these sections were carried.
func (bmp *BaseMetadataPreprocessor) ProcessEmbeddedMedia(originalFilePath string, embeddedMedia []EmbeddedMedia) (string, []ContentSection) {
	if bmp.router == nil || len(embeddedMedia) == 0 {
		return "", nil
	}

	var result string
	var sections []ContentSection
	// Line cursor into `result`, maintained incrementally.
	line := 0

	for i, media := range embeddedMedia {
		// Create context showing original file relationship
		embeddedPath := bmp.utilities.RouterHelper.CreateEmbeddedMediaPath(originalFilePath, media.OriginalName)

		// Reprocess embedded media through router
		// The router tracks nesting depth itself, keyed on the temp path it handed
		// out for this embedded item -- see FileRouter.noteEmbeddedChild. The
		// preprocessor cannot construct a router ProcessingContext (router imports
		// preprocessors, so the reverse would be an import cycle) and its Process
		// method takes no context to thread one through, so depth is owned on the
		// router side rather than plumbed through every preprocessor signature.
		if processed, err := bmp.router.ProcessFile(media.TempFilePath, nil); err == nil && processed != nil && processed.Success {
			// Update processed content to show original file relationship
			processed.OriginalPath = embeddedPath
			processed.Filename = embeddedPath

			// Format and append embedded media section
			block := bmp.utilities.RouterHelper.FormatEmbeddedMediaSection(i, media.OriginalName, processed.Text)
			result += block

			// FormatEmbeddedMediaSection prefixes "\n--- ... ---\n", so the
			// item's own text starts two lines further on.
			contentLine := line + 2

			// Attribute findings to "container.docx -> audio1.wav", i.e. the BARE
			// media filename. CreateEmbeddedMediaPath keeps the full archive member
			// name ("word/media/audio1.wav"); the label the deleted text-parsing
			// path produced was the basename, and it is what appears in the FILE
			// column of every report, so keep it identical.
			sectionSource := bmp.utilities.RouterHelper.CreateEmbeddedMediaPath(
				originalFilePath, filepath.Base(media.OriginalName))

			// Prefer the sub-result's OWN declared sections — the router built
			// them from that file's preprocessor names — and just re-anchor them
			// onto this text and onto the "container -> item" source label. This
			// composes: a section nested two levels deep still carries the rule
			// set of the extractor that actually produced it.
			if len(processed.Sections) > 0 {
				for _, sub := range processed.Sections {
					sub.SourceFile = sectionSource
					sub.LineOffset += contentLine
					sections = append(sections, sub)
				}
			} else {
				kind, metaType := ClassifySection(processed.ProcessorType)
				sections = append(sections, ContentSection{
					Name:       processed.ProcessorType,
					Kind:       kind,
					Type:       metaType,
					SourceFile: embeddedPath,
					Text:       processed.Text,
					LineOffset: contentLine,
				})
			}

			line += strings.Count(block, "\n")
		}
	}

	return result, sections
}

// EmbeddedMedia represents embedded media extracted from documents
type EmbeddedMedia struct {
	OriginalName string
	TempFilePath string
	MediaType    string
}

// MetadataProcessingConfig holds configuration for metadata processing
type MetadataProcessingConfig struct {
	EnableRetry          bool
	MaxRetries           int
	EnableResourceLimits bool
	EnableObservability  bool
}

// DefaultMetadataProcessingConfig returns default configuration
func DefaultMetadataProcessingConfig() *MetadataProcessingConfig {
	return &MetadataProcessingConfig{
		EnableRetry:          true,
		MaxRetries:           3,
		EnableResourceLimits: true,
		EnableObservability:  true,
	}
}

// ApplyConfig applies configuration to the base preprocessor
func (bmp *BaseMetadataPreprocessor) ApplyConfig(config *MetadataProcessingConfig) {
	if config.MaxRetries > 0 {
		bmp.recoveryManager.SetMaxRetries(config.MaxRetries)
	}
}
