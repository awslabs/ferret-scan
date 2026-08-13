// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"context"
	"errors"
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

	// ProcessEmbedded processes a child file that was extracted OUT OF parentPath,
	// enforcing a nesting-depth bound.
	//
	// Separate from ProcessFile because the router is the only component that can own
	// the depth: the preprocessor instance is shared across concurrent workers (so it
	// cannot hold per-call state) and Process takes no context to thread one through.
	// The preprocessor knows its own path — that is the argument to Process — so
	// passing it as parentPath is enough for the router to compute depth without any
	// change to the Preprocessor interface.
	//
	// Returns ErrEmbeddedTooDeep when the bound is reached. Callers must DISCLOSE
	// that rather than skipping quietly: refusing to descend is incomplete coverage,
	// and an undisclosed gap reads as a clean result.
	ProcessEmbedded(childPath, parentPath string) (*ProcessedContent, error)
}

// ErrEmbeddedTooDeep is returned by RouterInterface.ProcessEmbedded when a container
// nests deeper than the router's bound.
//
// A sentinel rather than a formatted string so the caller can branch on it with
// errors.Is and tell "too deep" (coverage was cut short — say so) apart from "this
// child failed to parse" (already handled by the ordinary error path).
var ErrEmbeddedTooDeep = errors.New("embedded container nesting limit reached")

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
// ProcessEmbeddedMedia now also returns WARNINGS: notes about embedded items it could
// not descend into. An item skipped silently is undisclosed missing coverage, which is
// the failure mode this whole area keeps producing.
func (bmp *BaseMetadataPreprocessor) ProcessEmbeddedMedia(originalFilePath string, embeddedMedia []EmbeddedMedia) (string, []ContentSection, []string) {
	if bmp.router == nil || len(embeddedMedia) == 0 {
		return "", nil, nil
	}

	var result string
	var sections []ContentSection
	// warnings records embedded items we declined to descend into, so the caller can
	// surface them through ExtractionWarning.
	var warnings []string
	// Line cursor into `result`, maintained incrementally.
	line := 0

	for i, media := range embeddedMedia {
		// Create context showing original file relationship
		embeddedPath := bmp.utilities.RouterHelper.CreateEmbeddedMediaPath(originalFilePath, media.OriginalName)

		// Reprocess embedded media through the router.
		//
		// NOTHING BOUNDS THE NESTING DEPTH HERE. This comment used to claim the
		// router tracked depth "keyed on the temp path it handed out, see
		// FileRouter.noteEmbeddedChild". No such method exists, and no
		// nesting-depth tracking exists anywhere in internal/router or
		// internal/preprocessors — the only guards are the size caps
		// MaxFileSize (100MB) and MaxEmbeddedMediaSize (50MB), and a
		// deep-nesting bomb is small on disk.
		//
		// That mattered because this call site is exactly where someone would look
		// before admitting embedded OOXML documents in
		// meta-extract-officelib.embeddedMediaType, which is currently the other
		// half of the nesting leak (an embedded .docx is never scanned; see #297).
		// A reader who trusted the old comment would have concluded a bound was
		// already in place and shipped unbounded recursion.
		//
		// Recursion is bounded TODAY only because the admitted types are leaves:
		// images and audio route to extractors that follow nothing, and the legacy
		// .doc/.xls/.ppt extractor reads OLE streams directly without following
		// embeddings. Admitting .docx/.xlsx/.pptx routes back into this same
		// function, so it requires a real depth cap first — and a cap must DISCLOSE
		// when it truncates, or it replaces a silent miss with a different one.
		processed, perr := bmp.router.ProcessEmbedded(media.TempFilePath, originalFilePath)
		if errors.Is(perr, ErrEmbeddedTooDeep) {
			// DISCLOSE rather than skip. Hitting the bound means this item's content
			// was never examined; saying nothing would reproduce the exact bug the
			// bound was added alongside.
			warnings = append(warnings, fmt.Sprintf(
				"embedded item %q was not examined: %v", filepath.Base(media.OriginalName), perr))
			continue
		}
		if perr == nil && processed != nil && processed.Success {
			// Carry the CHILD's own warning up.
			//
			// Without this the disclosure dies one level below where it is needed. The
			// nesting bound fires deep in the chain and sets ExtractionWarning on THAT
			// level's content; every level above then reads only processed.Text, so a
			// 9-level bomb terminated correctly at the bound and reported nothing at all
			// -- measured: 0 findings, 0 disclosure lines. Propagating it means the top
			// level, which is the one the operator sees, says coverage was cut short.
			if processed.ExtractionWarning != "" {
				warnings = append(warnings, processed.ExtractionWarning)
			}

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

	return result, sections, warnings
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
