// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// ContentRouter intelligently separates metadata from document body content
type ContentRouter struct {
	observer   observability.Observer
	fileRouter *FileRouter // Reference to FileRouter for file type detection
}

// RoutedContent represents content that has been separated into document body and metadata
type RoutedContent struct {
	DocumentBody string            // Combined plain text + document text
	Metadata     []MetadataContent // Separated metadata by preprocessor
	OriginalPath string

	// FullText is every byte the preprocessors extracted, captured BEFORE any
	// routing decision is made.
	//
	// It is the SECOND of two independent controls, and it is deliberately kept now
	// that structure is declared out of band rather than parsed out of the text.
	// The first control removes the capability: routing reads
	// ProcessedContent.Sections, built from our own preprocessor names, so a
	// document author can no longer forge a section boundary. This one contains the
	// consequence if the first is ever wrong — a bug in a producer, a preprocessor
	// that populates Sections incorrectly, a caller that declares nothing.
	//
	// It matters because the two paths do not run the same validators. The document
	// path runs the full set; the metadata path runs a single field-name scanner
	// with no SSN, card, phone or email logic. So any split that moves content from
	// the document path to the metadata path moves it from ~19 validators to 1 that
	// cannot detect it, and the finding does not get relabelled, it vanishes. Since
	// only reported findings reach the redactor, a vanished finding is a value left
	// in cleartext.
	//
	// Letting the document path scan the union makes routing a LABELLING decision
	// rather than a COVERAGE decision, for section names nobody has thought of yet.
	// Do not "simplify" this away on the grounds that the declared sections are now
	// trustworthy: defence in depth is the point.
	FullText string
}

// MetadataContent represents metadata content with preprocessor context
type MetadataContent struct {
	Content          string                 // The actual metadata content
	PreprocessorType string                 // "image_metadata", "document_metadata", etc.
	PreprocessorName string                 // Human-readable name
	SourceFile       string                 // Original file path
	Metadata         map[string]interface{} // Additional metadata about the content
}

// ContentRouterError represents errors that occur during content routing
type ContentRouterError struct {
	Operation string
	FilePath  string
	Cause     error
}

func (e *ContentRouterError) Error() string {
	return fmt.Sprintf("content router %s failed for %s: %v", e.Operation, e.FilePath, e.Cause)
}

// Preprocessor type constants. These are the keys the METADATA validator's
// per-preprocessor rule table is indexed by, so a MetadataContent must carry one
// of them or the wrong sensitive-field list is applied.
//
// "mixed_content" used to live here too. It was a category the deleted
// text-sniffing classifier returned when it found metadata-looking markers in the
// document text; nothing keys a rule set off it, and with structure now declared
// out of band there is no way to reach it.
const (
	PreprocessorTypeImageMetadata    = "image_metadata"
	PreprocessorTypeDocumentMetadata = "document_metadata"
	PreprocessorTypeOfficeMetadata   = "office_metadata"
	PreprocessorTypeAudioMetadata    = "audio_metadata"
	PreprocessorTypeVideoMetadata    = "video_metadata"
	PreprocessorTypePlainText        = "plain_text"
	PreprocessorTypeDocumentText     = "document_text"
)

// NewContentRouter creates a new content router
func NewContentRouter() *ContentRouter {
	return &ContentRouter{}
}

// NewContentRouterWithFileRouter creates a new content router with FileRouter reference
func NewContentRouterWithFileRouter(fileRouter *FileRouter) *ContentRouter {
	return &ContentRouter{
		fileRouter: fileRouter,
	}
}

// SetFileRouter sets the FileRouter reference for metadata capability detection
func (cr *ContentRouter) SetFileRouter(fileRouter *FileRouter) {
	cr.fileRouter = fileRouter
}

// SetObserver sets the observability component
func (cr *ContentRouter) SetObserver(observer observability.Observer) {
	cr.observer = observer
}

// RouteContent separates and routes content to appropriate validators
func (cr *ContentRouter) RouteContent(processedContent *preprocessors.ProcessedContent) (*RoutedContent, error) {
	// Check for nil input first
	if processedContent == nil {
		err := &ContentRouterError{
			Operation: "route_content",
			FilePath:  "unknown",
			Cause:     fmt.Errorf("processed content is nil"),
		}
		// Start timing with unknown path for nil input
		if cr.observer != nil {
			finishTiming := cr.observer.StartTiming("content_router", "route_content", "unknown")
			finishTiming(false, map[string]interface{}{"error": err.Error()})
		}
		return nil, err
	}

	// Now we can safely access processedContent fields
	var finishTiming func(bool, map[string]interface{})
	if cr.observer != nil {
		finishTiming = cr.observer.StartTiming("content_router", "route_content", processedContent.OriginalPath)
	}

	// Initialize routed content.
	//
	// FullText is populated HERE, in the struct literal, deliberately: this is above
	// the CanContainMetadata early return below and above the whole
	// `switch preprocessorType`, including its graceful-degradation arms. Assigning
	// it inside any branch would leave some path emitting an empty FullText, and an
	// empty FullText silently disables the coverage guarantee for exactly the inputs
	// that took the unusual path.
	routedContent := &RoutedContent{
		OriginalPath: processedContent.OriginalPath,
		Metadata:     make([]MetadataContent, 0),
		FullText:     processedContent.Text,
	}

	// Check if file can contain metadata using FileRouter
	if cr.fileRouter != nil && !cr.fileRouter.CanContainMetadata(processedContent.OriginalPath) {
		// Skip metadata content creation entirely for non-metadata files
		routedContent.DocumentBody = processedContent.Text

		// Debug logging for file type filtering decision
		if cr.observer != nil && cr.observer.Debug() != nil {
			ext := strings.ToLower(filepath.Ext(processedContent.OriginalPath))
			cr.observer.Debug().LogDetail("file_type_filtering",
				fmt.Sprintf("Metadata validation skipped - File: %s, Extension: %s, Reason: file type does not support metadata",
					filepath.Base(processedContent.OriginalPath), ext))
		}

		if finishTiming != nil {
			finishTiming(true, map[string]interface{}{
				"metadata_skipped":     true,
				"reason":               "file_type_no_metadata",
				"document_body_length": len(routedContent.DocumentBody),
				"metadata_items":       0,
				"file_extension":       strings.ToLower(filepath.Ext(processedContent.OriginalPath)),
			})
		}

		return routedContent, nil
	}

	// Route from the OUT-OF-BAND structure when the producer declared one.
	//
	// This is the whole point of the change. The router previously recovered the
	// structure by scanning processedContent.Text for "--- name ---" lines — and a
	// document author types the text, so the author decided where the sections
	// were. A paragraph reading "--- office_metadata ---" moved everything after it
	// onto the metadata path, which runs ONE field-name scanner instead of the full
	// validator set, so the finding was not relabelled but deleted. In-band
	// signalling, same class as SQL injection, same answer: carry the structure
	// beside the data instead of re-deriving it from the data.
	//
	// ProcessedContent.Sections is built by the file router in the same loop that
	// builds the concatenation, from each Preprocessor's GetName(). That name is
	// our own code's constant, never a byte of the scanned file, so a boundary here
	// cannot be forged.
	if len(processedContent.Sections) > 0 {
		routedContent.DocumentBody, routedContent.Metadata = cr.routeSections(processedContent)
	} else {
		// FAIL CLOSED. No declared structure means we do not guess one from the
		// text — the whole extraction is document body, which is the safe
		// direction: the document path runs every validator, so the worst case is
		// a missing metadata LABEL, never missing coverage. (Reversing it would
		// hand the whole file to the single-field-name metadata scanner.)
		//
		// ProcessorType is still consulted, and that is not a hole: it is
		// strings.Join of the preprocessors' GetName() values, i.e. our own
		// constants, not document content. It is the one trustworthy classifier
		// available to a caller that builds ProcessedContent by hand (the pkg and
		// ScanContent entry points, and older callers) rather than through the file
		// router.
		routedContent.DocumentBody = processedContent.Text

		// A single metadata preprocessor's output is metadata as a whole, so it can
		// still be labelled without inspecting the text. DocumentBody above already
		// carries the same bytes to the document path: for a media file that is the
		// only thing that detects an SSN inside an EXIF field, because the METADATA
		// validator is a field-NAME allowlist that reports one coarse type per
		// matching line and never an SSN, a PAN or a key inside the value.
		if metaType := metadataTypeForProcessorType(processedContent.ProcessorType); metaType != "" &&
			strings.TrimSpace(processedContent.Text) != "" {
			routedContent.Metadata = append(routedContent.Metadata, MetadataContent{
				Content:          processedContent.Text,
				PreprocessorType: metaType,
				PreprocessorName: cr.getPreprocessorName(metaType),
				SourceFile:       processedContent.OriginalPath,
				Metadata: map[string]interface{}{
					"processor_type": processedContent.ProcessorType,
					"format":         processedContent.Format,
					"success":        processedContent.Success,
					"declared":       false,
				},
			})
		}
	}

	if finishTiming != nil {
		// processor_type is the preprocessors' own joined GetName() string now,
		// rather than a category inferred by sniffing the document text. The
		// sniffing classifier is gone: it was the read half of the in-band
		// signalling, and reporting a label derived from attacker-supplied text
		// would have kept a use for it alive.
		finishTiming(true, map[string]interface{}{
			"processor_type":       processedContent.ProcessorType,
			"document_body_length": len(routedContent.DocumentBody),
			"metadata_items":       len(routedContent.Metadata),
			"declared_sections":    len(processedContent.Sections),
		})
	}

	return routedContent, nil
}

// routeSections turns the producer-declared sections into the routed body and
// metadata items. It reads only ContentSection fields — never the section text —
// so nothing in the scanned document influences the split.
func (cr *ContentRouter) routeSections(processedContent *preprocessors.ProcessedContent) (string, []MetadataContent) {
	var bodySections []string
	metadataItems := make([]MetadataContent, 0, len(processedContent.Sections))

	for _, section := range processedContent.Sections {
		if section.Kind != preprocessors.SectionKindMetadata {
			bodySections = append(bodySections, section.Text)
			continue
		}

		// Skip a section with nothing in it rather than emitting an empty
		// metadata item, matching what the previous path did.
		if strings.TrimSpace(section.Text) == "" {
			continue
		}

		metaType := section.Type
		if metaType == "" {
			metaType = PreprocessorTypeDocumentMetadata
		}
		sourceFile := section.SourceFile
		if sourceFile == "" {
			sourceFile = processedContent.OriginalPath
		}

		metadataItems = append(metadataItems, MetadataContent{
			Content:          section.Text,
			PreprocessorType: metaType,
			PreprocessorName: cr.getPreprocessorName(metaType),
			SourceFile:       sourceFile,
			Metadata: map[string]interface{}{
				"processor_type": processedContent.ProcessorType,
				"format":         processedContent.Format,
				"success":        processedContent.Success,
				"declared":       true,
				"section_name":   section.Name,
				"section_line":   section.LineOffset,
			},
		})
	}

	// Join body sections with a blank line, mirroring the "\n\n" the file router
	// puts between concatenated preprocessor outputs. Without a separator the last
	// line of one section and the first of the next would land on a single logical
	// line, fusing two adjacent values or splitting one, and every line-based
	// validator would see the wrong line at each seam.
	documentBody := strings.Join(bodySections, "\n\n")

	// No body section at all (a pure-metadata file: every media type has exactly
	// one capable preprocessor, and it is a metadata one). Hand the metadata text
	// to the document path as well, because dual_path_bridge gates that path on
	// having text to scan, and the METADATA validator alone reports nothing for an
	// SSN or a card number sitting inside a metadata VALUE.
	if documentBody == "" {
		documentBody = processedContent.Text
	}

	return documentBody, metadataItems
}

// metadataTypeForProcessorType maps a SINGLE preprocessor's ProcessorType to the
// metadata type whose validation rules apply, or "" when the content is not
// wholly metadata (document text, plain text, an unknown producer, or a
// multi-preprocessor "a+b" join whose structure was not declared).
//
// Only used on the undeclared-structure path; a declared section carries its type
// directly. The input is our own GetName()-derived constant, so this is an exact
// match rather than the substring test the deleted text-scanning path used.
func metadataTypeForProcessorType(processorType string) string {
	switch strings.ToLower(strings.TrimSpace(processorType)) {
	case "image_metadata", "image-metadata", "imagemetadata":
		return PreprocessorTypeImageMetadata
	case "document_metadata", "document-metadata", "documentmetadata",
		"pdf_metadata", "pdf-metadata", "pdfmetadata":
		return PreprocessorTypeDocumentMetadata
	case "office_metadata", "office-metadata", "officemetadata":
		return PreprocessorTypeOfficeMetadata
	case "audio_metadata", "audio-metadata", "audiometadata":
		return PreprocessorTypeAudioMetadata
	case "video_metadata", "video-metadata", "videometadata":
		return PreprocessorTypeVideoMetadata
	default:
		return ""
	}
}

// getPreprocessorName returns a human-readable name for a preprocessor type
func (cr *ContentRouter) getPreprocessorName(preprocessorType string) string {
	switch preprocessorType {
	case PreprocessorTypeImageMetadata:
		return "Image Metadata Extractor"
	case PreprocessorTypeDocumentMetadata:
		return "Document Metadata Extractor"
	case PreprocessorTypeOfficeMetadata:
		return "Office Metadata Extractor"
	case PreprocessorTypeAudioMetadata:
		return "Audio Metadata Extractor"
	case PreprocessorTypeVideoMetadata:
		return "Video Metadata Extractor"
	case PreprocessorTypePlainText:
		return "Plain Text Preprocessor"
	case PreprocessorTypeDocumentText:
		return "Document Text Extractor"
	default:
		return "Unknown Preprocessor"
	}
}
