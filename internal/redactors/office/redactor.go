// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/position"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// OfficeRedactor implements redaction for Microsoft Office documents using unified ZIP/XML approach
type OfficeRedactor struct {
	// observer handles observability and metrics
	observer observability.Observer

	// outputManager handles file system operations
	outputManager *redactors.OutputStructureManager

	// positionCorrelator handles position correlation between extracted and original text
	positionCorrelator position.PositionCorrelator

	// enablePositionCorrelation controls whether to use position correlation
	enablePositionCorrelation bool

	// confidenceThreshold is the minimum confidence required for position-based redaction
	confidenceThreshold float64

	// fallbackToSimple controls whether to fall back to simple text replacement on correlation failure
	fallbackToSimple bool
}

// OfficeDocumentType represents the type of Office document
type OfficeDocumentType int

const (
	// DocumentTypeUnknown represents an unknown document type
	DocumentTypeUnknown OfficeDocumentType = iota
	// DocumentTypeDOCX represents a Word document
	DocumentTypeDOCX
	// DocumentTypeXLSX represents an Excel spreadsheet
	DocumentTypeXLSX
	// DocumentTypePPTX represents a PowerPoint presentation
	DocumentTypePPTX
)

// Decompression-bomb bounds for extractOfficeContent. An Office file is a ZIP,
// and the only upstream gate is on-disk (compressed) size — a small archive can
// declare gigabytes of uncompressed content. These caps bound what a single
// document can expand to in memory. They mirror the 50MB/entry cap already used
// by the text and metadata extractors; the redactor was the one reader still
// doing an unbounded io.ReadAll (security finding HIGH-4).
const (
	// maxOfficeEntryBytes bounds a single decompressed zip entry.
	maxOfficeEntryBytes = 50 * 1024 * 1024 // 50MB
	// maxOfficeTotalBytes bounds the cumulative decompressed size across all
	// entries in one document.
	maxOfficeTotalBytes = 200 * 1024 * 1024 // 200MB
)

// String returns the string representation of the document type
func (dt OfficeDocumentType) String() string {
	switch dt {
	case DocumentTypeDOCX:
		return "docx"
	case DocumentTypeXLSX:
		return "xlsx"
	case DocumentTypePPTX:
		return "pptx"
	default:
		return "unknown"
	}
}

// NewOfficeRedactor creates a new OfficeRedactor
func NewOfficeRedactor(outputManager *redactors.OutputStructureManager, observer observability.Observer) *OfficeRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	return &OfficeRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        position.NewDefaultPositionCorrelator(),
		enablePositionCorrelation: true,
		confidenceThreshold:       0.8,
		fallbackToSimple:          true,
	}
}

// GetName returns the name of the redactor
func (or *OfficeRedactor) GetName() string {
	return "office_redactor"
}

// GetSupportedTypes returns the file types this redactor can handle
func (or *OfficeRedactor) GetSupportedTypes() []string {
	return []string{"docx", ".docx", "xlsx", ".xlsx", "pptx", ".pptx"}
}

// GetSupportedStrategies returns the redaction strategies this redactor supports
func (or *OfficeRedactor) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// RedactDocument creates a redacted copy of the Office document at outputPath
func (or *OfficeRedactor) RedactDocument(originalPath string, outputPath string, matches []detector.Match, strategy redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	var finishTiming func(bool, map[string]interface{})
	if or.observer != nil {
		finishTiming = or.observer.StartTiming("office_redactor", "redact_document", originalPath)
	} else {
		finishTiming = func(bool, map[string]interface{}) {} // No-op function
	}
	defer finishTiming(true, map[string]interface{}{
		"output_path": outputPath,
		"match_count": len(matches),
		"strategy":    strategy.String(),
	})

	startTime := time.Now()

	// Detect document type
	docType, err := or.detectDocumentType(originalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect document type: %w", err)
	}

	// Extract ZIP contents and text
	zipContents, extractedText, textPositions, err := or.extractOfficeContent(originalPath, docType)
	if err != nil {
		return nil, fmt.Errorf("failed to extract office content: %w", err)
	}

	// Perform redaction
	redactionMap, modifiedContents, err := or.redactOfficeContent(zipContents, extractedText, textPositions, matches, strategy, docType)
	if err != nil {
		return nil, fmt.Errorf("failed to redact office content: %w", err)
	}

	// Repackage ZIP with modified contents
	err = or.repackageOfficeDocument(modifiedContents, outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to repackage office document: %w", err)
	}

	// Calculate overall confidence
	confidence := or.calculateOverallConfidence(redactionMap)

	processingTime := time.Since(startTime)

	return &redactors.RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     redactionMap,
		ProcessingTime:   processingTime,
		Confidence:       confidence,
		Error:            nil,
	}, nil
}

// detectDocumentType detects the type of Office document by examining the ZIP contents
func (or *OfficeRedactor) detectDocumentType(filePath string) (OfficeDocumentType, error) {
	// First, try to detect by file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".docx":
		return DocumentTypeDOCX, nil
	case ".xlsx":
		return DocumentTypeXLSX, nil
	case ".pptx":
		return DocumentTypePPTX, nil
	}

	// If extension is not conclusive, examine ZIP contents
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return DocumentTypeUnknown, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	// Look for content types file
	for _, file := range reader.File {
		if file.Name == "[Content_Types].xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				continue
			}

			contentStr := string(content)
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main") {
				return DocumentTypeDOCX, nil
			}
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main") {
				return DocumentTypeXLSX, nil
			}
			if strings.Contains(contentStr, "application/vnd.openxmlformats-officedocument.presentationml.presentation.main") {
				return DocumentTypePPTX, nil
			}
		}
	}

	return DocumentTypeUnknown, fmt.Errorf("unable to determine document type")
}

// OfficeZipContents represents the contents of an Office document ZIP file
type OfficeZipContents struct {
	Files map[string][]byte // filename -> content

	// Order is the entry order of the ORIGINAL package, captured while reading
	// it. Repackaging replays this order instead of ranging Files, which is a
	// Go map and therefore randomized: without it the redacted .docx/.xlsx/.pptx
	// was written with its parts in a different sequence on every run, so the
	// same input produced a different output file each time — no byte
	// reproducibility for anything that hashes or diffs the artifact. It also
	// meant [Content_Types].xml frequently landed after the content parts, and
	// OPC requires it to be the first entry in the package.
	Order []string
}

// addFile records a package entry, preserving first-seen order.
func (c *OfficeZipContents) addFile(name string, content []byte) {
	if _, exists := c.Files[name]; !exists {
		c.Order = append(c.Order, name)
	}
	c.Files[name] = content
}

// orderedNames returns the entry names in the original package order, with any
// entry that is present in Files but absent from Order appended in sorted order.
// The fallback keeps output deterministic even if a future code path adds a part
// without going through addFile.
func (c *OfficeZipContents) orderedNames() []string {
	names := make([]string, 0, len(c.Files))
	seen := make(map[string]bool, len(c.Files))
	for _, name := range c.Order {
		if _, exists := c.Files[name]; exists && !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	if len(names) == len(c.Files) {
		return names
	}

	extra := make([]string, 0, len(c.Files)-len(names))
	for name := range c.Files {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return append(names, extra...)
}

// OfficeTextPosition represents text position information in an Office document
type OfficeTextPosition struct {
	FileName       string            // XML file containing the text
	XMLPath        string            // XPath-like location in XML
	DocumentOffset int               // Character offset within the entire document
	Text           string            // The actual text
	ElementInfo    OfficeElementInfo // XML element information
}

// OfficeElementInfo contains XML element information for Office text
type OfficeElementInfo struct {
	ElementName string            // XML element name (e.g., "w:t", "t", "a:t")
	Attributes  map[string]string // Element attributes
	ParentPath  string            // Path to parent element
}

// extractOfficeContent extracts ZIP contents and text from an Office document
func (or *OfficeRedactor) extractOfficeContent(filePath string, docType OfficeDocumentType) (*OfficeZipContents, string, []OfficeTextPosition, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to open ZIP file: %w", err)
	}
	defer reader.Close()

	zipContents := &OfficeZipContents{
		Files: make(map[string][]byte, len(reader.File)),
		Order: make([]string, 0, len(reader.File)),
	}

	var extractedText strings.Builder
	var textPositions []OfficeTextPosition
	var totalDecompressed int64

	// Extract all files from ZIP
	for _, file := range reader.File {
		// Reject before decompressing when the entry declares a size over the
		// per-entry cap. This is the cheap first line of defense against a
		// decompression bomb (a tiny compressed entry claiming multi-GB output).
		if file.UncompressedSize64 > maxOfficeEntryBytes {
			return nil, "", nil, fmt.Errorf("office entry %q declares %d bytes, exceeding the %d cap (possible decompression bomb)",
				file.Name, file.UncompressedSize64, maxOfficeEntryBytes)
		}

		rc, err := file.Open()
		if err != nil {
			or.logEvent("file_extraction_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}

		// Read at most one byte past the cap so a lying declared size (or a
		// stored/zip64 entry) is still caught by the actual decompressed length.
		content, err := io.ReadAll(io.LimitReader(rc, maxOfficeEntryBytes+1))
		rc.Close()
		if err != nil {
			or.logEvent("file_read_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}
		// The redactor repackages exactly what it reads, so a truncated entry
		// would silently corrupt the redacted output — fail closed instead.
		if int64(len(content)) > maxOfficeEntryBytes {
			return nil, "", nil, fmt.Errorf("office entry %q exceeds the %d per-entry decompression cap (possible bomb)",
				file.Name, maxOfficeEntryBytes)
		}
		totalDecompressed += int64(len(content))
		if totalDecompressed > maxOfficeTotalBytes {
			return nil, "", nil, fmt.Errorf("office document exceeds the %d cumulative decompression cap (possible bomb)",
				maxOfficeTotalBytes)
		}

		// Record the entry with its position in the source package, so the
		// repackaged document is written in the same order.
		zipContents.addFile(file.Name, content)

		// Extract text from relevant XML files
		if or.isTextContainingFile(file.Name, docType) {
			fileText, filePositions, err := or.extractTextFromXML(file.Name, content, docType, extractedText.Len())
			if err != nil {
				or.logEvent("text_extraction_failed", false, map[string]interface{}{
					"file_name": file.Name,
					"error":     err.Error(),
				})
				continue
			}

			extractedText.WriteString(fileText)
			textPositions = append(textPositions, filePositions...)
		}
	}

	return zipContents, extractedText.String(), textPositions, nil
}

// isTextContainingFile determines if a ZIP file contains text content based on document type.
//
// Matching is case-INSENSITIVE because a zip entry name is producer-controlled data and
// nothing makes the conventional spelling normative. This mirrors the extractor's part
// selection, and it has to: the extractor finds the text, the redactor rewrites it, and
// if only one of them recognizes a part then the tool reports a finding it cannot
// redact. Measured before this change, on a .docx whose body part was named
// word/Document.xml: the SSN and card were detected (4 findings) yet both survived
// --enable-redaction in cleartext inside the rewritten file, because this predicate's
// strings.Contains(fileName, "document") is case-sensitive and never matched. A
// reported-but-unredacted value is the same leak as an undetected one, dressed as a
// success.
func (or *OfficeRedactor) isTextContainingFile(fileName string, docType OfficeDocumentType) bool {
	name := strings.ToLower(fileName)
	if !strings.HasSuffix(name, ".xml") {
		return false
	}

	switch docType {
	case DocumentTypeDOCX:
		// Word: the main document plus the parts that carry user-visible prose.
		// "main" is included alongside "document" because a producer may name the
		// body part word/main.xml; the extractor accepts it, so the redactor must.
		if !strings.HasPrefix(name, "word/") {
			return false
		}
		for _, part := range []string{"document", "main", "header", "footer", "footnote", "endnote", "comment"} {
			if strings.Contains(name, part) {
				return true
			}
		}
		return false

	case DocumentTypeXLSX:
		// Excel: worksheets and the shared string table.
		return strings.HasPrefix(name, "xl/worksheets/") || name == "xl/sharedstrings.xml"

	case DocumentTypePPTX:
		// PowerPoint: slides, layouts, masters.
		return strings.HasPrefix(name, "ppt/slides/") ||
			strings.HasPrefix(name, "ppt/slidelayouts/") ||
			strings.HasPrefix(name, "ppt/slidemasters/")

	default:
		return false
	}
}

// extractTextFromXML extracts text content from an XML file
func (or *OfficeRedactor) extractTextFromXML(fileName string, content []byte, docType OfficeDocumentType, baseOffset int) (string, []OfficeTextPosition, error) {
	var extractedText strings.Builder
	var positions []OfficeTextPosition

	// Parse XML
	decoder := xml.NewDecoder(bytes.NewReader(content))
	var currentPath []string
	var currentElement xml.StartElement
	textOffset := baseOffset

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("XML parsing error: %w", err)
		}

		switch t := token.(type) {
		case xml.StartElement:
			currentPath = append(currentPath, t.Name.Local)
			currentElement = t

		case xml.EndElement:
			if len(currentPath) > 0 {
				currentPath = currentPath[:len(currentPath)-1]
			}

		case xml.CharData:
			text := strings.TrimSpace(string(t))
			if text != "" && or.isTextElement(currentPath, docType) {
				// Create position info
				position := OfficeTextPosition{
					FileName:       fileName,
					XMLPath:        strings.Join(currentPath, "/"),
					DocumentOffset: textOffset,
					Text:           text,
					ElementInfo: OfficeElementInfo{
						ElementName: currentElement.Name.Local,
						Attributes:  or.extractAttributes(currentElement),
						ParentPath:  strings.Join(currentPath[:len(currentPath)-1], "/"),
					},
				}

				positions = append(positions, position)
				extractedText.WriteString(text)
				if extractedText.Len() > textOffset {
					extractedText.WriteString(" ") // Add space between text elements
				}
				textOffset = baseOffset + extractedText.Len()
			}
		}
	}

	return extractedText.String(), positions, nil
}

// isTextElement determines if the current XML path represents a text element
func (or *OfficeRedactor) isTextElement(path []string, docType OfficeDocumentType) bool {
	if len(path) == 0 {
		return false
	}

	lastElement := path[len(path)-1]

	switch docType {
	case DocumentTypeDOCX:
		// Word text elements: w:t (text), w:delText (deleted text)
		return lastElement == "t" || lastElement == "delText"

	case DocumentTypeXLSX:
		// Excel text elements: t (text in shared strings), v (cell value), f (formula)
		return lastElement == "t" || lastElement == "v" || lastElement == "f"

	case DocumentTypePPTX:
		// PowerPoint text elements: a:t (text)
		return lastElement == "t"

	default:
		return false
	}
}

// extractAttributes extracts attributes from an XML start element
func (or *OfficeRedactor) extractAttributes(element xml.StartElement) map[string]string {
	attributes := make(map[string]string)
	for _, attr := range element.Attr {
		attributes[attr.Name.Local] = attr.Value
	}
	return attributes
}

// redactOfficeContent performs redaction on Office document content
func (or *OfficeRedactor) redactOfficeContent(zipContents *OfficeZipContents, extractedText string, textPositions []OfficeTextPosition, matches []detector.Match, strategy redactors.RedactionStrategy, docType OfficeDocumentType) ([]redactors.RedactionMapping, *OfficeZipContents, error) {
	var redactionMap []redactors.RedactionMapping
	modifiedContents := &OfficeZipContents{
		Files: make(map[string][]byte, len(zipContents.Files)),
		Order: make([]string, 0, len(zipContents.Files)),
	}

	// Copy all files initially, walking the recorded order rather than the map
	// so the copy carries the source package's entry order forward.
	for _, fileName := range zipContents.orderedNames() {
		modifiedContents.addFile(fileName, zipContents.Files[fileName])
	}

	// Restore bounded (display-truncated) consolidated match texts to their
	// full-line spans first — redaction locates matches by searching for
	// Match.Text in the extracted content, and a bounded display text does not
	// occur there. See redactors.RestoreBoundedMatchText.
	matches = redactors.RestoreBoundedMatchText(matches)

	// Collapse overlapping matches to their widest span so a smaller match
	// contained in a larger one doesn't get redacted first and hide the larger
	// match's un-redacted head. See redactors.ResolveOverlaps.
	matches = redactors.ResolveOverlaps(matches)

	// Process each match
	for _, match := range matches {
		mapping, err := or.redactMatch(modifiedContents, extractedText, textPositions, match, strategy, docType)
		if err != nil {
			or.logEvent("match_redaction_failed", false, map[string]interface{}{
				"match_type": match.Type,
				"match_line": match.LineNumber,
				"error":      err.Error(),
			})
			continue
		}

		if mapping != nil {
			redactionMap = append(redactionMap, *mapping)
		}
	}

	return redactionMap, modifiedContents, nil
}

// redactMatch redacts a single match in the Office document
func (or *OfficeRedactor) redactMatch(zipContents *OfficeZipContents, extractedText string, textPositions []OfficeTextPosition, match detector.Match, strategy redactors.RedactionStrategy, docType OfficeDocumentType) (*redactors.RedactionMapping, error) {
	// Find the position of the match in the extracted text
	matchPos := strings.Index(extractedText, match.Text)
	if matchPos == -1 {
		return nil, fmt.Errorf("match text not found in extracted content")
	}

	// Find corresponding Office position
	var officePosition *OfficeTextPosition
	for _, pos := range textPositions {
		if pos.DocumentOffset <= matchPos && matchPos < pos.DocumentOffset+len(pos.Text) {
			officePosition = &pos
			break
		}
	}

	if officePosition == nil {
		return nil, fmt.Errorf("could not find Office position for match")
	}

	// Generate replacement text
	replacement, err := or.generateReplacement(match.Text, match.Type, strategy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate replacement: %w", err)
	}

	// Apply redaction to XML content
	err = or.applyXMLRedaction(zipContents, officePosition, match.Text, replacement, docType)
	if err != nil {
		return nil, fmt.Errorf("failed to apply XML redaction: %w", err)
	}

	// Create redaction mapping
	mapping := redactors.RedactionMapping{
		RedactedText: replacement,
		Position: redactors.TextPosition{
			Line:      match.LineNumber,
			StartChar: matchPos,
			EndChar:   matchPos + len(match.Text),
		},
		DataType:   match.Type,
		Strategy:   strategy,
		Confidence: match.Confidence,

		Metadata: map[string]interface{}{
			"office_file":     officePosition.FileName,
			"xml_path":        officePosition.XMLPath,
			"element_info":    officePosition.ElementInfo,
			"document_type":   docType.String(),
			"position_method": "xml_text_extraction",
		},
	}

	or.logEvent("office_redaction_applied", true, map[string]interface{}{
		"match_type":         match.Type,
		"file_name":          officePosition.FileName,
		"replacement_length": len(replacement),
		"confidence":         match.Confidence,
		"document_type":      docType.String(),
	})

	return &mapping, nil
}

// applyXMLRedaction applies redaction to XML content
func (or *OfficeRedactor) applyXMLRedaction(zipContents *OfficeZipContents, position *OfficeTextPosition, originalText, replacement string, docType OfficeDocumentType) error {
	// Get the XML content
	xmlContent, exists := zipContents.Files[position.FileName]
	if !exists {
		return fmt.Errorf("XML file not found: %s", position.FileName)
	}

	// Replace the text in XML content
	// This is a simplified approach - in production, you'd want more sophisticated XML manipulation
	modifiedContent := bytes.ReplaceAll(xmlContent, []byte(originalText), []byte(replacement))

	// Update the ZIP contents. addFile rather than a bare map write so the entry
	// order stays consistent with Files even though this path only ever replaces
	// a part that is already present.
	zipContents.addFile(position.FileName, modifiedContent)

	or.logEvent("xml_content_modified", true, map[string]interface{}{
		"file_name":     position.FileName,
		"original_size": len(xmlContent),
		"modified_size": len(modifiedContent),
		"replacements":  bytes.Count(xmlContent, []byte(originalText)),
	})

	return nil
}

// repackageOfficeDocument repackages the modified ZIP contents into a new Office document
func (or *OfficeRedactor) repackageOfficeDocument(contents *OfficeZipContents, outputPath string) error {
	// Ensure output directory exists
	if or.outputManager != nil {
		if err := or.outputManager.EnsureDirectoryExists(outputPath); err != nil {
			return fmt.Errorf("failed to ensure output directory: %w", err)
		}
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create ZIP writer
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Write all files to ZIP in the order they appeared in the source package.
	// Ranging contents.Files directly here made the redacted document's entry
	// order random per run, which broke byte reproducibility and regularly moved
	// [Content_Types].xml out of the first slot that OPC requires it to occupy.
	for _, fileName := range contents.orderedNames() {
		content := contents.Files[fileName]
		fileWriter, err := zipWriter.Create(fileName)
		if err != nil {
			return fmt.Errorf("failed to create ZIP entry for %s: %w", fileName, err)
		}

		_, err = fileWriter.Write(content)
		if err != nil {
			return fmt.Errorf("failed to write content for %s: %w", fileName, err)
		}
	}

	or.logEvent("office_document_repackaged", true, map[string]interface{}{
		"output_path": outputPath,
		"file_count":  len(contents.Files),
	})

	return nil
}

// generateReplacement generates a replacement string based on the redaction strategy
// generateReplacement delegates to the shared replacement package.
func (or *OfficeRedactor) generateReplacement(originalText, dataType string, strategy redactors.RedactionStrategy) (string, error) {
	return replacement.Generate(originalText, dataType, strategy), nil
}

// calculateOverallConfidence calculates the overall confidence for the redaction
func (or *OfficeRedactor) calculateOverallConfidence(redactionMap []redactors.RedactionMapping) float64 {
	if len(redactionMap) == 0 {
		return 1.0
	}
	total := 0.0
	for _, m := range redactionMap {
		total += m.Confidence
	}
	return total / float64(len(redactionMap))
}

// logEvent logs an event if observer is available
func (or *OfficeRedactor) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if or.observer != nil {
		or.observer.StartTiming("office_redactor", operation, "")(success, metadata)
	}
}

// GetComponentName returns the component name for observability
func (or *OfficeRedactor) GetComponentName() string {
	return "office_redactor"
}

// SetPositionCorrelationEnabled enables or disables position correlation
func (or *OfficeRedactor) SetPositionCorrelationEnabled(enabled bool) {
	or.enablePositionCorrelation = enabled
}

// SetConfidenceThreshold sets the minimum confidence threshold for position-based redaction
func (or *OfficeRedactor) SetConfidenceThreshold(threshold float64) {
	if threshold >= 0.0 && threshold <= 1.0 {
		or.confidenceThreshold = threshold
	}
}

// SetFallbackToSimple controls whether to fall back to simple text replacement on correlation failure
func (or *OfficeRedactor) SetFallbackToSimple(fallback bool) {
	or.fallbackToSimple = fallback
}

// GetPositionCorrelationStats returns statistics about position correlation performance
func (or *OfficeRedactor) GetPositionCorrelationStats() map[string]interface{} {
	return map[string]interface{}{
		"correlation_enabled":  or.enablePositionCorrelation,
		"confidence_threshold": or.confidenceThreshold,
		"fallback_enabled":     or.fallbackToSimple,
		"correlator_type":      fmt.Sprintf("%T", or.positionCorrelator),
	}
}
