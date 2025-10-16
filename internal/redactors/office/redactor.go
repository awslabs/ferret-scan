// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
	"ferret-scan/internal/redactors"
	"ferret-scan/internal/redactors/position"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// OfficeRedactor implements redaction for Microsoft Office documents using unified ZIP/XML approach
type OfficeRedactor struct {
	// observer handles observability and metrics
	observer *observability.StandardObserver

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
func NewOfficeRedactor(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver) *OfficeRedactor {
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

// NewOfficeRedactorWithPositionCorrelation creates a new OfficeRedactor with custom position correlation settings
func NewOfficeRedactorWithPositionCorrelation(outputManager *redactors.OutputStructureManager, observer *observability.StandardObserver, correlator position.PositionCorrelator, confidenceThreshold float64) *OfficeRedactor {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	if correlator == nil {
		correlator = position.NewDefaultPositionCorrelator()
	}

	return &OfficeRedactor{
		observer:                  observer,
		outputManager:             outputManager,
		positionCorrelator:        correlator,
		enablePositionCorrelation: true,
		confidenceThreshold:       confidenceThreshold,
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
		Files: make(map[string][]byte),
	}

	var extractedText strings.Builder
	var textPositions []OfficeTextPosition

	// Extract all files from ZIP
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			or.logEvent("file_extraction_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			or.logEvent("file_read_failed", false, map[string]interface{}{
				"file_name": file.Name,
				"error":     err.Error(),
			})
			continue
		}

		zipContents.Files[file.Name] = content

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

// isTextContainingFile determines if a ZIP file contains text content based on document type
func (or *OfficeRedactor) isTextContainingFile(fileName string, docType OfficeDocumentType) bool {
	switch docType {
	case DocumentTypeDOCX:
		// Word documents: main document, headers, footers, footnotes, etc.
		return strings.HasPrefix(fileName, "word/") && strings.HasSuffix(fileName, ".xml") &&
			(strings.Contains(fileName, "document") || strings.Contains(fileName, "header") ||
				strings.Contains(fileName, "footer") || strings.Contains(fileName, "footnote") ||
				strings.Contains(fileName, "endnote") || strings.Contains(fileName, "comment"))

	case DocumentTypeXLSX:
		// Excel documents: worksheets and shared strings
		return (strings.HasPrefix(fileName, "xl/worksheets/") && strings.HasSuffix(fileName, ".xml")) ||
			fileName == "xl/sharedStrings.xml"

	case DocumentTypePPTX:
		// PowerPoint documents: slides, slide layouts, slide masters
		return (strings.HasPrefix(fileName, "ppt/slides/") && strings.HasSuffix(fileName, ".xml")) ||
			(strings.HasPrefix(fileName, "ppt/slideLayouts/") && strings.HasSuffix(fileName, ".xml")) ||
			(strings.HasPrefix(fileName, "ppt/slideMasters/") && strings.HasSuffix(fileName, ".xml"))

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
		Files: make(map[string][]byte),
	}

	// Copy all files initially
	for fileName, content := range zipContents.Files {
		modifiedContents.Files[fileName] = content
	}

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

	// Update the ZIP contents
	zipContents.Files[position.FileName] = modifiedContent

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

	// Write all files to ZIP
	for fileName, content := range contents.Files {
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
func (or *OfficeRedactor) generateReplacement(originalText, dataType string, strategy redactors.RedactionStrategy) (string, error) {
	switch strategy {
	case redactors.RedactionSimple:
		return or.generateSimpleReplacement(dataType), nil

	case redactors.RedactionFormatPreserving:
		return or.generateFormatPreservingReplacement(originalText, dataType), nil

	case redactors.RedactionSynthetic:
		return or.generateSyntheticReplacement(originalText, dataType)

	default:
		return or.generateSimpleReplacement(dataType), nil
	}
}

// generateSimpleReplacement creates a simple placeholder replacement
func (or *OfficeRedactor) generateSimpleReplacement(dataType string) string {
	switch dataType {
	case "CREDIT_CARD":
		return "[CREDIT-CARD-REDACTED]"
	case "SSN":
		return "[SSN-REDACTED]"
	case "EMAIL":
		return "[EMAIL-REDACTED]"
	case "PHONE":
		return "[PHONE-REDACTED]"
	case "SECRETS":
		return "[SECRET-REDACTED]"
	case "IP_ADDRESS":
		return "[IP-ADDRESS-REDACTED]"
	case "PASSPORT":
		return "[PASSPORT-REDACTED]"
	default:
		return "[" + dataType + "-REDACTED]"
	}
}

// generateFormatPreservingReplacement creates a replacement that preserves the original format
func (or *OfficeRedactor) generateFormatPreservingReplacement(originalText, dataType string) string {
	// Use similar logic as other redactors for consistency
	switch dataType {
	case "CREDIT_CARD":
		return or.preserveCreditCardFormat(originalText)
	case "SSN":
		return or.preserveSSNFormat(originalText)
	case "EMAIL":
		return or.preserveEmailFormat(originalText)
	case "PHONE":
		return or.preservePhoneFormat(originalText)
	case "IP_ADDRESS":
		return or.preserveIPFormat(originalText)
	default:
		// For unknown types, replace with asterisks of same length
		return strings.Repeat("*", len(originalText))
	}
}

// generateSyntheticReplacement creates realistic but fake data
func (or *OfficeRedactor) generateSyntheticReplacement(originalText, dataType string) (string, error) {
	// Use similar logic as other redactors for consistency
	switch dataType {
	case "CREDIT_CARD":
		return or.generateSyntheticCreditCard(originalText)
	case "SSN":
		return or.generateSyntheticSSN(originalText)
	case "EMAIL":
		return or.generateSyntheticEmail(originalText)
	case "PHONE":
		return or.generateSyntheticPhone(originalText)
	case "IP_ADDRESS":
		return or.generateSyntheticIP(originalText)
	default:
		// For unknown types, generate random alphanumeric string of same length
		return or.generateRandomString(len(originalText))
	}
}

// Helper methods for format preservation and synthetic data generation
// (Proper implementations matching PlainText redactor behavior)

func (or *OfficeRedactor) preserveCreditCardFormat(original string) string {
	// Preserve first 4 and last 4 digits, mask the middle
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 8 {
		return strings.Repeat("*", len(original))
	}

	first4 := cleaned[:4]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-8)

	// Preserve original formatting
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digits := first4 + middle + last4
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(digits) {
			replacement := string(digits[digitIndex])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

func (or *OfficeRedactor) preserveSSNFormat(original string) string {
	// Pattern: ***-**-1234 (preserve last 4 digits)
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 4 {
		return strings.Repeat("*", len(original))
	}

	last4 := cleaned[len(cleaned)-4:]

	// Replace digits with pattern, preserving last 4
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(cleaned)-4 {
			digitIndex++
			return "*"
		}
		if digitIndex < len(cleaned) {
			replacement := string(last4[digitIndex-(len(cleaned)-4)])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

func (or *OfficeRedactor) preserveEmailFormat(original string) string {
	// Pattern: u***@example.com (preserve first char and domain)
	parts := strings.Split(original, "@")
	if len(parts) != 2 {
		return strings.Repeat("*", len(original))
	}

	username := parts[0]
	domain := parts[1]

	if len(username) == 0 {
		return "*@" + domain
	}

	if len(username) == 1 {
		return username + "@" + domain
	}

	maskedUsername := string(username[0]) + strings.Repeat("*", len(username)-1)
	return maskedUsername + "@" + domain
}

func (or *OfficeRedactor) preservePhoneFormat(original string) string {
	// Preserve format but mask middle digits
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")
	if len(cleaned) < 6 {
		return strings.Repeat("*", len(original))
	}

	// Keep first 3 and last 4, mask middle
	first3 := cleaned[:3]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-7)

	maskedDigits := first3 + middle + last4

	// Apply to original format
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(maskedDigits) {
			replacement := string(maskedDigits[digitIndex])
			digitIndex++
			return replacement
		}
		return "*"
	})

	return result
}

func (or *OfficeRedactor) preserveIPFormat(original string) string {
	// Pattern: 192.168.*.*
	parts := strings.Split(original, ".")
	if len(parts) != 4 {
		return strings.Repeat("*", len(original))
	}

	// Keep first two octets, mask last two
	return parts[0] + "." + parts[1] + ".*.*"
}

func (or *OfficeRedactor) generateSyntheticCreditCard(original string) (string, error) {
	// Generate a valid Luhn number that looks real but isn't
	// Use test card prefixes that are known to be invalid
	testPrefixes := []string{"4000", "4111", "5555", "3782"}

	prefix := testPrefixes[or.secureRandom(len(testPrefixes))]

	// Generate remaining digits
	var digits []int
	for _, char := range prefix {
		if char >= '0' && char <= '9' {
			digits = append(digits, int(char-'0'))
		}
	}

	// Add random digits to make 15 digits total (16th will be check digit)
	for len(digits) < 15 {
		digits = append(digits, or.secureRandom(10))
	}

	// Calculate Luhn check digit
	checkDigit := or.calculateLuhnCheckDigit(digits)
	digits = append(digits, checkDigit)

	// Convert to string with original formatting
	result := ""
	digitIndex := 0
	for _, char := range original {
		if char >= '0' && char <= '9' {
			if digitIndex < len(digits) {
				result += fmt.Sprintf("%d", digits[digitIndex])
				digitIndex++
			} else {
				result += "0"
			}
		} else {
			result += string(char)
		}
	}

	return result, nil
}

func (or *OfficeRedactor) generateSyntheticSSN(original string) (string, error) {
	// Generate a synthetic SSN that follows format but is invalid
	// Use area numbers that are known to be invalid (000, 666, 900-999)
	invalidAreas := []string{"000", "666", "900", "999"}
	area := invalidAreas[or.secureRandom(len(invalidAreas))]

	group := fmt.Sprintf("%02d", or.secureRandom(100))
	serial := fmt.Sprintf("%04d", or.secureRandom(10000))

	syntheticSSN := area + group + serial

	// Apply original formatting
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(syntheticSSN) {
			replacement := string(syntheticSSN[digitIndex])
			digitIndex++
			return replacement
		}
		return "0"
	})

	return result, nil
}

func (or *OfficeRedactor) generateSyntheticEmail(original string) (string, error) {
	// Generate a synthetic email with example.com domain
	parts := strings.Split(original, "@")
	if len(parts) != 2 {
		return "user@example.com", nil
	}

	// Generate random username
	username, err := or.generateRandomString(len(parts[0]))
	if err != nil {
		return "", err
	}

	return strings.ToLower(username) + "@example.com", nil
}

func (or *OfficeRedactor) generateSyntheticPhone(original string) (string, error) {
	// Generate synthetic phone with 555 area code (reserved for fiction)
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(original, "")

	syntheticDigits := "555"
	for len(syntheticDigits) < len(cleaned) {
		syntheticDigits += fmt.Sprintf("%d", or.secureRandom(10))
	}

	// Apply to original format
	result := original
	digitPattern := regexp.MustCompile(`\d`)
	digitIndex := 0

	result = digitPattern.ReplaceAllStringFunc(result, func(match string) string {
		if digitIndex < len(syntheticDigits) {
			replacement := string(syntheticDigits[digitIndex])
			digitIndex++
			return replacement
		}
		return "0"
	})

	return result, nil
}

func (or *OfficeRedactor) generateSyntheticIP(original string) (string, error) {
	// Generate IP in private range (192.168.x.x)
	return fmt.Sprintf("192.168.%d.%d",
		or.secureRandom(256),
		or.secureRandom(256)), nil
}

func (or *OfficeRedactor) generateRandomString(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)

	for i := range result {
		result[i] = charset[or.secureRandom(len(charset))]
	}

	return string(result), nil
}

// secureRandom generates a cryptographically secure random number
func (or *OfficeRedactor) secureRandom(max int) int {
	if max <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		// Fallback to a simple approach if crypto/rand fails
		return int(time.Now().UnixNano()) % max
	}

	return int(n.Int64())
}

// calculateLuhnCheckDigit calculates the Luhn check digit for a credit card number
func (or *OfficeRedactor) calculateLuhnCheckDigit(digits []int) int {
	sum := 0
	alternate := true

	// Process digits from right to left
	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return (10 - (sum % 10)) % 10
}

// generateVerificationHash creates a hash of surrounding context for verification
func (or *OfficeRedactor) generateVerificationHash(text string, startPos, endPos int) string {
	// Validate input parameters
	if startPos < 0 || endPos > len(text) || startPos >= endPos {
		return redactors.GenerateContextHash("invalid_position")
	}

	// Extract context around the match
	contextStart := startPos - 20
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := endPos + 20
	if contextEnd > len(text) {
		contextEnd = len(text)
	}

	// Additional safety check
	if contextStart > len(text) || contextEnd < 0 || contextStart >= contextEnd {
		return redactors.GenerateContextHash("invalid_context")
	}

	context := text[contextStart:startPos] + "[REDACTED]" + text[endPos:contextEnd]
	return redactors.GenerateContextHash(context)
}

// calculateOverallConfidence calculates the overall confidence for the redaction
func (or *OfficeRedactor) calculateOverallConfidence(redactionMap []redactors.RedactionMapping) float64 {
	if len(redactionMap) == 0 {
		return 1.0
	}

	totalConfidence := 0.0
	for _, mapping := range redactionMap {
		totalConfidence += mapping.Confidence
	}

	return totalConfidence / float64(len(redactionMap))
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
