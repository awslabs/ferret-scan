// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Security constants
const (
	MaxFileSize     = 100 * 1024 * 1024 // 100MB max file size
	MaxXMLSize      = 10 * 1024 * 1024  // 10MB max XML content
	XMLParseTimeout = 30 * time.Second  // 30 second timeout for XML parsing
)

// Global replacer for efficient error sanitization (initialized once)
var errorSanitizer = strings.NewReplacer(
	"\n", " ",
	"\r", " ",
	"\t", " ",
	"\x00", " ",
	"\x1b", " ", // ESC character
)

// sanitizeErrorForLogging sanitizes error messages to prevent log injection attacks
func sanitizeErrorForLogging(err error) string {
	if err == nil {
		return ""
	}
	// Use pre-initialized replacer for efficient single-pass replacement
	return errorSanitizer.Replace(err.Error())
}

// SanitizedError wraps an error with a sanitized message for safe logging
type SanitizedError struct {
	original error
	message  string
}

func (e *SanitizedError) Error() string {
	return e.message
}

func (e *SanitizedError) Unwrap() error {
	return e.original
}

// newSanitizedError creates a new error with sanitized message while preserving the original error chain
func newSanitizedError(prefix string, err error) error {
	return &SanitizedError{
		original: err,
		message:  prefix + ": " + sanitizeErrorForLogging(err),
	}
}

// Metadata represents document metadata
type Metadata struct {
	Filename       string
	FileSize       int64
	ModTime        time.Time
	MimeType       string
	Title          string
	Creator        string
	Author         string
	Description    string
	LastModifiedBy string
	Created        time.Time
	Modified       time.Time
	Application    string
	AppVersion     string
	Company        string
	Category       string
	Keywords       string
	Subject        string
	Manager        string
	Comments       string
	ContentStatus  string
	Identifier     string
	Language       string
	Revision       string
	PageCount      int
	WordCount      int
	CharCount      int
	Properties     map[string]string
	EmbeddedImages []string // EXIF data from embedded images
	// High-risk metadata fields
	Template          string
	CustomProps       map[string]string
	HiddenSlides      int
	TotalEditTime     string
	HyperlinksChanged bool
	SharedDocument    bool
}

// validateFilePath validates file path to prevent directory traversal attacks
func validateFilePath(filePath string) error {
	// Clean the path and check for traversal attempts
	cleanPath := filepath.Clean(filePath)

	// Check for path traversal patterns
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("path traversal attempt detected in: %s", filePath)
	}

	// Check for suspicious absolute paths (system directories)
	suspiciousPaths := []string{
		"/etc/", "/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/",
		"/root/", "/home/", "/var/", "/tmp/", "/sys/", "/proc/",
		"C:\\Windows\\", "C:\\Program Files\\", "C:\\Users\\",
		"\\Windows\\", "\\Program Files\\", "\\Users\\",
	}

	cleanPathLower := strings.ToLower(cleanPath)
	for _, suspiciousPath := range suspiciousPaths {
		if strings.HasPrefix(cleanPathLower, strings.ToLower(suspiciousPath)) {
			return fmt.Errorf("access to system directory denied: %s", filePath)
		}
	}

	// Check for URL schemes that might be used for attacks
	if strings.Contains(filePath, "://") {
		return fmt.Errorf("URL schemes not allowed in file paths: %s", filePath)
	}

	return nil
}

// validateFileSize validates file size to prevent DoS attacks
func validateFileSize(fileInfo os.FileInfo) error {
	if fileInfo.Size() > MaxFileSize {
		return fmt.Errorf("file too large: %d bytes (max: %d)", fileInfo.Size(), MaxFileSize)
	}
	if fileInfo.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	return nil
}

// secureXMLUnmarshal safely unmarshals XML with XXE protection
func secureXMLUnmarshal(data []byte, v any) error {
	if len(data) > MaxXMLSize {
		return fmt.Errorf("XML content too large: %d bytes (max: %d)", len(data), MaxXMLSize)
	}

	// Validate XML content is not empty
	if len(data) == 0 {
		return fmt.Errorf("XML content is empty")
	}

	// Basic XML structure validation (must start with '<')
	if data[0] != '<' {
		return fmt.Errorf("invalid XML content: does not start with '<'")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), XMLParseTimeout)
	defer cancel()

	// Create secure XML decoder
	decoder := xml.NewDecoder(bytes.NewReader(data))

	// Disable external entity processing to prevent XXE attacks
	decoder.Strict = false
	decoder.Entity = xml.HTMLEntity

	// Parse with timeout protection
	done := make(chan error, 1)
	go func() {
		done <- decoder.Decode(v)
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("XML parsing timeout exceeded")
	}
}

// ExtractMetadata extracts metadata from an Office document
func ExtractMetadata(filePath string) (*Metadata, error) {
	// Validate file path for security
	if err := validateFilePath(filePath); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	// Check if file exists
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, newSanitizedError("file error", err)
	}

	// Validate file size for security
	if err := validateFileSize(fileInfo); err != nil {
		return nil, fmt.Errorf("file size validation failed: %w", err)
	}

	// Initialize metadata with basic file info
	metadata := &Metadata{
		Filename:   filepath.Base(filePath),
		FileSize:   fileInfo.Size(),
		ModTime:    fileInfo.ModTime(),
		Properties: make(map[string]string),
	}

	// Determine file type based on extension
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".docx":
		metadata.MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	case ".xlsx":
		metadata.MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	case ".pptx":
		metadata.MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	case ".doc":
		metadata.MimeType = "application/msword"
		return metadata, fmt.Errorf("legacy Office formats (.doc, .xls, .ppt) not supported")
	case ".xls":
		metadata.MimeType = "application/vnd.ms-excel"
		return metadata, fmt.Errorf("legacy Office formats (.doc, .xls, .ppt) not supported")
	case ".ppt":
		metadata.MimeType = "application/vnd.ms-powerpoint"
		return metadata, fmt.Errorf("legacy Office formats (.doc, .xls, .ppt) not supported")
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}
}

// extractOfficeOpenXMLMetadata extracts metadata from Office Open XML documents
func extractOfficeOpenXMLMetadata(filePath string, metadata *Metadata) (*Metadata, error) {
	// Open the file as a ZIP archive
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return metadata, newSanitizedError("error opening file as ZIP", err)
	}
	defer reader.Close()

	// Create file index for efficient lookup
	fileIndex := createFileIndex(reader)

	// Extract core properties
	if coreProps, err := extractCorePropertiesOptimized(fileIndex); err == nil {
		metadata.Title = coreProps.Title
		metadata.Creator = coreProps.Creator
		metadata.Author = coreProps.Creator // Alias for Creator
		metadata.Description = coreProps.Description
		metadata.LastModifiedBy = coreProps.LastModifiedBy
		metadata.Subject = coreProps.Subject
		metadata.Keywords = strings.Join(coreProps.Keywords, ", ")
		metadata.Category = coreProps.Category
		metadata.Manager = coreProps.Manager
		metadata.Comments = coreProps.Comments
		metadata.ContentStatus = coreProps.ContentStatus
		metadata.Identifier = coreProps.Identifier
		metadata.Language = coreProps.Language
		metadata.Revision = coreProps.Revision

		// Parse dates
		if coreProps.Created != "" {
			if t, parseErr := parseOfficeDate(coreProps.Created); parseErr == nil {
				metadata.Created = t
			}
		}

		if coreProps.Modified != "" {
			if t, parseErr := parseOfficeDate(coreProps.Modified); parseErr == nil {
				metadata.Modified = t
			}
		}
	}

	// Extract app properties
	if appProps, err := extractAppPropertiesOptimized(fileIndex); err == nil {
		metadata.Application = appProps.Application
		metadata.AppVersion = appProps.AppVersion
		metadata.Company = appProps.Company
		metadata.Template = appProps.Template
		metadata.TotalEditTime = appProps.TotalTime

		// Extract counts with error handling using helper function
		parseIntField := func(value string, fieldName string, target *int) {
			if value != "" {
				if _, err := fmt.Sscanf(value, "%d", target); err != nil {
					metadata.Properties[fieldName+"ParseError"] = sanitizeErrorForLogging(err)
				}
			}
		}

		parseIntField(appProps.Pages, "PageCount", &metadata.PageCount)
		parseIntField(appProps.Words, "WordCount", &metadata.WordCount)
		parseIntField(appProps.Characters, "CharCount", &metadata.CharCount)
		parseIntField(appProps.HiddenSlides, "HiddenSlides", &metadata.HiddenSlides)

		// Parse boolean flags
		metadata.HyperlinksChanged = strings.ToLower(appProps.HyperlinksChanged) == "true"
		metadata.SharedDocument = strings.ToLower(appProps.SharedDoc) == "true"

		// Store high-risk properties in Properties map for easy access
		if metadata.Template != "" {
			metadata.Properties["Template"] = metadata.Template
		}
		if appProps.Manager != "" {
			metadata.Properties["Manager"] = appProps.Manager
		}
		if appProps.MMClips != "" {
			metadata.Properties["MultimediaClips"] = appProps.MMClips
		}
		if appProps.ScaleCrop != "" {
			metadata.Properties["ScaleCrop"] = appProps.ScaleCrop
		}
	}

	// Extract custom properties (HIGH RISK)
	if customProps, err := extractCustomPropertiesOptimized(fileIndex); err == nil && len(customProps) > 0 {
		metadata.CustomProps = customProps
		// Also store in Properties map with "Custom_" prefix for easy scanning
		for key, value := range customProps {
			metadata.Properties["Custom_"+key] = value
		}
	}

	// Extract document-specific metadata
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".docx":
		extractWordMetadata(reader, metadata)
	case ".xlsx":
		extractExcelMetadata(reader, metadata)
	case ".pptx":
		extractPowerPointMetadata(reader, metadata)
	}

	// Extract embedded images
	if err := extractEmbeddedImages(reader, metadata); err != nil {
		// Log error but don't fail the entire extraction
		metadata.Properties["ImageExtractionError"] = err.Error()
	}

	return metadata, nil
}

// CoreProperties represents Office document core properties
type CoreProperties struct {
	Title          string   `xml:"title"`
	Subject        string   `xml:"subject"`
	Creator        string   `xml:"creator"`
	Keywords       []string `xml:"keywords"`
	Description    string   `xml:"description"`
	LastModifiedBy string   `xml:"lastModifiedBy"`
	Revision       string   `xml:"revision"`
	Created        string   `xml:"created"`
	Modified       string   `xml:"modified"`
	Category       string   `xml:"category"`
	Manager        string   `xml:"manager"`
	Comments       string   `xml:"comments"`
	ContentStatus  string   `xml:"contentStatus"`
	Identifier     string   `xml:"identifier"`
	Language       string   `xml:"language"`
}

// AppProperties represents Office document app properties
type AppProperties struct {
	Application        string `xml:"Application"`
	AppVersion         string `xml:"AppVersion"`
	Company            string `xml:"Company"`
	Pages              string `xml:"Pages"`
	Words              string `xml:"Words"`
	Characters         string `xml:"Characters"`
	Lines              string `xml:"Lines"`
	Paragraphs         string `xml:"Paragraphs"`
	Slides             string `xml:"Slides"`
	Notes              string `xml:"Notes"`
	Template           string `xml:"Template"`
	TotalTime          string `xml:"TotalTime"`
	HiddenSlides       string `xml:"HiddenSlides"`
	MMClips            string `xml:"MMClips"`
	ScaleCrop          string `xml:"ScaleCrop"`
	SharedDoc          string `xml:"SharedDoc"`
	HyperlinksChanged  string `xml:"HyperlinksChanged"`
	Manager            string `xml:"Manager"`
	PresentationFormat string `xml:"PresentationFormat"`
}

// CustomProperty represents a custom document property
type CustomProperty struct {
	Name  string `xml:"name,attr"`
	Fmtid string `xml:"fmtid,attr"`
	Pid   string `xml:"pid,attr"`
	Value string `xml:",innerxml"`
}

// CustomProperties represents the custom properties collection
type CustomProperties struct {
	Properties []CustomProperty `xml:"property"`
}

// createFileIndex creates an index of files for efficient lookup
func createFileIndex(reader *zip.ReadCloser) map[string]*zip.File {
	// Pre-allocate map with capacity to reduce rehashing
	fileIndex := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		fileIndex[file.Name] = file
	}
	return fileIndex
}

// extractCorePropertiesOptimized extracts core properties using file index
func extractCorePropertiesOptimized(fileIndex map[string]*zip.File) (*CoreProperties, error) {
	corePropsFile, exists := fileIndex["docProps/core.xml"]
	if !exists {
		return nil, fmt.Errorf("core properties file not found")
	}

	return extractCorePropertiesFromFile(corePropsFile)
}

// extractCorePropertiesFromFile extracts core properties from a specific file
func extractCorePropertiesFromFile(corePropsFile *zip.File) (*CoreProperties, error) {

	// Open the core properties file
	rc, err := corePropsFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Read the content with size limit
	content, err := io.ReadAll(io.LimitReader(rc, MaxXMLSize))
	if err != nil {
		return nil, newSanitizedError("failed to read core properties", err)
	}

	// Parse XML securely
	var coreProps CoreProperties
	err = secureXMLUnmarshal(content, &coreProps)
	if err != nil {
		return nil, newSanitizedError("failed to parse core properties XML", err)
	}

	return &coreProps, nil
}

// extractAppPropertiesOptimized extracts app properties using file index
func extractAppPropertiesOptimized(fileIndex map[string]*zip.File) (*AppProperties, error) {
	appPropsFile, exists := fileIndex["docProps/app.xml"]
	if !exists {
		return nil, fmt.Errorf("app properties file not found")
	}

	return extractAppPropertiesFromFile(appPropsFile)
}

// extractAppPropertiesFromFile extracts app properties from a specific file
func extractAppPropertiesFromFile(appPropsFile *zip.File) (*AppProperties, error) {

	// Open the app properties file
	rc, err := appPropsFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Read the content with size limit
	content, err := io.ReadAll(io.LimitReader(rc, MaxXMLSize))
	if err != nil {
		return nil, newSanitizedError("failed to read app properties", err)
	}

	// Parse XML securely
	var appProps AppProperties
	err = secureXMLUnmarshal(content, &appProps)
	if err != nil {
		return nil, newSanitizedError("failed to parse app properties XML", err)
	}

	return &appProps, nil
}

// extractCustomPropertiesOptimized extracts custom properties using file index
func extractCustomPropertiesOptimized(fileIndex map[string]*zip.File) (map[string]string, error) {
	customPropsFile, exists := fileIndex["docProps/custom.xml"]
	if !exists {
		return nil, fmt.Errorf("custom properties file not found")
	}

	return extractCustomPropertiesFromFile(customPropsFile)
}

// extractCustomPropertiesFromFile extracts custom properties from a specific file
func extractCustomPropertiesFromFile(customPropsFile *zip.File) (map[string]string, error) {

	// Open the custom properties file
	rc, err := customPropsFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// Read the content with size limit
	content, err := io.ReadAll(io.LimitReader(rc, MaxXMLSize))
	if err != nil {
		return nil, newSanitizedError("failed to read custom properties", err)
	}

	// Parse XML securely - custom properties have a more complex structure
	var customProps CustomProperties
	err = secureXMLUnmarshal(content, &customProps)
	if err != nil {
		return nil, newSanitizedError("failed to parse custom properties XML", err)
	}

	// Extract property values
	result := make(map[string]string)
	for _, prop := range customProps.Properties {
		// Extract the actual value from the inner XML
		value := extractCustomPropertyValue(prop.Value)
		if value != "" {
			result[prop.Name] = value
		}
	}

	return result, nil
}

// Compiled regex for better performance and security
var (
	xmlContentRegex = regexp.MustCompile(`>([^<]+)<`)
)

// extractCustomPropertyValue extracts the actual value from custom property XML
func extractCustomPropertyValue(innerXML string) string {
	// Limit input size to prevent ReDoS attacks
	if len(innerXML) > 1000 {
		innerXML = innerXML[:1000]
	}

	// Early return for empty input
	if len(innerXML) == 0 {
		return ""
	}

	// Custom properties can have different value types: lpwstr, i4, bool, filetime, etc.
	// We'll extract the text content regardless of type

	// Remove XML tags and get the text content (optimized with single pass)
	start := strings.Index(innerXML, ">")
	if start == -1 {
		return ""
	}

	end := strings.LastIndex(innerXML, "<")
	if end <= start {
		return ""
	}

	// Extract and trim in one operation
	content := innerXML[start+1 : end]
	if len(content) == 0 {
		return ""
	}

	return strings.TrimSpace(content)
}

// extractWordMetadata extracts Word-specific metadata
func extractWordMetadata(_ *zip.ReadCloser, metadata *Metadata) {
	// Add Word-specific metadata extraction here if needed
	metadata.Properties["DocumentType"] = "Word Document"
}

// extractExcelMetadata extracts Excel-specific metadata
func extractExcelMetadata(reader *zip.ReadCloser, metadata *Metadata) {
	metadata.Properties["DocumentType"] = "Excel Spreadsheet"

	// Count worksheets
	worksheetCount := 0
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			worksheetCount++
		}
	}
	metadata.Properties["WorksheetCount"] = fmt.Sprintf("%d", worksheetCount)
}

// extractPowerPointMetadata extracts PowerPoint-specific metadata
func extractPowerPointMetadata(reader *zip.ReadCloser, metadata *Metadata) {
	metadata.Properties["DocumentType"] = "PowerPoint Presentation"

	// Count slides
	slideCount := 0
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "ppt/slides/slide") && strings.HasSuffix(file.Name, ".xml") {
			slideCount++
		}
	}
	metadata.PageCount = slideCount // Set slide count as page count
	metadata.Properties["SlideCount"] = fmt.Sprintf("%d", slideCount)
}

// parseOfficeDate parses Office date format
func parseOfficeDate(dateStr string) (time.Time, error) {
	// Office dates can have different formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05-07:00",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("could not parse date: %s", dateStr)
}

// EmbeddedMedia represents extracted media files that need further processing
type EmbeddedMedia struct {
	TempFilePath string
	OriginalName string
	MediaType    string // "image", "audio", etc.
}

// extractEmbeddedImages extracts embedded media files for further processing
func extractEmbeddedImages(reader *zip.ReadCloser, metadata *Metadata) error {
	var tempFiles []string
	var embeddedMedia []EmbeddedMedia

	defer func() {
		// Clean up temp files
		for _, tempFile := range tempFiles {
			os.Remove(tempFile)
		}
	}()

	for _, file := range reader.File {
		// Check for media files in media folders
		if !strings.Contains(file.Name, "/media/") {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name))
		mediaType := ""

		// Determine media type
		switch ext {
		case ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".gif", ".bmp", ".webp":
			mediaType = "image"
		case ".mp3", ".wav", ".m4a", ".flac":
			mediaType = "audio"
		default:
			continue // Skip unsupported media types
		}

		// Extract media to temp file
		tempFile, err := extractImageToTemp(file)
		if err != nil {
			continue
		}
		tempFiles = append(tempFiles, tempFile)

		embeddedMedia = append(embeddedMedia, EmbeddedMedia{
			TempFilePath: tempFile,
			OriginalName: file.Name,
			MediaType:    mediaType,
		})
	}

	// Store embedded media info for external processing
	// This will be handled by the metadata preprocessor
	if len(embeddedMedia) > 0 {
		metadata.Properties["EmbeddedMediaCount"] = fmt.Sprintf("%d", len(embeddedMedia))
		for i, media := range embeddedMedia {
			metadata.Properties[fmt.Sprintf("EmbeddedMedia_%d_Type", i)] = media.MediaType
			metadata.Properties[fmt.Sprintf("EmbeddedMedia_%d_Name", i)] = media.OriginalName
		}
	}

	return nil
}

// extractImageToTemp extracts an image from ZIP to a temporary file
func extractImageToTemp(file *zip.File) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	// Create temp file
	tempFile, err := os.CreateTemp("", "office_image_*"+filepath.Ext(file.Name))
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Copy image data
	_, err = io.Copy(tempFile, rc)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

// ExtractEmbeddedMediaForProcessing extracts embedded media and returns temp file paths for full processing
func ExtractEmbeddedMediaForProcessing(filePath string) ([]EmbeddedMedia, error) {
	// Open the file as a ZIP archive
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file as ZIP: %v", err)
	}
	defer reader.Close()

	var embeddedMedia []EmbeddedMedia

	for _, file := range reader.File {
		// Check for media files in media folders
		if !strings.Contains(file.Name, "/media/") {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name))
		mediaType := ""

		// Determine media type
		switch ext {
		case ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".gif", ".bmp", ".webp":
			mediaType = "image"
		case ".mp3", ".wav", ".m4a", ".flac":
			mediaType = "audio"
		default:
			continue // Skip unsupported media types
		}

		// Extract media to temp file
		tempFile, err := extractImageToTemp(file)
		if err != nil {
			continue
		}

		embeddedMedia = append(embeddedMedia, EmbeddedMedia{
			TempFilePath: tempFile,
			OriginalName: file.Name,
			MediaType:    mediaType,
		})
	}

	return embeddedMedia, nil
}

// CleanupEmbeddedMedia removes temporary files
func CleanupEmbeddedMedia(media []EmbeddedMedia) {
	for _, m := range media {
		os.Remove(m.TempFilePath)
	}
}
