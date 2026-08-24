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

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// Security constants
const (
	MaxFileSize     = 100 * 1024 * 1024 // 100MB max file size
	MaxXMLSize      = 10 * 1024 * 1024  // 10MB max XML content
	XMLParseTimeout = 30 * time.Second  // 30 second timeout for XML parsing
	// MaxEmbeddedMediaSize bounds a single embedded media file extracted to a
	// temp file. Without it, extractImageToTemp did an unbounded io.Copy, so a
	// small .docx/.xlsx/.pptx with a media entry that deflates to many GB could
	// exhaust the temp filesystem (security finding MED-3). The XML readers in
	// this file already cap at MaxXMLSize; media is larger but still bounded.
	MaxEmbeddedMediaSize = 50 * 1024 * 1024 // 50MB max per embedded media file
	// maxEmbeddedNotes bounds how many individually-named refusals one container can put
	// into its disclosure, because that text goes on ONE line of stderr and into every
	// machine format.
	//
	// The part count is attacker-controlled and cheap: a 6 MB .docx holding 120 entries
	// that each deflate from 50 MB of zeros produced a single 16.8 KB warning line,
	// measured, and the shape scales linearly with entries a container can declare. A
	// report an operator cannot read is a report they will not read.
	//
	// The count is never lost — what is dropped is the NAMES beyond this many, and the note
	// that replaces them says how many. A cap that truncates silently would be the same
	// class of defect as the silent skip this disclosure exists to fix.
	maxEmbeddedNotes = 8
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

// validateFilePath rejects paths this extractor must not open.
//
// It used to refuse any path under a list of "system directories" that included
// /home/, /var/ and /tmp/. That denylist protected nothing and broke the tool's
// primary use case: on Linux EVERY file a user owns is under /home/, so
// `ferret-scan --file ~/report.docx` silently lost Office metadata extraction — no
// error surfaced, the file simply dropped to a single preprocessor and its author,
// company and custom properties were never scanned. Measured on one .docx: an
// allowed path yields {SSN, PERSON_NAME, AUTHOR_INFO}, a /tmp path yields {SSN}
// alone. Since only reported findings are redacted, that was a cleartext leak of
// every metadata field, on the default path, for a whole platform. It also made the
// repository unusable as a fixture location on GitHub's Linux runners, which check
// out under /home/runner/work.
//
// The denylist was never a control. This function is not a trust boundary: the path
// arrives from the CLI, which has already resolved and stat'd it, and the tool's
// entire purpose is to read files the invoking user named and can already read. A
// prefix denylist over such a path stops nothing — a symlink, a relative path or a
// bind mount reaches the same bytes — and per BSC1 input-validation guidance a
// denylist is incomplete by construction.
//
// A first attempt at replacing it kept a smaller denylist for the kernel
// pseudo-filesystems (/proc/, /sys/, /dev/). That reproduced the same class of bug
// one directory down: /dev/shm is world-writable tmpfs that scripts and CI use for
// ordinary temporary files, and those are ordinary regular files, so a .docx there
// was refused for no reason. It was also Unix-only — the Windows device namespace
// (\\.\PhysicalDrive0) and reserved DOS names (CON, NUL, COM1) all passed straight
// through, so on one of three supported platforms it read as protection while
// providing none.
//
// The real concern behind it — do not try to read something that has no size and
// may never end — is a property of the file's MODE, not of its name, so it now
// lives in the router's CanProcessFile as an os.FileMode().IsRegular() check. That
// covers devices, FIFOs and sockets on every platform, with no list to maintain and
// no false positive on /dev/shm, and it applies to all seven extractors rather than
// only to this one, which was the sole extractor that ever carried a path denylist.
//
// What remains here is cheap defence in depth for a path that reaches this package
// by some route other than the router:
//   - a LEADING "..", which after filepath.Clean is the only form a real traversal
//     can survive in. The previous strings.Contains check also rejected legitimate
//     names like "my..report.docx" and any directory whose name contains two dots.
//   - "://", so a URL mistaken for a path fails with a clear message instead of
//     being read as a bizarre relative filename.
//
// The bounds that actually matter for hostile input are elsewhere and unchanged: the
// 100MB size gate (validateFileSize), the per-entry decompression cap, and
// XXE-disabled XML parsing.
func validateFilePath(filePath string) error {
	cleanPath := filepath.Clean(filePath)

	// Reject escaping the working directory. Post-Clean, an interior ".." has been
	// resolved away, so only a leading one is a traversal.
	if cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) ||
		strings.HasPrefix(filepath.ToSlash(cleanPath), "../") {
		return fmt.Errorf("path traversal attempt detected in: %s", filePath)
	}

	// Checked on the RAW path, not the cleaned one: filepath.Clean collapses the
	// double slash, so "https://host/x" becomes "https:/host/x" and the "://" marker
	// is gone.
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
		return extractLegacyOfficeMetadataOnly(filePath, metadata)
	case ".xls":
		metadata.MimeType = "application/vnd.ms-excel"
		return extractLegacyOfficeMetadataOnly(filePath, metadata)
	case ".ppt":
		metadata.MimeType = "application/vnd.ms-powerpoint"
		return extractLegacyOfficeMetadataOnly(filePath, metadata)
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

	// Extract custom properties (HIGH RISK).
	//
	// CustomProps is the ONLY home. A mirror of every entry used to be written into
	// Properties under a "Custom_" prefix as well, described as "for easy scanning",
	// and the office preprocessor renders BOTH maps — the dedicated
	// "--- Custom Properties ---" block from CustomProps, then FormatPropertiesMap over
	// Properties. Both lines carry the custom_ prefix the validator types on, so every
	// custom property was reported TWICE.
	//
	// Measured on a real corpus of 304 .docx files: 506 CUSTOM_PROPERTY findings across
	// 202 files, with ZERO files holding an odd count and every (file, confidence)
	// bucket even — i.e. ~253 real properties each counted twice. A synthetic
	// one-property fixture produced 2 findings.
	//
	// The existing dedup could not catch it: per #202 the key is the BYTE SPAN, and the
	// two lines occupy genuinely different spans in the preprocessed text, so they are
	// correctly treated as two occurrences of duplicated input. The fix belongs here, at
	// the point the same value was written into two maps.
	//
	// Nothing read the mirror by key — verified, the write below was its only reference
	// anywhere in the tree — so dropping it removes the duplicate rendering without
	// costing any consumer. The legacy OLE extractor already populates CustomProps
	// alone, so this also brings the two extractors into line. See #308.
	if customProps, err := extractCustomPropertiesOptimized(fileIndex); err == nil && len(customProps) > 0 {
		metadata.CustomProps = customProps
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

// createFileIndex creates an index of files for efficient lookup, keyed by
// LOWERCASED part name.
//
// A zip entry name is data the document producer chose, and nothing requires the
// conventional casing. Keyed exactly, "docProps/Core.xml" was a different part
// from "docProps/core.xml", so one capital letter made a document's author,
// company and custom properties invisible to this extractor while the file still
// scanned "successfully" — the same class of defect the text extractor had for
// word/document.xml (see text-extract-officetextlib/ooxml_parts.go). Lookups
// therefore go through lookupPart. First entry wins, so a package carrying two
// spellings of the same part resolves deterministically to the earlier one.
func createFileIndex(reader *zip.ReadCloser) map[string]*zip.File {
	// Pre-allocate map with capacity to reduce rehashing
	fileIndex := make(map[string]*zip.File, len(reader.File))
	for _, file := range reader.File {
		key := strings.ToLower(file.Name)
		if _, seen := fileIndex[key]; !seen {
			fileIndex[key] = file
		}
	}
	return fileIndex
}

// lookupPart finds a part in an index built by createFileIndex, ignoring the case
// the producer used.
func lookupPart(fileIndex map[string]*zip.File, name string) (*zip.File, bool) {
	f, ok := fileIndex[strings.ToLower(name)]
	return f, ok
}

// extractCorePropertiesOptimized extracts core properties using file index
func extractCorePropertiesOptimized(fileIndex map[string]*zip.File) (*CoreProperties, error) {
	corePropsFile, exists := lookupPart(fileIndex, "docProps/core.xml")
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
	appPropsFile, exists := lookupPart(fileIndex, "docProps/app.xml")
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
	customPropsFile, exists := lookupPart(fileIndex, "docProps/custom.xml")
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
// isEmbeddedPartPath reports whether an OOXML part holds an embedded file that
// should be scanned in its own right.
//
// "/media/" alone was not enough. Word stores an embedded DOCUMENT under
// word/embeddings/ (an OLE object), and that path was never considered — so a
// document attached to a document was invisible. Verified as a cleartext leak:
// an SSN in the inner file survived into the redacted copy at
// word/embeddings/Microsoft_Word_Document.docx -> word/document.xml, with
// exit 0 and no warning. The same held for a container placed under
// word/media/.
func isEmbeddedPartPath(name string) bool {
	// Delegated so the read and write sides cannot disagree about which parts are
	// embedded files. See package embedded: a part one side descends into and the
	// other does not is a reported-but-unredactable finding, i.e. a cleartext leak
	// dressed as success.
	return embedded.IsPartPath(name)
}

// embeddedMediaType classifies an embedded part by extension, returning "" for
// anything no preprocessor can read.
//
// The previous switch had `default: continue`, which silently dropped every
// embedded DOCUMENT: .docx/.xlsx/.pptx and the legacy .doc/.xls/.ppt were all
// skipped, so their body text and metadata never reached a validator. A scanner
// missing a document nested inside a document is a detection hole with no
// attacker required.
func embeddedMediaType(ext string) string {
	// Delegated to the single admission table shared with the redactor. The switch
	// that used to live here had its own copy of the extension list, and the write
	// side had another; the classes of file the two admitted diverged, which is
	// exactly how an embedded image's EXIF and an embedded .docx's body both came
	// to be reported and then left in cleartext by --enable-redaction.
	//
	// The table also admits .pdf, which this switch never did, so an embedded PDF
	// is scanned for the first time.
	return embedded.Kind(ext)
}

type EmbeddedMedia struct {
	TempFilePath string
	OriginalName string
	MediaType    string // "image", "audio", etc.
}

// extractEmbeddedImages extracts embedded media files for further processing
func extractEmbeddedImages(reader *zip.ReadCloser, metadata *Metadata) error {
	// Only the name and the media type are recorded, so this loop writes no files. It used to
	// materialise every part to a temp file, use nothing but the path's existence, and delete
	// the lot on return — so every embedded part in the document was inflated and written to
	// disk twice per scan, once here and once in ExtractEmbeddedMediaForProcessing (#379).
	// Measured: a .docx with two parts produced four temp files.
	//
	// The parts are still INFLATED here, to io.Discard, and that is not waste: the admission
	// verdict is what decides membership below, and it depends on the actual byte count, on
	// read errors and on the budget charge. Skipping the read would change EmbeddedMediaCount
	// and the EmbeddedMedia_N_* indices — which are rendered into the text every validator
	// scans, so it would change detection, not just cost. Measured on a document whose first
	// part is over-cap: the count stays 2 and the survivor keeps index 0.
	var embeddedMedia []EmbeddedMedia

	// One budget per container. This loop and ExtractEmbeddedMediaForProcessing each get their
	// own, because they run at different times over the same archive and neither peak overlaps
	// the other. Note this is a PER-CONTAINER budget, not the whole-traversal one that
	// embedded.BudgetBytes' own comment describes; see the note there.
	budget := newExtractionBudget()

	for _, file := range reader.File {
		if !isEmbeddedPartPath(file.Name) {
			continue
		}

		// Extract EVERY part under media/ or embeddings/, and let the ROUTER decide
		// whether it can process it.
		//
		// This used to filter on a hand-maintained extension table, which meant the set
		// of embedded types examined was whatever someone had enumerated rather than
		// whatever the pipeline can actually read. Measured across 334 real Office
		// files: 488 of 2,520 embedded parts (19%) were excluded by that table,
		// including 411 .svg parts -- plain XML text that yields findings when scanned
		// on its own -- plus .emf, .wdp and the .bin form Word uses for embedded OLE
		// objects.
		//
		// The caller (OfficeMetadataPreprocessor.processEmbeddedMedia) now asks
		// RouterInterface.CanProcessFile per part, so embedded coverage tracks
		// top-level coverage automatically and cannot drift behind it again.
		ext := strings.ToLower(filepath.Ext(file.Name))
		mediaType := embeddedMediaType(ext)
		if mediaType == "" {
			mediaType = "unclassified"
		}

		// Ask for the admission verdict without keeping the bytes.
		if _, err := admitEmbeddedPart(file, budget, io.Discard); err != nil {
			// Silent HERE, deliberately, and not the same omission as the one #374 fixed.
			//
			// This loop exists only to count the embedded parts and record their names as
			// metadata properties. The loop that decides what actually gets SCANNED is
			// ExtractEmbeddedMediaForProcessing, which walks the same parts against the same
			// cap and returns a note for each one it could not extract. Reporting the refusal
			// here as well would put the same part on the operator's screen twice.
			//
			// The visible cost is that EmbeddedMediaCount under-counts by the refused parts.
			// That count is a report hint, and it is rendered into the text the validators
			// scan, so changing it changes scanned content — a separate decision from
			// disclosure.
			continue
		}

		embeddedMedia = append(embeddedMedia, EmbeddedMedia{
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

// extractionBudget bounds the TOTAL bytes one container may materialise to temp, across all of its
// embedded parts.
//
// MaxEmbeddedMediaSize bounds a single part; nothing bounded the sum. Measured at main @ 0610b7e on a
// 1.43MB .docx holding 30 parts that each declare 49MB -- just under the per-part cap:
//
//	peak temp disk   1.44 GB
//	peak RSS         0.27 GB   (this is a DISK exhaustion, not a memory one)
//	wall             1.87s
//	warnings         none, and the scan reported success
//
// 1.44GB is already 7x embedded.BudgetBytes, which existed as a declared constant that no production
// code consulted -- only comments and a test asserting it was positive. With MaxDispatchedParts at
// 512 the ceiling is about 25GB of temp from a ~25MB container.
//
// This is the "declared size bounds declared size" shape again: each part is checked against a cap,
// and the caps compose to nothing. Bounding the AGGREGATE is the only check an attacker cannot
// satisfy by splitting one large part into many admissible ones.
type extractionBudget struct {
	remaining int64
}

func newExtractionBudget() *extractionBudget {
	return &extractionBudget{remaining: embedded.BudgetBytes}
}

// reserve claims n bytes, reporting whether the budget allows it.
//
// Charged AFTER the copy with the bytes actually written, not before with the declared size: a lying
// declaration would otherwise exhaust the budget on parts that never materialise, turning an
// over-claim into a denial of service against the rest of the document. The per-part LimitReader
// already bounds any single copy, so the worst overshoot is one part's cap.
func (b *extractionBudget) reserve(n int64) bool {
	if b == nil {
		return true
	}
	if n > b.remaining {
		b.remaining = 0
		return false
	}
	b.remaining -= n
	return true
}

// admitEmbeddedPart applies the admission decision both extraction loops make, copying the
// part's bytes to dst.
//
// Both loops must reach the SAME verdict about the same part, because the metadata loop's
// verdict decides membership of EmbeddedMediaCount and the EmbeddedMedia_N_* properties, while
// the scanning loop's decides what is examined and what is disclosed. Two copies of these four
// checks would be free to drift, which is the divergence internal/embedded's package doc exists
// to prevent — so they live here once, and the temp-writing form below is a wrapper around this.
//
// dst may be io.Discard when a caller needs the verdict but not the bytes. The bytes still have
// to be inflated either way: the verdict depends on the ACTUAL length (a lying declared size is
// caught mid-copy), on read errors, and on the aggregate budget charge.
func admitEmbeddedPart(file *zip.File, budget *extractionBudget, dst io.Writer) (int64, error) {
	// Refuse on the declared size before opening the entry, so a part that cannot be admitted
	// costs no I/O and — in the temp-writing wrapper — no file.
	//
	// This is fractionally earlier than the original order, which opened the entry first. The
	// only observable difference is for an entry that is BOTH corrupt and over-cap: it now
	// reports the size refusal rather than the open error. That is the more informative of the
	// two causes, and it is the cheaper path.
	if file.UncompressedSize64 > MaxEmbeddedMediaSize {
		// The part's NAME is deliberately absent from the message. The only caller that
		// surfaces this error names the part's base name itself, and a scanned tree's
		// internal paths should not be repeated into a report twice — see #367, which is
		// open about exactly that. Sizes only.
		return 0, fmt.Errorf("declares %d bytes, over the %d-byte embedded cap (possible decompression bomb)",
			file.UncompressedSize64, MaxEmbeddedMediaSize)
	}

	rc, err := file.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	// Bounded so a lying declared size cannot exhaust the destination. Read one byte past the
	// cap so an over-cap entry is detectable.
	n, err := io.Copy(dst, io.LimitReader(rc, MaxEmbeddedMediaSize+1))
	if err != nil {
		return n, err
	}
	if n > MaxEmbeddedMediaSize {
		// Name omitted for the same reason as the declared-size refusal above.
		return n, fmt.Errorf("exceeds the %d-byte embedded extraction cap while being read (possible decompression bomb)",
			MaxEmbeddedMediaSize)
	}

	// Charge the AGGREGATE budget with the bytes actually written, not the declared size.
	if !budget.reserve(n) {
		return n, fmt.Errorf("would exceed the %d-byte total embedded extraction budget for this document (%w)",
			embedded.BudgetBytes, embedded.ErrBudgetExhausted)
	}

	return n, nil
}

// extractImageToTemp admits a part and materialises it to a temporary file.
//
// Only the SCANNING loop needs this. The metadata loop calls admitEmbeddedPart with io.Discard,
// because it needs the verdict and not the bytes.
func extractImageToTemp(file *zip.File, budget *extractionBudget) (string, error) {
	// Cheap refusals first, so a refused part creates no file. admitEmbeddedPart repeats the
	// declared-size check — it has to, since it is also the entry point for the other loop —
	// and repeating it here is what keeps os.CreateTemp off the refusal path.
	if file.UncompressedSize64 > MaxEmbeddedMediaSize {
		return "", fmt.Errorf("declares %d bytes, over the %d-byte embedded cap (possible decompression bomb)",
			file.UncompressedSize64, MaxEmbeddedMediaSize)
	}

	// The extension comes from the ADMISSION TABLE, not from the entry name. A zip
	// entry name is producer-controlled and this is a filesystem path, so the raw
	// name must not reach it (BSC1: validate untrusted input against an allowlist
	// at the sink). filepath.Ext happens to stop at a path separator, so the
	// previous form was not exploitable for traversal, but it did pass arbitrary
	// attacker bytes into a filename and relied on that incidental property; the
	// table returns one of a fixed set of ".xyz" literals instead.
	//
	// An unadmitted extension cannot occur here — the caller already checked
	// embeddedMediaType — so the fallback is unreachable in practice and exists
	// only so this function has no path that concatenates an unvalidated string.
	safeExt, ok := embedded.SafeExt(file.Name)
	if !ok {
		return "", fmt.Errorf("no admitted file type")
	}
	tempFile, err := os.CreateTemp("", "office_embedded_*"+safeExt)
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Any refusal removes the partial file, so a bomb leaves nothing on disk (MED-3).
	if _, err := admitEmbeddedPart(file, budget, tempFile); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

// ExtractEmbeddedMediaForProcessing extracts embedded media and returns temp file paths for
// full processing, plus one note per part it could NOT extract.
//
// # Why the notes exist
//
// This loop used to discard extractImageToTemp's error with a bare `continue`. When that error
// was the MaxEmbeddedMediaSize refusal, the part was never scanned and nothing said so: an
// outer .docx whose word/embeddings/attachment.docx crossed the cap reported "No matches
// found" at exit 0, and exit 0 again under --fail-on-incomplete, with nothing on stderr —
// while the identical inner document under the cap reported its SSN at HIGH 100. A container
// declared clean while sensitive content sat unread inside it is the cleartext-passthrough
// shape this tool exists to prevent, and the flag whose entire purpose is to escalate
// incomplete coverage could not see it. See #374.
//
// The notes are returned rather than logged because the caller owns the disclosure channel:
// OfficeMetadataPreprocessor merges them into ProcessedContent.ExtractionWarning, which
// survives FileRouter's combine step and reaches both the operator's "NOT FULLY EXAMINED"
// section and the --fail-on-incomplete exit code.
//
// Payload-free by construction: a note names the part's BASE name and the reason, never a
// path and never any bytes from the part. It reaches stderr and every machine format.
func ExtractEmbeddedMediaForProcessing(filePath string) ([]EmbeddedMedia, []string, error) {
	// Open the file as a ZIP archive
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file as ZIP: %v", err)
	}
	defer reader.Close()

	var embeddedMedia []EmbeddedMedia
	var notExamined []string
	refused := 0

	// The aggregate budget for this container. Unlike the metadata loop, every refusal here is
	// DISCLOSED through notExamined, so a document truncated by the budget says so rather than
	// reporting a partial scan as complete.
	budget := newExtractionBudget()

	for _, file := range reader.File {
		if !isEmbeddedPartPath(file.Name) {
			continue
		}

		// Extract EVERY part under media/ or embeddings/ and let the ROUTER decide
		// whether it can process it.
		//
		// This is the function that feeds the routing path, and it used to drop any part
		// whose extension was absent from a hand-maintained table. The set of embedded
		// types examined was therefore whatever someone had enumerated rather than
		// whatever the pipeline can read. Measured across 334 real Office files, 488 of
		// 2,520 embedded parts (19%) were excluded, including 411 .svg parts -- plain
		// XML text that yields an SSN finding when scanned as a standalone file -- plus
		// .emf, .wdp, and the .bin form Word uses for embedded OLE objects.
		//
		// The classification is kept only as a HINT for the report. The admission
		// decision now belongs to OfficeMetadataPreprocessor.processEmbeddedMedia, which
		// asks RouterInterface.CanProcessFile per part, so embedded coverage tracks
		// top-level coverage automatically and cannot silently fall behind it again.
		ext := strings.ToLower(filepath.Ext(file.Name))
		mediaType := embeddedMediaType(ext)
		if mediaType == "" {
			mediaType = "unclassified"
		}

		// Extract media to temp file
		tempFile, err := extractImageToTemp(file, budget)
		if err != nil {
			// DISCLOSE rather than skip. Every error this can return means a part that the
			// router was going to be asked about was not made available to it: the size
			// refusals, a zip entry that will not open, a temp file that cannot be created,
			// a read that fails part way. In each case content the operator believes was
			// scanned was not, so the note has to travel — a silent `continue` here is what
			// #374 is.
			//
			// Deliberately NOT the same judgement as the router's own admission check. That
			// one stays silent on purpose (a part nothing can read is a non-event, and a
			// line per decorative .emf trains operators to ignore warnings). This is the
			// opposite case: whether the part was readable is exactly what we no longer know.
			refused++
			if len(notExamined) < maxEmbeddedNotes {
				notExamined = append(notExamined, fmt.Sprintf("embedded part %q was not examined: %v",
					filepath.Base(file.Name), err))
			}
			continue
		}

		embeddedMedia = append(embeddedMedia, EmbeddedMedia{
			TempFilePath: tempFile,
			OriginalName: file.Name,
			MediaType:    mediaType,
		})
	}

	if refused > len(notExamined) {
		notExamined = append(notExamined, fmt.Sprintf(
			"and %d more embedded part(s) were not examined", refused-len(notExamined)))
	}

	return embeddedMedia, notExamined, nil
}

// CleanupEmbeddedMedia removes temporary files
func CleanupEmbeddedMedia(media []EmbeddedMedia) {
	for _, m := range media {
		os.Remove(m.TempFilePath)
	}
}
