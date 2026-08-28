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
	// maxEmbeddedParts bounds how many embedded parts one container contributes, because
	// neither existing cap bounds the COUNT. MaxEmbeddedMediaSize bounds one part and
	// embedded.BudgetBytes bounds their total bytes; a part may be empty, so a container can
	// declare unboundedly many while charging nothing against either.
	//
	// The cost is per-part and linear, not quadratic — measured at HEAD on .docx files whose
	// media entries hold an 8-byte PNG signature and nothing else:
	//
	//	  1,000 parts    1.0s     50MB RSS      122KB input
	//	 10,000 parts    9.0s    120MB RSS      1.2MB input
	//	 50,000 parts   43.8s    352MB RSS      6.2MB input
	//	200,000 parts  184.3s   1182MB RSS     25.2MB input
	//
	// About 0.9ms and 6KB of RSS per part, and a zip entry costs the attacker ~128 bytes, so
	// 25MB of input buys three minutes of CPU and 1.2GB of memory. Linear is not safe by
	// itself when the constant is this large relative to the input.
	//
	// 4096 comes from the real distribution, not from taste. Across 381 real Office documents
	// on hand, the most embedded parts in any one file was 361 (next: 201, 201, 198, 83), the
	// median was 0 and the mean 7. So the cap sits ~11x above the largest legitimate file
	// measured and refuses nothing in that corpus, while cutting the 200,000-part case to
	// about 3.7s.
	//
	// It deliberately does NOT bound the cost to something trivial: a legitimate 4096-part
	// deck still costs seconds. Choosing a small cap to make the worst case fast would refuse
	// real documents, and refusing coverage on a real document is the more expensive error —
	// which is why every part past the cap is DISCLOSED with this cause named, never dropped
	// quietly.
	maxEmbeddedParts = 4096
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
	// Macro-enabled OOXML: the same container and the same docProps parts, so the same
	// reader. Only the declared MIME type differs (#497).
	case ".docm":
		metadata.MimeType = "application/vnd.ms-word.document.macroEnabled.12"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	case ".xlsm":
		metadata.MimeType = "application/vnd.ms-excel.sheet.macroEnabled.12"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	case ".pptm":
		metadata.MimeType = "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
		return extractOfficeOpenXMLMetadata(filePath, metadata)
	// ODF. These were already in officeExtensions, so IsOfficeFile claimed them and the office
	// metadata preprocessor was selected — and then this switch fell through to "unsupported file
	// format", the preprocessor returned that error, and the router silently moved on to the text
	// extractor. meta.xml was never read on any ODF document. See odf-extractor.go (#498).
	case ".odt":
		metadata.MimeType = "application/vnd.oasis.opendocument.text"
		return extractODFMetadata(filePath, metadata)
	case ".ods":
		metadata.MimeType = "application/vnd.oasis.opendocument.spreadsheet"
		return extractODFMetadata(filePath, metadata)
	case ".odp":
		metadata.MimeType = "application/vnd.oasis.opendocument.presentation"
		return extractODFMetadata(filePath, metadata)
	// ODF TEMPLATES. The same packages with a template media type (ODF 1.3 §3.3), so the same
	// reader. Registering them only in officeExtensions would repeat the .3gp mistake -- claimed
	// by the router and then unhandled here, which returns "unsupported file format" and looks
	// exactly like a clean file (#528).
	case ".ott":
		metadata.MimeType = "application/vnd.oasis.opendocument.text-template"
		return extractODFMetadata(filePath, metadata)
	case ".ots":
		metadata.MimeType = "application/vnd.oasis.opendocument.spreadsheet-template"
		return extractODFMetadata(filePath, metadata)
	case ".otp":
		metadata.MimeType = "application/vnd.oasis.opendocument.presentation-template"
		return extractODFMetadata(filePath, metadata)
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
	case ".docx", ".docm":
		extractWordMetadata(reader, metadata)
	case ".xlsx", ".xlsm":
		extractExcelMetadata(reader, metadata)
	case ".pptx", ".pptm":
		extractPowerPointMetadata(reader, metadata)
	}

	// Record the embedded parts this container holds. Cannot fail; see its doc comment.
	//
	// This used to be guarded by `if err != nil { metadata.Properties["ImageExtractionError"] =
	// err.Error() }`, which was unreachable AND wrong in two ways had it ever run. Properties is
	// rendered wholesale into the text the validators scan, so a diagnostic string there is
	// scanned as though it were document content: measured on a build with the arm forced, a
	// document went from 11 findings to 13, the extra ones matching the diagnostic rather than
	// anything in the file. And a message that names a temp path would have put that path in the
	// report. A diagnostic belongs in the disclosure channel, not in the scanned text.
	extractEmbeddedImages(reader, metadata)

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

// extractEmbeddedImages records the embedded parts a container holds, on the Metadata.
//
// Returns nothing. It used to return an error that it never produced — the body had exactly one
// return statement, `return nil` — so the caller's `if err != nil` arm was unreachable. That is
// worth removing rather than leaving armed: a channel that cannot carry anything reads, to the next
// person, as a channel that has been handled, and this file has already shipped one silent-discard
// bug for that exact reason (#374, #404). A part that cannot be admitted is disclosed by the loop
// below through notExamined, which is a real channel; total success is now stated in the signature
// instead of being implied by a return the compiler could not check.
func extractEmbeddedImages(reader *zip.ReadCloser, metadata *Metadata) {
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

	// One PER-CONTAINER budget, and deliberately NOT charged against the whole-traversal one.
	//
	// This loop writes nothing — every part goes to io.Discard — so it materialises no bytes for
	// the traversal bound to bound. Charging it anyway would spend the traversal's allowance
	// twice over on the same parts (measured at exactly 2x the bytes ever written) and, because
	// this loop's verdict decides membership of EmbeddedMediaCount and the EmbeddedMedia_N_*
	// properties that the validators scan, the parts the writing loop then had to refuse would
	// change DETECTION and not merely cost. The traversal bound covers bytes that persist and
	// re-enter the router; this one covers inflate work.
	budget := newExtractionBudget(nil)
	considered := 0

	for _, file := range reader.File {
		if !isEmbeddedPartPath(file.Name) {
			continue
		}

		// The same count cap as ExtractEmbeddedMediaForProcessing, and it has to be the same
		// number: this loop's verdict decides EmbeddedMediaCount and the EmbeddedMedia_N_*
		// properties, that loop's decides what gets scanned. If one capped and the other did
		// not, the metadata would advertise parts the scan never looked at, or the reverse.
		//
		// Here it can break rather than walk on. This loop discloses nothing (see below), so
		// unlike the scanning loop it has no count to finish computing.
		considered++
		if considered > maxEmbeddedParts {
			break
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

	// traversal is the budget shared by every container in ONE top-level file's tree, or
	// nil for a loop that materialises nothing. Set only for the temp-writing loop: see the
	// note at its construction for why charging the io.Discard loop too would cut detection.
	traversal *embedded.Budget
}

func newExtractionBudget(traversal *embedded.Budget) *extractionBudget {
	return &extractionBudget{remaining: embedded.BudgetBytes, traversal: traversal}
}

// reserveTraversal claims a part's DECLARED size against the whole-traversal budget, before any
// of its bytes are written.
//
// # Why this one is charged before the copy when the per-container one is charged after
//
// Charging after the copy bounds what gets SCANNED but not what gets WRITTEN, and the writing is
// most of the harm. Measured with the traversal charged post-copy on a 642KB document holding 16
// heavy children: 12 of the 16 parts were correctly refused and disclosed, and all 16 had already
// written their 45MB to temp — 659MB of disk from a two-thirds-of-a-megabyte file, with the bound
// working exactly as designed. A bound that fires after the cost has been paid is not a bound.
//
// Reserving up front makes the refusal free: once the traversal latches exhausted, every later
// part in every later container is refused without opening the entry. Total written is then
// BudgetBytes plus at most the single part that straddles the boundary.
//
// The declared size is producer-controlled, which is the objection to using it — an over-claim
// could exhaust the budget on parts that never materialise. settleTraversal answers that by
// handing back the difference as soon as the real length is known, before the next part is
// considered. It is already bounded by MaxEmbeddedMediaSize, checked by the caller above.
func (b *extractionBudget) reserveTraversal(declared int64) error {
	if b == nil || b.traversal == nil {
		return nil
	}
	if !b.traversal.Reserve(declared) {
		return fmt.Errorf("would exceed the %d-byte embedded extraction budget for this file and everything nested inside it (%w)",
			b.traversal.Limit(), embedded.ErrBudgetExhausted)
	}
	return nil
}

// settleTraversal corrects a reservation to the bytes actually written.
//
// Called on every path out of the copy, including the error paths: a part whose entry would not
// open, or whose read failed, must not leave its declared size spent. Leaking a reservation would
// let a document full of corrupt entries deny coverage to its own valid ones.
func (b *extractionBudget) settleTraversal(declared, actual int64) {
	if b == nil || b.traversal == nil {
		return
	}
	b.traversal.Release(declared - actual)
}

// reserveContainer charges this container's own allowance with the bytes actually written.
//
// Charged AFTER the copy, not before with the declared size: a lying declaration would otherwise
// exhaust the budget on parts that never materialise, turning an over-claim into a denial of
// service against the rest of the document. The per-part LimitReader already bounds any single
// copy, so the worst overshoot is one part's cap. Unlike the traversal above, this budget is
// discarded when the container is done, so an overshoot cannot accumulate.
func (b *extractionBudget) reserveContainer(n int64) error {
	if b == nil {
		return nil
	}
	if n > b.remaining {
		b.remaining = 0
		return fmt.Errorf("would exceed the %d-byte total embedded extraction budget for this document (%w)",
			embedded.BudgetBytes, embedded.ErrBudgetExhausted)
	}
	b.remaining -= n
	return nil
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

	// Claim the whole-traversal allowance BEFORE writing anything, so an exhausted traversal
	// costs no I/O and no disk. See reserveTraversal: charging it after the copy left every part
	// written before being refused.
	declared := int64(file.UncompressedSize64)
	if err := budget.reserveTraversal(declared); err != nil {
		return 0, err
	}
	// Corrected to the real length on every path out, including the failures below.
	written := int64(0)
	defer func() { budget.settleTraversal(declared, written) }()

	rc, err := file.Open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()

	// Bounded so a lying declared size cannot exhaust the destination. Read one byte past the
	// cap so an over-cap entry is detectable.
	n, err := io.Copy(dst, io.LimitReader(rc, MaxEmbeddedMediaSize+1))
	written = n
	if err != nil {
		return n, err
	}
	if n > MaxEmbeddedMediaSize {
		// Name omitted for the same reason as the declared-size refusal above.
		return n, fmt.Errorf("exceeds the %d-byte embedded extraction cap while being read (possible decompression bomb)",
			MaxEmbeddedMediaSize)
	}

	// Charge this container's own allowance with the bytes actually written.
	if err := budget.reserveContainer(n); err != nil {
		return n, err
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
// traversal bounds the bytes the WHOLE tree this container belongs to may materialise, and may
// be nil. The router owns it and hands the same one to every descendant of a top-level file; nil
// means "no traversal bound", which is how a direct caller with no router behaves — the same
// behaviour as before the bound existed. See #474.
func ExtractEmbeddedMediaForProcessing(filePath string, traversal *embedded.Budget) ([]EmbeddedMedia, []string, error) {
	// Open the file as a ZIP archive
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening file as ZIP: %v", err)
	}
	defer reader.Close()

	var embeddedMedia []EmbeddedMedia
	var notExamined []string
	refused := 0
	considered := 0
	beyondCap := 0

	// The aggregate budget for this container, charging the whole-traversal budget as well.
	// Unlike the metadata loop, every refusal here is DISCLOSED through notExamined, so a
	// document truncated by either budget says so rather than reporting a partial scan as
	// complete.
	//
	// This is the loop that WRITES, and it is the only one that charges the traversal. The
	// metadata loop below inflates the same parts to io.Discard, so charging both against one
	// allowance would halve effective coverage — and because the metadata loop's verdict decides
	// membership of EmbeddedMediaCount and the EmbeddedMedia_N_* properties, which the validators
	// scan, that would change DETECTION rather than only cost. Measured: charging both put the
	// aggregate at exactly 2x the bytes ever written. The traversal budget bounds bytes that
	// PERSIST and re-enter the router; the per-container budget bounds inflate work.
	budget := newExtractionBudget(traversal)

	for _, file := range reader.File {
		if !isEmbeddedPartPath(file.Name) {
			continue
		}

		// Past the count cap, keep WALKING but stop extracting.
		//
		// Breaking out would be cheaper and would make the disclosure a lie by omission: the
		// note below states how many parts went unexamined, and that number is only knowable
		// by finishing the walk. The remaining work is one string test per entry against a
		// central directory the zip reader has already parsed, so the walk is not the cost
		// this cap exists to bound — the inflate and the temp file are.
		considered++
		if considered > maxEmbeddedParts {
			beyondCap++
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

	// A separate line, and a separate counter from `refused`, because this is a different cause.
	// Folding it into the extraction-failure total would tell an operator that 195,904 parts
	// failed to read, when in fact they were never attempted — the same answer for the wrong
	// reason, which is the harder kind of report to act on.
	if beyondCap > 0 {
		notExamined = append(notExamined, fmt.Sprintf(
			"%d embedded part(s) beyond the %d-part limit were not examined (container declares %d)",
			beyondCap, maxEmbeddedParts, considered))
	}

	return embeddedMedia, notExamined, nil
}

// CleanupEmbeddedMedia removes temporary files
func CleanupEmbeddedMedia(media []EmbeddedMedia) {
	for _, m := range media {
		os.Remove(m.TempFilePath)
	}
}
