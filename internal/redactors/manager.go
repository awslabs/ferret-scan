// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// RedactionManager coordinates all redaction operations and manages multiple redactors
type RedactionManager struct {
	// redactors maps file extensions to their corresponding redactors
	redactors map[string]Redactor

	// observer handles observability and metrics
	observer observability.Observer

	// outputManager handles file system operations
	outputManager *OutputStructureManager

	// auditLogManager handles redaction audit log management
	auditLogManager *RedactionAuditLogManager

	// config contains redaction policies and settings
	config *RedactionManagerConfig

	// mutex protects concurrent access to redactors map
	mu sync.RWMutex

	// documentCounter assigns audit-log document IDs. It is incremented under
	// documentMu, never read from the clock: two files finishing within the same
	// clock tick used to receive the same ID, and the loser's audit entry was
	// dropped. See nextDocumentID.
	documentCounter int
	documentMu      sync.Mutex

	// stats tracks redaction statistics
	stats *RedactionStats

	// embeddedDepth bounds container-inside-container redaction.
	//
	// Held here rather than on a redactor because a redactor instance is shared
	// across concurrent files and RedactDocument has no context parameter to thread
	// a counter through — the same reason FileRouter owns the read side's copy. See
	// RedactEmbedded in embedded.go.
	embeddedDepth embeddedDepthState
}

// RedactionManagerConfig contains configuration for the redaction manager
type RedactionManagerConfig struct {
	// DefaultStrategy is the default redaction strategy to use
	DefaultStrategy RedactionStrategy

	// MaxConcurrentRedactions limits the number of concurrent redaction operations
	MaxConcurrentRedactions int

	// EnableBatchProcessing enables batch processing capabilities
	EnableBatchProcessing bool

	// BatchSize is the maximum number of files to process in a single batch
	BatchSize int

	// RetryAttempts is the number of retry attempts for failed redactions
	RetryAttempts int

	// RetryDelay is the delay between retry attempts
	RetryDelay time.Duration

	// EnableAuditTrail enables audit trail logging
	EnableAuditTrail bool

	// AuditLogPath is the path to the audit log file
	AuditLogPath string

	// FailureHandling defines how to handle redaction failures
	FailureHandling FailureHandlingMode
}

// FailureHandlingMode defines how to handle redaction failures
type FailureHandlingMode int

const (
	// FailureHandlingStrict stops processing on any failure
	FailureHandlingStrict FailureHandlingMode = iota
	// FailureHandlingContinue continues processing despite failures
	FailureHandlingContinue
	// FailureHandlingGraceful attempts graceful degradation
	FailureHandlingGraceful
)

// RedactionStats tracks statistics for redaction operations
type RedactionStats struct {
	mu sync.RWMutex

	// TotalFiles is the total number of files processed
	TotalFiles int64

	// SuccessfulRedactions is the number of successful redactions
	SuccessfulRedactions int64

	// FailedRedactions is the number of failed redactions
	FailedRedactions int64

	// TotalMatches is the total number of matches found
	TotalMatches int64

	// TotalRedactions is the total number of redactions applied
	TotalRedactions int64

	// ProcessingTime is the total time spent on redaction operations
	ProcessingTime time.Duration

	// RedactorStats tracks statistics per redactor type
	RedactorStats map[string]*RedactorStats

	// StartTime is when the redaction manager was created
	StartTime time.Time
}

// RedactorStats tracks statistics for a specific redactor
type RedactorStats struct {
	FilesProcessed  int64
	SuccessfulCount int64
	FailedCount     int64
	TotalMatches    int64
	TotalRedactions int64
	ProcessingTime  time.Duration
	AverageFileSize int64
	LastProcessedAt time.Time
}

// BatchRedactionRequest represents a batch redaction request
type BatchRedactionRequest struct {
	// Files is the list of files to redact
	Files []FileRedactionRequest

	// Strategy is the redaction strategy to use for all files
	Strategy RedactionStrategy

	// OutputDirectory is the base output directory
	OutputDirectory string

	// Metadata contains additional metadata for the batch
	Metadata map[string]interface{}
}

// FileRedactionRequest represents a single file redaction request
type FileRedactionRequest struct {
	// InputPath is the path to the input file
	InputPath string

	// OutputPath is the path for the redacted output file
	OutputPath string

	// Matches are the sensitive data matches to redact
	Matches []detector.Match

	// Strategy is the redaction strategy (overrides batch strategy if set)
	Strategy *RedactionStrategy

	// Metadata contains additional metadata for this file
	Metadata map[string]interface{}
}

// BatchRedactionResult represents the result of a batch redaction operation
type BatchRedactionResult struct {
	// Success indicates if the entire batch was successful
	Success bool

	// Results contains the results for each file
	Results []FileRedactionResult

	// TotalFiles is the total number of files in the batch
	TotalFiles int

	// SuccessfulFiles is the number of successfully processed files
	SuccessfulFiles int

	// FailedFiles is the number of failed files
	FailedFiles int

	// TotalProcessingTime is the total time for the batch
	TotalProcessingTime time.Duration

	// Errors contains any batch-level errors
	Errors []error

	// Metadata contains additional result metadata
	Metadata map[string]interface{}
}

// FileRedactionResult represents the result of a single file redaction
type FileRedactionResult struct {
	// InputPath is the path to the input file
	InputPath string

	// Result is the redaction result (nil if failed)
	Result *RedactionResult

	// Error is the error if redaction failed
	Error error

	// RedactorUsed is the name of the redactor that processed this file
	RedactorUsed string

	// ProcessingTime is the time taken to process this file
	ProcessingTime time.Duration

	// RetryAttempts is the number of retry attempts made
	RetryAttempts int
}

// NewRedactionManagerWithConfig creates a new RedactionManager with custom configuration
func NewRedactionManagerWithConfig(outputManager *OutputStructureManager, observer observability.Observer, config *RedactionManagerConfig) *RedactionManager {
	if observer == nil {
		observer = observability.NewStandardObserver(observability.ObservabilityMetrics, nil)
	}

	if config == nil {
		config = &RedactionManagerConfig{
			DefaultStrategy:         RedactionFormatPreserving,
			MaxConcurrentRedactions: 4,
			EnableBatchProcessing:   true,
			BatchSize:               100,
			RetryAttempts:           3,
			RetryDelay:              time.Second * 2,
			EnableAuditTrail:        true,
			FailureHandling:         FailureHandlingGraceful,
		}
	}

	stats := &RedactionStats{
		RedactorStats: make(map[string]*RedactorStats),
		StartTime:     time.Now(),
	}

	// Create audit log manager
	auditLogManager := NewRedactionAuditLogManager("v1.0.0", outputManager.baseOutputDir)

	return &RedactionManager{
		redactors:       make(map[string]Redactor),
		observer:        observer,
		outputManager:   outputManager,
		auditLogManager: auditLogManager,
		config:          config,
		stats:           stats,
	}
}

// RegisterRedactor registers a redactor for specific file types
func (rm *RedactionManager) RegisterRedactor(redactor Redactor) error {
	if redactor == nil {
		return fmt.Errorf("redactor cannot be nil")
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	supportedTypes := redactor.GetSupportedTypes()
	if len(supportedTypes) == 0 {
		return fmt.Errorf("redactor must support at least one file type")
	}

	// Register redactor for each supported type
	for _, fileType := range supportedTypes {
		// Normalize file type (ensure it starts with a dot for extensions)
		normalizedType := strings.ToLower(fileType)
		if !strings.HasPrefix(normalizedType, ".") {
			normalizedType = "." + normalizedType
		}

		rm.redactors[normalizedType] = redactor
	}

	// Initialize stats for this redactor
	rm.stats.mu.Lock()
	rm.stats.RedactorStats[redactor.GetName()] = &RedactorStats{
		LastProcessedAt: time.Now(),
	}
	rm.stats.mu.Unlock()

	rm.logEvent("redactor_registered", true, map[string]interface{}{
		"redactor_name":   redactor.GetName(),
		"supported_types": supportedTypes,
		"total_redactors": len(rm.redactors),
	})

	return nil
}

// GetRedactorForFile returns the appropriate redactor for a given file
func (rm *RedactionManager) GetRedactorForFile(filePath string) (Redactor, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	ext := strings.ToLower(filepath.Ext(filePath))

	redactor, exists := rm.redactors[ext]
	if !exists {
		// A file whose BYTES are text is redactable as text, whatever it is named.
		//
		// The scanner admits files by SNIFFING them — router.isTextFile reads the first 512
		// bytes and asks preprocessors.LooksLikeText — so it happily scans .env, .tfvars, .sql,
		// .py, .sh, .properties, .toml, .pem, Dockerfile and Makefile. Redactor selection
		// instead matched an eleven-extension allowlist, so every one of those was scanned,
		// reported findings, and could never produce a redacted copy. Measured on a file
		// holding an AWS secret key and a database password: 3 findings, no output file,
		// exit 0, for all eleven names above, while the same content in a .txt redacted fine.
		//
		// This is the same "reported but unredactable" failure as #306, and .env is the single
		// likeliest file in a repository to hold a live credential.
		//
		// The fix reuses the SNIFF rather than lengthening the list, so the two decisions
		// cannot drift apart again: whatever the scanner is willing to read as text, the
		// redactor is willing to write as text. A longer allowlist is a list of names someone
		// thought of, and the failure being fixed is a name nobody thought of.
		//
		// Binary files are not at risk. LooksLikeText is the null-byte-and-encoding sniff the
		// text preprocessor uses, and it returns false for every binary container this tool
		// handles — verified against real .mp3, .m4a, .flac, .wav, .jpg, .png, .zip and
		// arbitrary byte soup. Those keep falling through to the refusal below, which is
		// disclosed. It returns TRUE for UTF-16 text, which a naive null-byte check would
		// have rejected.
		if plain, ok := rm.redactors[".txt"]; ok && looksLikeTextFile(filePath) {
			return plain, nil
		}
		if ext == "" {
			return nil, fmt.Errorf("file has no extension and its bytes are not text: %s", filePath)
		}
		return nil, fmt.Errorf("no redactor registered for file type: %s", ext)
	}

	// A container extension whose BYTES are plain text must be redacted as text.
	//
	// Selection here is by extension, exactly as routing was, and the two have to
	// agree: once the scanner detects a value in a text file named .docx, refusing
	// to redact it produces the worst outcome available — the finding is REPORTED,
	// so the report says it was handled, and no output file is written at all.
	// Measured before this: 1 finding, zero bytes redacted, exit 0.
	//
	// The check is deliberately narrow. It runs only for extensions a
	// container-format redactor claims, and only when the file does not carry that
	// format's signature, so a well-formed document is never diverted. Reading a
	// few hundred bytes is also cheap next to the redaction that follows.
	if plain, ok := rm.redactors[".txt"]; ok && !hasContainerSignature(filePath) {
		if _, isContainer := containerRedactorExtensions[ext]; isContainer {
			return plain, nil
		}
	}

	return redactor, nil
}

// looksLikeTextFile reports whether a file's leading bytes are text, using the SAME sniff that
// decided to scan it.
//
// Shared deliberately rather than reimplemented: preprocessors.LooksLikeText is what
// router.isTextFile calls to admit a file for scanning, so routing this through it makes scan
// coverage and redact coverage agree by construction. Two local definitions of "text" would
// eventually disagree, and the direction they disagree in is a file that gets scanned and
// cannot be redacted — which is the bug this exists to close.
//
// A read failure is false, not an error: the caller's next step is a refusal that gets
// disclosed either way, and a file that cannot be opened here cannot be redacted anyway.
// A zero-byte file is false too — router.isTextFile calls an empty file text so it is not
// reported as unreadable, but an empty file has no findings to remove.
func looksLikeTextFile(filePath string) bool {
	f, err := os.Open(filepath.Clean(filePath)) // #nosec G304 -- path already vetted by the router
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}
	return preprocessors.LooksLikeText(buf[:n])
}

// containerRedactorExtensions are the extensions handled by a redactor that
// requires a specific binary container format. A file with one of these names but
// without the matching signature cannot be redacted by that redactor, so it falls
// back to text.
//
// .pdf is absent on purpose: PDF redaction is unimplemented and refuses to write
// output rather than falsely report success, and diverting a text file named .pdf
// to the text redactor would be correct but is a behaviour change beyond this fix.
var containerRedactorExtensions = map[string]struct{}{
	".docx": {}, ".xlsx": {}, ".pptx": {},
	".docm": {}, ".xlsm": {}, ".pptm": {},
	".doc": {}, ".xls": {}, ".ppt": {},
	// OpenDocument is a ZIP container too, so a file merely NAMED .odt must fall back to
	// the text redactor rather than reaching the office redactor and failing there (#514).
	".odt": {}, ".ods": {}, ".odp": {},
	".ott": {}, ".ots": {}, ".otp": {},
}

// hasContainerSignature reports whether a file begins with the ZIP (OOXML) or OLE
// compound-file magic. A read failure returns true so an unreadable file keeps its
// extension-selected redactor and fails through the existing path, rather than
// being silently rewritten as text.
func hasContainerSignature(filePath string) bool {
	f, err := os.Open(filepath.Clean(filePath)) // #nosec G304 -- path already vetted by the caller
	if err != nil {
		return true
	}
	defer f.Close()

	var head [8]byte
	n, err := io.ReadFull(f, head[:])
	if err != nil && n < 4 {
		return true
	}

	// ZIP local file header: OOXML and OpenDocument.
	if n >= 4 && head[0] == 0x50 && head[1] == 0x4B {
		return true
	}
	// OLE compound file: legacy .doc/.xls/.ppt.
	if n >= 8 && head[0] == 0xD0 && head[1] == 0xCF && head[2] == 0x11 && head[3] == 0xE0 {
		return true
	}
	return false
}

// updateStats safely updates statistics using a callback function
func (rm *RedactionManager) updateStats(updateFunc func(*RedactionStats)) {
	rm.stats.mu.Lock()
	defer rm.stats.mu.Unlock()
	updateFunc(rm.stats)
}

// logEvent logs an event if observer is available
func (rm *RedactionManager) logEvent(operation string, success bool, metadata map[string]interface{}) {
	if rm.observer != nil {
		rm.observer.StartTiming("redaction_manager", operation, "")(success, metadata)
	}
}

// GetOutputManager returns the output manager for use by external redactor registration
func (rm *RedactionManager) GetOutputManager() *OutputStructureManager {
	return rm.outputManager
}

// nextDocumentID returns a fresh audit-log document ID.
//
// IDs come from a counter rather than time.Now().UnixNano(). The clock has
// microsecond resolution in practice, so two files whose redaction finished in the
// same tick were handed the same ID; CreateAuditLog rejects a duplicate and the
// caller treated that as a soft failure, so the second file's audit entry was
// silently discarded. A counter cannot collide, and it also makes the IDs
// reproducible for a given traversal order, so two audit logs of the same input can
// be compared.
//
// The worker pool calls in from several goroutines, hence the dedicated mutex — it
// is separate from rm.mu, which guards the redactors map.
func (rm *RedactionManager) nextDocumentID() string {
	rm.documentMu.Lock()
	defer rm.documentMu.Unlock()

	rm.documentCounter++
	return fmt.Sprintf("doc_%d", rm.documentCounter)
}

// AddRedactionResult adds a redaction result to the index manager
func (rm *RedactionManager) AddRedactionResult(originalPath, redactedPath string, result *RedactionResult) {
	if rm.auditLogManager != nil && result != nil {
		// Generate document ID
		documentID := rm.nextDocumentID()

		// Create audit log for this document. A failure here loses the compliance
		// record for a file that was still redacted on disk, so report it as an
		// error rather than a debug event.
		_, err := rm.auditLogManager.CreateAuditLog(documentID, originalPath, redactedPath)
		if err != nil {
			rm.logEvent("index_creation_failed", false, map[string]interface{}{
				"error":         err.Error(),
				"document_id":   documentID,
				"original_path": originalPath,
			})
			return
		}

		// Add each redaction to the index
		for i, redactionMapping := range result.RedactionMap {
			contentRedaction := ContentRedaction{
				ID:           fmt.Sprintf("%s_redaction_%d", documentID, i),
				TargetType:   "parent_document",
				DataType:     redactionMapping.DataType,
				RedactedText: redactionMapping.RedactedText,
				Strategy:     redactionMapping.Strategy,
				Confidence:   redactionMapping.Confidence / 100.0, // Convert to 0-1 range
				Timestamp:    time.Now(),
			}

			err := rm.auditLogManager.AddContentRedaction(documentID, contentRedaction)
			if err != nil {
				rm.logEvent("redaction_add_failed", false, map[string]interface{}{
					"error":       err.Error(),
					"document_id": documentID,
				})
			}
		}

		// Update statistics
		rm.updateStats(func(stats *RedactionStats) {
			stats.TotalRedactions += int64(len(result.RedactionMap))
			stats.SuccessfulRedactions++
		})

		rm.logEvent("redaction_result_added", true, map[string]interface{}{
			"original_path":   originalPath,
			"redacted_path":   redactedPath,
			"redaction_count": len(result.RedactionMap),
			"document_id":     documentID,
		})
	}
}

// ExportAuditLog exports the redaction audit log to the specified file path
func (rm *RedactionManager) ExportAuditLog(auditLogPath string) error {
	if rm.auditLogManager == nil {
		return fmt.Errorf("audit log manager not initialized")
	}

	// Export all audit logs to JSON
	data, err := rm.auditLogManager.ExportAllAuditLogs()
	if err != nil {
		return fmt.Errorf("failed to export audit logs: %w", err)
	}

	// Write to file with secure permissions (owner read/write only)
	if err := os.WriteFile(auditLogPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write audit log file: %w", err)
	}

	return nil
}
