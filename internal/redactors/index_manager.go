// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// RedactionAuditLogManager manages redaction audit logs for multiple documents
type RedactionAuditLogManager struct {
	// auditLogs maps document IDs to their redaction audit logs
	auditLogs map[string]*RedactionAuditLog

	// filePaths maps file paths to document IDs for quick lookup
	filePaths map[string]string

	// mutex protects concurrent access to the manager
	mutex sync.RWMutex

	// ferretVersion is the version of Ferret-Scan
	ferretVersion string

	// outputDir is the base directory for redacted files
	outputDir string
}

// NewRedactionAuditLogManager creates a new RedactionAuditLogManager
func NewRedactionAuditLogManager(ferretVersion, outputDir string) *RedactionAuditLogManager {
	return &RedactionAuditLogManager{
		auditLogs:     make(map[string]*RedactionAuditLog),
		filePaths:     make(map[string]string),
		ferretVersion: ferretVersion,
		outputDir:     outputDir,
	}
}

// CreateIndex creates a new redaction index for a document
func (rim *RedactionAuditLogManager) CreateAuditLog(documentID, originalPath, redactedPath string) (*RedactionAuditLog, error) {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	// Check if audit log already exists
	if _, exists := rim.auditLogs[documentID]; exists {
		return nil, fmt.Errorf("audit log for document ID %s already exists", documentID)
	}

	// Create new audit log
	auditLog := NewRedactionAuditLog(documentID, originalPath, redactedPath, rim.ferretVersion)

	// Generate verification hash for the original document, streaming rather than buffering:
	// see HashFile for the 80 MB measurement that motivated it.
	if hash := HashFile(originalPath); hash != "" {
		auditLog.SetOriginalFileHash(hash)
	}

	// And for the redacted document, which is the artifact anyone downstream actually consumes.
	//
	// SetRedactedFileHash existed and had NO callers, so redacted_file_hash was empty in every audit
	// log ever written, for every redactor and every file type. The log therefore attested to the
	// input and to a list of replacements, but nothing tied it to the bytes that were produced —
	// which is the one thing a compliance reader needs it for.
	//
	// This is the right point despite the field's history: the caller is
	// RedactionManager.AddRedactionResult, which the worker pool invokes only AFTER the redactor has
	// returned successfully, so the output file is already on disk. Verified rather than assumed —
	// see TestRedactedFileHashIsSetAndVerifiable, which recomputes the digest with an independent
	// sha256 over the written file and compares.
	//
	// When the file cannot be hashed the field is left EMPTY and omitted from the JSON rather than
	// written as "": a redactor may legitimately decline to write an output (the Office redactor
	// refuses a partial redaction; an unregistered type produces none), and a consumer must be able
	// to tell "no artifact to attest to" from "an artifact whose digest is the empty string". A
	// sha256 is never legitimately empty, so absent is unambiguous.
	if hash := HashFile(redactedPath); hash != "" {
		auditLog.SetRedactedFileHash(hash)
	}

	// Store the audit log
	rim.auditLogs[documentID] = auditLog
	rim.filePaths[originalPath] = documentID

	return auditLog, nil
}

// GetAuditLogByPath retrieves a redaction audit log by original file path
func (rim *RedactionAuditLogManager) GetAuditLogByPath(originalPath string) (*RedactionAuditLog, bool) {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	documentID, exists := rim.filePaths[originalPath]
	if !exists {
		return nil, false
	}

	auditLog, exists := rim.auditLogs[documentID]
	return auditLog, exists
}

// sortedDocumentIDs returns the managed document IDs in a fixed order. Callers
// that walk every audit log use it so their behavior — in particular which
// document a validation error names when several are invalid — does not depend
// on Go's randomized map iteration order.
//
// Callers must already hold rim.mutex.
func (rim *RedactionAuditLogManager) sortedDocumentIDs() []string {
	documentIDs := make([]string, 0, len(rim.auditLogs))
	for documentID := range rim.auditLogs {
		documentIDs = append(documentIDs, documentID)
	}
	sort.Strings(documentIDs)
	return documentIDs
}

// GetAuditLogCount returns the total number of audit logs managed
func (rim *RedactionAuditLogManager) GetAuditLogCount() int {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	return len(rim.auditLogs)
}

// AddContentRedaction adds a content redaction to the specified document's audit log
func (rim *RedactionAuditLogManager) AddContentRedaction(documentID string, redaction ContentRedaction) error {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	auditLog.AddContentRedaction(redaction)
	return nil
}

// ExportAllAuditLogs exports all redaction audit logs to a combined JSON format
func (rim *RedactionAuditLogManager) ExportAllAuditLogs() ([]byte, error) {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	// Create a combined structure
	combined := struct {
		ExportTimestamp time.Time                     `json:"export_timestamp"`
		FerretVersion   string                        `json:"ferret_version"`
		TotalDocuments  int                           `json:"total_documents"`
		AuditLogs       map[string]*RedactionAuditLog `json:"audit_logs"`
	}{
		ExportTimestamp: time.Now(),
		FerretVersion:   rim.ferretVersion,
		TotalDocuments:  len(rim.auditLogs),
		AuditLogs:       make(map[string]*RedactionAuditLog),
	}

	// Validate and copy all audit logs. Walk in sorted order so that when more
	// than one log is invalid the reported document is always the same one —
	// ranging the map made the error message vary run to run on identical input.
	// The emitted JSON itself is unaffected: encoding/json sorts map keys.
	for _, documentID := range rim.sortedDocumentIDs() {
		auditLog := rim.auditLogs[documentID]
		if err := auditLog.Validate(); err != nil {
			return nil, fmt.Errorf("audit log validation failed for document %s: %w", documentID, err)
		}
		combined.AuditLogs[documentID] = auditLog
	}

	return jsonMarshalIndent(combined, "", "  ")
}

// RedactionStatistics contains statistics about redactions
type RedactionStatistics struct {
	TotalDocuments          int            `json:"total_documents"`
	TotalRedactions         int            `json:"total_redactions"`
	TotalContentRedactions  int            `json:"total_content_redactions"`
	TotalMetadataRedactions int            `json:"total_metadata_redactions"`
	DataTypeStats           map[string]int `json:"data_type_stats"`
	MetadataFieldStats      map[string]int `json:"metadata_field_stats"`
	StrategyStats           map[string]int `json:"strategy_stats"`
}

// Helper function to marshal JSON with indentation
func jsonMarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}
