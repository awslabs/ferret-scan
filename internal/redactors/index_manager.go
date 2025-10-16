// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// Generate verification hash for the original document
	if originalContent, err := os.ReadFile(originalPath); err == nil {
		auditLog.SetOriginalFileHash(GenerateDocumentHash(originalContent))
	}

	// Store the audit log
	rim.auditLogs[documentID] = auditLog
	rim.filePaths[originalPath] = documentID

	return auditLog, nil
}

// GetAuditLog retrieves a redaction audit log by document ID
func (rim *RedactionAuditLogManager) GetAuditLog(documentID string) (*RedactionAuditLog, bool) {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	auditLog, exists := rim.auditLogs[documentID]
	return auditLog, exists
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

// ListAuditLogs returns all document IDs that have audit logs
func (rim *RedactionAuditLogManager) ListAuditLogs() []string {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	documentIDs := make([]string, 0, len(rim.auditLogs))
	for documentID := range rim.auditLogs {
		documentIDs = append(documentIDs, documentID)
	}
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

// AddMetadataRedaction adds a metadata redaction to the specified document's audit log
func (rim *RedactionAuditLogManager) AddMetadataRedaction(documentID string, redaction MetadataRedaction) error {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	auditLog.AddMetadataRedaction(redaction)
	return nil
}

// SetRedactionSummary sets the redaction summary for the specified document's audit log
func (rim *RedactionAuditLogManager) SetRedactionSummary(documentID string, summary RedactionSummary) error {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	auditLog.SetRedactionSummary(summary)
	return nil
}

// SetRedactionConfig sets the redaction configuration snapshot for the specified document's audit log
func (rim *RedactionAuditLogManager) SetRedactionConfig(documentID string, config *RedactionConfigSnapshot) error {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	auditLog.SetRedactionConfig(config)
	return nil
}

// ExportAuditLog exports a single redaction audit log to JSON format
func (rim *RedactionAuditLogManager) ExportAuditLog(documentID string) ([]byte, error) {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return nil, fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	// Validate the audit log before export
	if err := auditLog.Validate(); err != nil {
		return nil, fmt.Errorf("audit log validation failed: %w", err)
	}

	return auditLog.ToJSON()
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

	// Validate and copy all audit logs
	for documentID, auditLog := range rim.auditLogs {
		if err := auditLog.Validate(); err != nil {
			return nil, fmt.Errorf("audit log validation failed for document %s: %w", documentID, err)
		}
		combined.AuditLogs[documentID] = auditLog
	}

	return jsonMarshalIndent(combined, "", "  ")
}

// SaveAuditLog saves a single redaction audit log to a file
func (rim *RedactionAuditLogManager) SaveAuditLog(documentID, filePath string) error {
	jsonData, err := rim.ExportAuditLog(documentID)
	if err != nil {
		return fmt.Errorf("failed to export index: %w", err)
	}

	// Ensure the directory exists with secure permissions (owner only)
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the file with secure permissions (owner read/write only)
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write index file %s: %w", filePath, err)
	}

	return nil
}

// SaveAllAuditLogs saves all redaction audit logs to a single file
func (rim *RedactionAuditLogManager) SaveAllAuditLogs(filePath string) error {
	jsonData, err := rim.ExportAllAuditLogs()
	if err != nil {
		return fmt.Errorf("failed to export all indexes: %w", err)
	}

	// Ensure the directory exists with secure permissions (owner only)
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write the file with secure permissions (owner read/write only)
	if err := os.WriteFile(filePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write index file %s: %w", filePath, err)
	}

	return nil
}

// LoadAuditLog loads a redaction audit log from a JSON file
func (rim *RedactionAuditLogManager) LoadAuditLog(filePath string) (*RedactionAuditLog, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index file %s: %w", filePath, err)
	}

	auditLog, err := FromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit log from %s: %w", filePath, err)
	}

	// Validate the loaded audit log
	if err := auditLog.Validate(); err != nil {
		return nil, fmt.Errorf("loaded audit log validation failed: %w", err)
	}

	// Add to manager
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	rim.auditLogs[auditLog.DocumentID] = auditLog
	rim.filePaths[auditLog.OriginalPath] = auditLog.DocumentID

	return auditLog, nil
}

// GetRedactionStatistics returns statistics about all redactions
func (rim *RedactionAuditLogManager) GetRedactionStatistics() RedactionStatistics {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	stats := RedactionStatistics{
		TotalDocuments:     len(rim.auditLogs),
		DataTypeStats:      make(map[string]int),
		MetadataFieldStats: make(map[string]int),
		StrategyStats:      make(map[string]int),
	}

	for _, auditLog := range rim.auditLogs {
		stats.TotalContentRedactions += len(auditLog.ContentRedactions)
		stats.TotalMetadataRedactions += len(auditLog.MetadataRedactions)

		// Count by data type
		for _, redaction := range auditLog.ContentRedactions {
			stats.DataTypeStats[redaction.DataType]++
			stats.StrategyStats[redaction.Strategy.String()]++
		}

		// Count by metadata field
		for _, redaction := range auditLog.MetadataRedactions {
			stats.MetadataFieldStats[redaction.Field]++
		}
	}

	stats.TotalRedactions = stats.TotalContentRedactions + stats.TotalMetadataRedactions

	return stats
}

// ValidateAllAuditLogs validates all managed audit logs
func (rim *RedactionAuditLogManager) ValidateAllAuditLogs() error {
	rim.mutex.RLock()
	defer rim.mutex.RUnlock()

	for documentID, auditLog := range rim.auditLogs {
		if err := auditLog.Validate(); err != nil {
			return fmt.Errorf("validation failed for document %s: %w", documentID, err)
		}
	}

	return nil
}

// Clear removes all audit logs from the manager
func (rim *RedactionAuditLogManager) Clear() {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	rim.auditLogs = make(map[string]*RedactionAuditLog)
	rim.filePaths = make(map[string]string)
}

// RemoveAuditLog removes a specific audit log from the manager
func (rim *RedactionAuditLogManager) RemoveAuditLog(documentID string) error {
	rim.mutex.Lock()
	defer rim.mutex.Unlock()

	auditLog, exists := rim.auditLogs[documentID]
	if !exists {
		return fmt.Errorf("no audit log found for document ID %s", documentID)
	}

	// Remove from both maps
	delete(rim.auditLogs, documentID)
	delete(rim.filePaths, auditLog.OriginalPath)

	return nil
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
