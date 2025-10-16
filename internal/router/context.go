// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"io"
	"time"
)

// ProcessingContext provides standardized context to preprocessors
type ProcessingContext struct {
	// File Information
	FilePath string `json:"file_path"`
	FileSize int64  `json:"file_size"`
	FileExt  string `json:"file_ext"`
	MimeType string `json:"mime_type,omitempty"`

	// Processing Configuration
	// GENAI_DISABLED: EnableGenAI   bool            `json:"enable_genai"`
	// GENAI_DISABLED: GenAIServices map[string]bool `json:"genai_services,omitempty"`
	// GENAI_DISABLED: GenAIRegion   string          `json:"genai_region,omitempty"`
	MaxFileSize int64 `json:"max_file_size"`

	// Runtime Context
	RequestID string    `json:"request_id"`
	StartTime time.Time `json:"start_time"`
	Debug     bool      `json:"debug"`

	// Internal
	metrics *RouterMetrics `json:"-"`
	logger  *DebugLogger   `json:"-"`
}

// LogDebug logs debug information if debug mode is enabled
func (ctx *ProcessingContext) LogDebug(component, operation string, data map[string]interface{}) {
	if ctx.Debug && ctx.logger != nil {
		data["request_id"] = ctx.RequestID
		data["file_path"] = ctx.FilePath
		ctx.logger.Log(component, operation, data)
	}
}

// DebugLogger handles structured debug logging
type DebugLogger struct {
	enabled bool
	writer  io.Writer
}

// NewDebugLogger creates a new debug logger
func NewDebugLogger(enabled bool, writer io.Writer) *DebugLogger {
	return &DebugLogger{
		enabled: enabled,
		writer:  writer,
	}
}

// Log writes a structured debug entry
func (d *DebugLogger) Log(component, operation string, data map[string]interface{}) {
	if !d.enabled {
		return
	}

	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339Nano),
		"component": component,
		"operation": operation,
		"data":      data,
	}

	json.NewEncoder(d.writer).Encode(entry)
}

// RouterMetrics collects performance and usage metrics
type RouterMetrics struct {
	FilesProcessed   int64            `json:"files_processed"`
	ProcessingTimeMs map[string]int64 `json:"processing_time_ms"`
	ErrorCounts      map[string]int64 `json:"error_counts"`
	FileTypeCounts   map[string]int64 `json:"file_type_counts"`
}

// NewRouterMetrics creates a new metrics collector
func NewRouterMetrics() *RouterMetrics {
	return &RouterMetrics{
		ProcessingTimeMs: make(map[string]int64),
		ErrorCounts:      make(map[string]int64),
		FileTypeCounts:   make(map[string]int64),
	}
}

// RecordProcessing records successful processing metrics
func (m *RouterMetrics) RecordProcessing(preprocessor string, durationMs int64) {
	m.FilesProcessed++
	m.ProcessingTimeMs[preprocessor] += durationMs
}

// RecordError records error metrics
func (m *RouterMetrics) RecordError(errorType string) {
	m.ErrorCounts[errorType]++
}

// RecordFileType records file type metrics
func (m *RouterMetrics) RecordFileType(fileExt string) {
	m.FileTypeCounts[fileExt]++
}

// GetSummary returns a summary of metrics
func (m *RouterMetrics) GetSummary() map[string]interface{} {
	return map[string]interface{}{
		"files_processed":    m.FilesProcessed,
		"processing_time_ms": m.ProcessingTimeMs,
		"error_counts":       m.ErrorCounts,
		"file_type_counts":   m.FileTypeCounts,
	}
}
