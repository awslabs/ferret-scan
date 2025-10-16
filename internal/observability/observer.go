// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"io"
	"time"
)

// StandardObserver implements observability for all components
type StandardObserver struct {
	level         ObservabilityLevel
	writer        io.Writer
	DebugObserver *DebugObserver // Reference to debug observer when in debug mode
}

type ObservabilityLevel int

const (
	ObservabilityOff     ObservabilityLevel = 0
	ObservabilityMetrics ObservabilityLevel = 1
	ObservabilityDebug   ObservabilityLevel = 2
)

// NewStandardObserver creates observability component
func NewStandardObserver(level ObservabilityLevel, writer io.Writer) *StandardObserver {
	return &StandardObserver{
		level:  level,
		writer: writer,
	}
}

// StartTiming returns a function to complete timing
func (o *StandardObserver) StartTiming(component, operation, filePath string) func(success bool, metadata map[string]interface{}) {
	start := time.Now()

	return func(success bool, metadata map[string]interface{}) {
		duration := time.Since(start)

		data := StandardObservabilityData{
			Component:  component,
			Operation:  operation,
			FilePath:   filePath,
			DurationMs: duration.Milliseconds(),
			Success:    success,
			Metadata:   metadata,
		}

		o.LogOperation(data)
	}
}

// LogOperation logs operation data
func (o *StandardObserver) LogOperation(data StandardObservabilityData) {
	if o.level == ObservabilityOff {
		return
	}

	data.RequestID = "req-" + time.Now().Format("20060102-150405")

	// Only log JSON in debug mode
	if o.level == ObservabilityDebug {
		json.NewEncoder(o.writer).Encode(data)
	}
}

// StandardObservabilityData for all components
type StandardObservabilityData struct {
	Component     string                 `json:"component"`
	Operation     string                 `json:"operation"`
	RequestID     string                 `json:"request_id"`
	FilePath      string                 `json:"file_path,omitempty"`
	DurationMs    int64                  `json:"duration_ms,omitempty"`
	Success       bool                   `json:"success"`
	Error         string                 `json:"error,omitempty"`
	ContentLength int                    `json:"content_length,omitempty"`
	MatchCount    int                    `json:"match_count,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}
