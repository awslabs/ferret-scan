// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// DebugObserver provides detailed step-by-step debugging
type DebugObserver struct {
	*StandardObserver
	indent int
}

// NewDebugObserver creates a debug observer with step-by-step logging
func NewDebugObserver(writer io.Writer) *DebugObserver {
	return &DebugObserver{
		StandardObserver: NewStandardObserver(ObservabilityDebug, writer),
		indent:           0,
	}
}

// StartStep begins a processing step with indentation
func (d *DebugObserver) StartStep(component, step, filePath string) func(success bool, details string) {
	start := time.Now()
	indentStr := strings.Repeat("  ", d.indent)

	fmt.Fprintf(d.writer, "%s🔄 %s: %s (%s)\n", indentStr, component, step, filePath)
	d.indent++

	return func(success bool, details string) {
		d.indent--
		duration := time.Since(start)
		indentStr := strings.Repeat("  ", d.indent)

		if success {
			fmt.Fprintf(d.writer, "%s✅ %s: %s completed (%dms) %s\n",
				indentStr, component, step, duration.Milliseconds(), details)
		} else {
			fmt.Fprintf(d.writer, "%s❌ %s: %s failed (%dms) %s\n",
				indentStr, component, step, duration.Milliseconds(), details)
		}
	}
}

// LogDetail logs a detail within the current step
func (d *DebugObserver) LogDetail(component, detail string) {
	indentStr := strings.Repeat("  ", d.indent)
	fmt.Fprintf(d.writer, "%s   → %s: %s\n", indentStr, component, detail)
}

// LogMetric logs a metric value
func (d *DebugObserver) LogMetric(component, metric string, value interface{}) {
	indentStr := strings.Repeat("  ", d.indent)
	fmt.Fprintf(d.writer, "%s   📊 %s: %s = %v\n", indentStr, component, metric, value)
}
