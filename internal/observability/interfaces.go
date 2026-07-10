// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package observability

// Observable interface for all components that need observability
type Observable interface {
	// GetComponentName returns the component identifier
	GetComponentName() string
}

// Observer is the telemetry seam consumed across ferret-scan components.
//
// Components hold an Observer (this interface) rather than the concrete
// *StandardObserver, so the telemetry implementation can be swapped without
// touching every call site. *StandardObserver is the production implementation;
// tests may supply their own.
//
// Debug() exposes the step-by-step debug observer (nil unless debug logging is
// enabled). It replaces direct access to the former exported DebugObserver
// field so the seam stays a pure interface.
type Observer interface {
	// StartTiming returns a function to complete timing for an operation.
	StartTiming(component, operation, filePath string) func(success bool, metadata map[string]interface{})
	// LogOperation logs structured operation data.
	LogOperation(data StandardObservabilityData)
	// Debug returns the debug observer, or nil when debug logging is off.
	Debug() *DebugObserver
}

// Unused OperationData struct removed
