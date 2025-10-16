// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package observability

// Observable interface for all components that need observability
type Observable interface {
	// GetComponentName returns the component identifier
	GetComponentName() string
}

// Unused OperationData struct removed

// Unused Observer interface and TrackedOperation removed
