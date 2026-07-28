// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"sort"

	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// PreprocessorFactory creates preprocessors with given configuration
type PreprocessorFactory func(config map[string]interface{}) preprocessors.Preprocessor

// PreprocessorRegistry manages preprocessor registration and creation
type PreprocessorRegistry struct {
	factories map[string]PreprocessorFactory
}

// NewPreprocessorRegistry creates a new preprocessor registry
func NewPreprocessorRegistry() *PreprocessorRegistry {
	return &PreprocessorRegistry{
		factories: make(map[string]PreprocessorFactory),
	}
}

// Register adds a preprocessor factory to the registry
func (r *PreprocessorRegistry) Register(name string, factory PreprocessorFactory) {
	r.factories[name] = factory
}

// Create creates a preprocessor instance by name with configuration
func (r *PreprocessorRegistry) Create(name string, config map[string]interface{}) preprocessors.Preprocessor {
	if factory, exists := r.factories[name]; exists {
		return factory(config)
	}
	return nil
}

// GetRegisteredNames returns all registered preprocessor names, sorted.
//
// Sorted rather than map order: callers use this to create and then run
// preprocessors, and Go randomizes map iteration per range, so an unsorted
// result made the preprocessor set order differ between processes.
func (r *PreprocessorRegistry) GetRegisteredNames() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CreateAll creates all registered preprocessors with given configuration, in a
// stable (name-sorted) order.
func (r *PreprocessorRegistry) CreateAll(config map[string]interface{}) []preprocessors.Preprocessor {
	names := r.GetRegisteredNames()
	processors := make([]preprocessors.Preprocessor, 0, len(names))
	for _, name := range names {
		if processor := r.Create(name, config); processor != nil {
			processors = append(processors, processor)
		}
	}
	return processors
}
