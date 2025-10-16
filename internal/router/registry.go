// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"ferret-scan/internal/preprocessors"
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

// GetRegisteredNames returns all registered preprocessor names
func (r *PreprocessorRegistry) GetRegisteredNames() []string {
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// CreateAll creates all registered preprocessors with given configuration
func (r *PreprocessorRegistry) CreateAll(config map[string]interface{}) []preprocessors.Preprocessor {
	var processors []preprocessors.Preprocessor
	for name := range r.factories {
		if processor := r.Create(name, config); processor != nil {
			processors = append(processors, processor)
		}
	}
	return processors
}
