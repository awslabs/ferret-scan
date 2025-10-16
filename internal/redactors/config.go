// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"path/filepath"
	"strings"
)

// RedactionConfig contains all redaction configuration settings
type RedactionConfig struct {
	// Enabled indicates whether redaction is enabled
	Enabled bool `yaml:"enabled"`

	// OutputDirectory is the base directory for redacted files
	OutputDirectory string `yaml:"output_directory"`

	// DefaultStrategy is the default redaction strategy to use
	DefaultStrategy string `yaml:"default_strategy"`

	// ParallelProcessing enables parallel processing of redactions
	ParallelProcessing bool `yaml:"parallel_processing"`

	// MaxWorkers is the maximum number of worker goroutines
	MaxWorkers int `yaml:"max_workers"`

	// PositionCorrelation contains position correlation settings
	PositionCorrelation PositionCorrelationConfig `yaml:"position_correlation"`

	// DocumentTypes contains document type-specific settings
	DocumentTypes map[string]DocumentTypeConfig `yaml:"document_types"`

	// DataTypes contains data type-specific settings
	DataTypes map[string]DataTypeConfig `yaml:"data_types"`

	// Security contains security-related settings
	Security SecurityConfig `yaml:"security"`

	// Observability contains observability settings
	Observability ObservabilityConfig `yaml:"observability"`
}

// PositionCorrelationConfig contains position correlation settings
type PositionCorrelationConfig struct {
	// Enabled indicates whether position correlation is enabled
	Enabled bool `yaml:"enabled"`

	// ConfidenceThreshold is the minimum confidence score for position mapping
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`

	// FuzzyMatching enables fuzzy matching for position correlation
	FuzzyMatching bool `yaml:"fuzzy_matching"`

	// ContextWindowSize is the size of the context window for position validation
	ContextWindowSize int `yaml:"context_window_size"`
}

// DocumentTypeConfig contains document type-specific redaction settings
type DocumentTypeConfig struct {
	// Enabled indicates whether redaction is enabled for this document type
	Enabled bool `yaml:"enabled"`

	// Strategy is the redaction strategy to use for this document type
	Strategy string `yaml:"strategy"`

	// TextRedaction enables text content redaction
	TextRedaction bool `yaml:"text_redaction"`

	// MetadataRedaction enables metadata redaction
	MetadataRedaction bool `yaml:"metadata_redaction"`

	// EmbeddedMedia enables embedded media redaction
	EmbeddedMedia bool `yaml:"embedded_media"`

	// PreserveStructure indicates whether to preserve document structure
	PreserveStructure bool `yaml:"preserve_structure"`

	// QualitySettings contains quality-related settings
	QualitySettings map[string]interface{} `yaml:"quality_settings"`
}

// DataTypeConfig contains data type-specific redaction settings
type DataTypeConfig struct {
	// Enabled indicates whether redaction is enabled for this data type
	Enabled bool `yaml:"enabled"`

	// Strategy is the redaction strategy to use for this data type
	Strategy string `yaml:"strategy"`

	// PreserveFormat indicates whether to preserve the original format
	PreserveFormat bool `yaml:"preserve_format"`

	// PreserveLength indicates whether to preserve the original length
	PreserveLength bool `yaml:"preserve_length"`

	// SyntheticOptions contains options for synthetic data generation
	SyntheticOptions map[string]interface{} `yaml:"synthetic_options"`

	// ValidationRules contains validation rules for this data type
	ValidationRules map[string]interface{} `yaml:"validation_rules"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	// MemoryScrubbing enables secure memory scrubbing
	MemoryScrubbing bool `yaml:"memory_scrubbing"`

	// AuditTrail enables audit trail generation
	AuditTrail bool `yaml:"audit_trail"`

	// SecureRandom uses cryptographically secure random number generation
	SecureRandom bool `yaml:"secure_random"`

	// AuditLogFile is the path to save the redaction audit log
	AuditLogFile string `yaml:"audit_log_file"`
}

// ObservabilityConfig contains observability settings
type ObservabilityConfig struct {
	// MetricsEnabled enables metrics collection
	MetricsEnabled bool `yaml:"metrics_enabled"`

	// DetailedLogging enables detailed debug logging
	DetailedLogging bool `yaml:"detailed_logging"`

	// PerformanceTracking enables performance tracking
	PerformanceTracking bool `yaml:"performance_tracking"`

	// ConfidenceTracking enables confidence score tracking
	ConfidenceTracking bool `yaml:"confidence_tracking"`
}

// NewDefaultRedactionConfig creates a new RedactionConfig with default values
func NewDefaultRedactionConfig() *RedactionConfig {
	return &RedactionConfig{
		Enabled:            false,
		OutputDirectory:    "./redacted",
		DefaultStrategy:    "format_preserving",
		ParallelProcessing: true,
		MaxWorkers:         4,
		PositionCorrelation: PositionCorrelationConfig{
			Enabled:             true,
			ConfidenceThreshold: 0.8,
			FuzzyMatching:       true,
			ContextWindowSize:   500,
		},
		DocumentTypes: map[string]DocumentTypeConfig{
			"pdf": {
				Enabled:           true,
				Strategy:          "format_preserving",
				TextRedaction:     true,
				MetadataRedaction: true,
				EmbeddedMedia:     true,
				PreserveStructure: true,
				QualitySettings:   make(map[string]interface{}),
			},
			"office": {
				Enabled:           true,
				Strategy:          "format_preserving",
				TextRedaction:     true,
				MetadataRedaction: true,
				EmbeddedMedia:     true,
				PreserveStructure: true,
				QualitySettings:   make(map[string]interface{}),
			},
			"image": {
				Enabled:           true,
				Strategy:          "simple",
				TextRedaction:     false,
				MetadataRedaction: true,
				EmbeddedMedia:     false,
				PreserveStructure: true,
				QualitySettings:   make(map[string]interface{}),
			},
			"text": {
				Enabled:           true,
				Strategy:          "format_preserving",
				TextRedaction:     true,
				MetadataRedaction: false,
				EmbeddedMedia:     false,
				PreserveStructure: true,
				QualitySettings:   make(map[string]interface{}),
			},
		},
		DataTypes: map[string]DataTypeConfig{
			"CREDIT_CARD": {
				Enabled:        true,
				Strategy:       "format_preserving",
				PreserveFormat: true,
				PreserveLength: true,
				SyntheticOptions: map[string]interface{}{
					"preserve_last_digits": 4,
				},
				ValidationRules: make(map[string]interface{}),
			},
			"SSN": {
				Enabled:        true,
				Strategy:       "synthetic",
				PreserveFormat: true,
				PreserveLength: true,
				SyntheticOptions: map[string]interface{}{
					"preserve_format": true,
				},
				ValidationRules: make(map[string]interface{}),
			},
			"EMAIL": {
				Enabled:        true,
				Strategy:       "synthetic",
				PreserveFormat: false,
				PreserveLength: false,
				SyntheticOptions: map[string]interface{}{
					"preserve_domain": false,
				},
				ValidationRules: make(map[string]interface{}),
			},
			"SECRETS": {
				Enabled:          true,
				Strategy:         "simple",
				PreserveFormat:   false,
				PreserveLength:   false,
				SyntheticOptions: make(map[string]interface{}),
				ValidationRules:  make(map[string]interface{}),
			},
		},
		Security: SecurityConfig{
			MemoryScrubbing: true,
			AuditTrail:      true,
			SecureRandom:    true,
		},
		Observability: ObservabilityConfig{
			MetricsEnabled:      true,
			DetailedLogging:     false,
			PerformanceTracking: true,
			ConfidenceTracking:  true,
		},
	}
}

// Validate validates the redaction configuration
func (rc *RedactionConfig) Validate() error {
	if rc.OutputDirectory == "" {
		return fmt.Errorf("output_directory cannot be empty")
	}

	// Validate output directory path
	if !filepath.IsAbs(rc.OutputDirectory) && !strings.HasPrefix(rc.OutputDirectory, "./") {
		return fmt.Errorf("output_directory must be an absolute path or start with './'")
	}

	// Validate default strategy
	strategy := ParseRedactionStrategy(rc.DefaultStrategy)
	if strategy.String() != rc.DefaultStrategy {
		return fmt.Errorf("invalid default_strategy: %s", rc.DefaultStrategy)
	}

	// Validate max workers
	if rc.MaxWorkers < 1 {
		return fmt.Errorf("max_workers must be at least 1")
	}

	// Validate position correlation settings
	if rc.PositionCorrelation.ConfidenceThreshold < 0 || rc.PositionCorrelation.ConfidenceThreshold > 1 {
		return fmt.Errorf("position_correlation.confidence_threshold must be between 0 and 1")
	}

	if rc.PositionCorrelation.ContextWindowSize < 0 {
		return fmt.Errorf("position_correlation.context_window_size must be non-negative")
	}

	// Validate document type configurations
	for docType, config := range rc.DocumentTypes {
		if err := rc.validateDocumentTypeConfig(docType, config); err != nil {
			return fmt.Errorf("document_types.%s: %w", docType, err)
		}
	}

	// Validate data type configurations
	for dataType, config := range rc.DataTypes {
		if err := rc.validateDataTypeConfig(dataType, config); err != nil {
			return fmt.Errorf("data_types.%s: %w", dataType, err)
		}
	}

	return nil
}

// validateDocumentTypeConfig validates a document type configuration
func (rc *RedactionConfig) validateDocumentTypeConfig(docType string, config DocumentTypeConfig) error {
	// Validate strategy
	strategy := ParseRedactionStrategy(config.Strategy)
	if strategy.String() != config.Strategy {
		return fmt.Errorf("invalid strategy: %s", config.Strategy)
	}

	// Validate that at least one redaction type is enabled if the document type is enabled
	if config.Enabled && !config.TextRedaction && !config.MetadataRedaction && !config.EmbeddedMedia {
		return fmt.Errorf("at least one redaction type must be enabled")
	}

	return nil
}

// validateDataTypeConfig validates a data type configuration
func (rc *RedactionConfig) validateDataTypeConfig(dataType string, config DataTypeConfig) error {
	// Validate strategy
	strategy := ParseRedactionStrategy(config.Strategy)
	if strategy.String() != config.Strategy {
		return fmt.Errorf("invalid strategy: %s", config.Strategy)
	}

	return nil
}

// GetDocumentTypeConfig returns the configuration for a specific document type
func (rc *RedactionConfig) GetDocumentTypeConfig(docType string) (DocumentTypeConfig, bool) {
	config, exists := rc.DocumentTypes[docType]
	return config, exists
}

// GetDataTypeConfig returns the configuration for a specific data type
func (rc *RedactionConfig) GetDataTypeConfig(dataType string) (DataTypeConfig, bool) {
	config, exists := rc.DataTypes[dataType]
	return config, exists
}

// IsDocumentTypeEnabled returns true if redaction is enabled for the specified document type
func (rc *RedactionConfig) IsDocumentTypeEnabled(docType string) bool {
	if !rc.Enabled {
		return false
	}

	config, exists := rc.GetDocumentTypeConfig(docType)
	if !exists {
		return false
	}

	return config.Enabled
}

// IsDataTypeEnabled returns true if redaction is enabled for the specified data type
func (rc *RedactionConfig) IsDataTypeEnabled(dataType string) bool {
	if !rc.Enabled {
		return false
	}

	config, exists := rc.GetDataTypeConfig(dataType)
	if !exists {
		return false
	}

	return config.Enabled
}

// GetStrategyForDataType returns the redaction strategy for a specific data type
func (rc *RedactionConfig) GetStrategyForDataType(dataType string) RedactionStrategy {
	config, exists := rc.GetDataTypeConfig(dataType)
	if !exists {
		return ParseRedactionStrategy(rc.DefaultStrategy)
	}

	return ParseRedactionStrategy(config.Strategy)
}
