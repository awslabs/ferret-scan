// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Note: SchemaValidatorInterface is defined in formatter.go to avoid redeclaration

// SchemaValidator provides GitLab SAST report schema validation
type SchemaValidator struct {
	supportedVersions map[string]bool
	strictMode        bool
}

// NewSchemaValidator creates a new schema validator with default configuration
func NewSchemaValidator() *SchemaValidator {
	return &SchemaValidator{
		supportedVersions: map[string]bool{
			"15.0.4": true,
			"15.0.3": true,
			"15.0.2": true,
			"15.0.1": true,
			"15.0.0": true,
		},
		strictMode: false,
	}
}

// NewStrictSchemaValidator creates a new schema validator in strict mode
func NewStrictSchemaValidator() *SchemaValidator {
	validator := NewSchemaValidator()
	validator.strictMode = true
	return validator
}

// ValidateReport performs comprehensive validation of a GitLab security report
func (v *SchemaValidator) ValidateReport(report *GitLabSecurityReport) error {
	if report == nil {
		return NewSchemaValidationError("report cannot be nil")
	}

	// Validate schema version
	if err := v.ValidateSchemaVersion(report.Version); err != nil {
		return fmt.Errorf("schema version validation failed: %w", err)
	}

	// Validate required fields
	if err := v.ValidateRequiredFields(report); err != nil {
		return fmt.Errorf("required fields validation failed: %w", err)
	}

	// Validate field formats
	if err := v.ValidateFieldFormats(report); err != nil {
		return fmt.Errorf("field format validation failed: %w", err)
	}

	// Validate using built-in model validation
	if err := report.Validate(); err != nil {
		return fmt.Errorf("model validation failed: %w", err)
	}

	// Validate JSON serialization
	if err := v.validateJSONSerialization(report); err != nil {
		return fmt.Errorf("JSON serialization validation failed: %w", err)
	}

	return nil
}

// ValidateVulnerability validates a single vulnerability according to GitLab schema
func (v *SchemaValidator) ValidateVulnerability(vuln *GitLabVulnerability) error {
	if vuln == nil {
		return NewSchemaValidationError("vulnerability cannot be nil")
	}

	// Validate required fields
	if err := v.validateVulnerabilityRequiredFields(vuln); err != nil {
		return fmt.Errorf("required fields validation failed: %w", err)
	}

	// Validate field formats
	if err := v.validateVulnerabilityFormats(vuln, 0); err != nil {
		return fmt.Errorf("field format validation failed: %w", err)
	}

	// Validate using built-in model validation
	if err := vuln.Validate(); err != nil {
		return fmt.Errorf("model validation failed: %w", err)
	}

	return nil
}

// IsValidSeverity checks if the given severity is valid according to GitLab schema
func (v *SchemaValidator) IsValidSeverity(severity string) bool {
	validSeverities := map[string]bool{
		"Critical": true,
		"High":     true,
		"Medium":   true,
		"Low":      true,
		"Info":     true,
	}
	return validSeverities[severity]
}

// ValidateSchemaVersion validates the GitLab schema version
func (v *SchemaValidator) ValidateSchemaVersion(version string) error {
	if version == "" {
		return NewSchemaValidationError("schema version is required")
	}

	if !v.IsCompatibleVersion(version) {
		if v.strictMode {
			return NewSchemaValidationError("unsupported schema version: %s", version)
		}
		// In non-strict mode, just warn about unknown versions
		if !isValidVersionFormat(version) {
			return NewSchemaValidationError("invalid version format: %s", version)
		}
	}

	return nil
}

// ValidateRequiredFields validates that all required fields are present
func (v *SchemaValidator) ValidateRequiredFields(report *GitLabSecurityReport) error {
	var errorList []string

	// Top-level required fields
	if report.Version == "" {
		errorList = append(errorList, "version is required")
	}

	if report.Vulnerabilities == nil {
		errorList = append(errorList, "vulnerabilities array is required")
	}

	if report.Remediations == nil {
		errorList = append(errorList, "remediations array is required")
	}

	// Validate scan info required fields
	if err := v.validateScanRequiredFields(&report.Scan); err != nil {
		errorList = append(errorList, fmt.Sprintf("scan: %v", err))
	}

	// Validate vulnerability required fields
	for i, vuln := range report.Vulnerabilities {
		if err := v.validateVulnerabilityRequiredFields(&vuln); err != nil {
			errorList = append(errorList, fmt.Sprintf("vulnerability[%d]: %v", i, err))
		}
	}

	if len(errorList) > 0 {
		return NewSchemaValidationError("required field validation failed: %s", strings.Join(errorList, "; "))
	}

	return nil
}

// ValidateFieldFormats validates the format of fields according to GitLab schema
func (v *SchemaValidator) ValidateFieldFormats(report *GitLabSecurityReport) error {
	var errorList []string

	// Validate vulnerability field formats
	for i, vuln := range report.Vulnerabilities {
		if err := v.validateVulnerabilityFormats(&vuln, i); err != nil {
			errorList = append(errorList, err.Error())
		}
	}

	// Validate scan field formats
	if err := v.validateScanFormats(&report.Scan); err != nil {
		errorList = append(errorList, fmt.Sprintf("scan: %v", err))
	}

	if len(errorList) > 0 {
		return NewSchemaValidationError("field format validation failed: %s", strings.Join(errorList, "; "))
	}

	return nil
}

// IsCompatibleVersion checks if the given version is supported
func (v *SchemaValidator) IsCompatibleVersion(version string) bool {
	return v.supportedVersions[version]
}

// validateScanRequiredFields validates required fields in scan info
func (v *SchemaValidator) validateScanRequiredFields(scan *GitLabScanInfo) error {
	var errorList []string

	if scan.Type == "" {
		errorList = append(errorList, "type is required")
	}

	if scan.Status == "" {
		errorList = append(errorList, "status is required")
	}

	if scan.Analyzer.ID == "" {
		errorList = append(errorList, "analyzer.id is required")
	}

	if scan.Analyzer.Name == "" {
		errorList = append(errorList, "analyzer.name is required")
	}

	if scan.Analyzer.Version == "" {
		errorList = append(errorList, "analyzer.version is required")
	}

	if scan.Analyzer.Vendor.Name == "" {
		errorList = append(errorList, "analyzer.vendor.name is required")
	}

	if scan.Scanner.ID == "" {
		errorList = append(errorList, "scanner.id is required")
	}

	if scan.Scanner.Name == "" {
		errorList = append(errorList, "scanner.name is required")
	}

	if scan.Scanner.Version == "" {
		errorList = append(errorList, "scanner.version is required")
	}

	if scan.Scanner.Vendor.Name == "" {
		errorList = append(errorList, "scanner.vendor.name is required")
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateVulnerabilityRequiredFields validates required fields in vulnerability
func (v *SchemaValidator) validateVulnerabilityRequiredFields(vuln *GitLabVulnerability) error {
	var errorList []string

	if vuln.ID == "" {
		errorList = append(errorList, "id is required")
	}

	if vuln.Category == "" {
		errorList = append(errorList, "category is required")
	}

	if vuln.Name == "" {
		errorList = append(errorList, "name is required")
	}

	if vuln.Message == "" {
		errorList = append(errorList, "message is required")
	}

	if vuln.Severity == "" {
		errorList = append(errorList, "severity is required")
	}

	if vuln.Location.File == "" {
		errorList = append(errorList, "location.file is required")
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateVulnerabilityFormats validates vulnerability field formats
func (v *SchemaValidator) validateVulnerabilityFormats(vuln *GitLabVulnerability, index int) error {
	var errorList []string

	// Validate ID format (should be unique and non-empty)
	if err := v.validateVulnerabilityID(vuln.ID); err != nil {
		errorList = append(errorList, fmt.Sprintf("vulnerability[%d].id: %v", index, err))
	}

	// Validate category format
	if err := v.validateCategory(vuln.Category); err != nil {
		errorList = append(errorList, fmt.Sprintf("vulnerability[%d].category: %v", index, err))
	}

	// Validate severity format
	if err := v.validateSeverity(vuln.Severity); err != nil {
		errorList = append(errorList, fmt.Sprintf("vulnerability[%d].severity: %v", index, err))
	}

	// Validate confidence format (if present)
	if vuln.Confidence != "" {
		if err := v.validateConfidence(vuln.Confidence); err != nil {
			errorList = append(errorList, fmt.Sprintf("vulnerability[%d].confidence: %v", index, err))
		}
	}

	// Validate location format
	if err := v.validateLocation(&vuln.Location); err != nil {
		errorList = append(errorList, fmt.Sprintf("vulnerability[%d].location: %v", index, err))
	}

	// Validate identifiers format
	for i, identifier := range vuln.Identifiers {
		if err := v.validateIdentifier(&identifier); err != nil {
			errorList = append(errorList, fmt.Sprintf("vulnerability[%d].identifiers[%d]: %v", index, i, err))
		}
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateScanFormats validates scan field formats
func (v *SchemaValidator) validateScanFormats(scan *GitLabScanInfo) error {
	var errorList []string

	// Validate scan type
	if scan.Type != "sast" {
		errorList = append(errorList, "type must be 'sast' for SAST reports")
	}

	// Validate scan status
	validStatuses := map[string]bool{
		"success": true,
		"failure": true,
	}
	if !validStatuses[scan.Status] {
		errorList = append(errorList, fmt.Sprintf("invalid status: %s (must be 'success' or 'failure')", scan.Status))
	}

	// Validate timestamp formats (if present)
	if scan.StartTime != "" {
		if err := v.validateTimestamp(scan.StartTime); err != nil {
			errorList = append(errorList, fmt.Sprintf("start_time: %v", err))
		}
	}

	if scan.EndTime != "" {
		if err := v.validateTimestamp(scan.EndTime); err != nil {
			errorList = append(errorList, fmt.Sprintf("end_time: %v", err))
		}
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateVulnerabilityID validates vulnerability ID format
func (v *SchemaValidator) validateVulnerabilityID(id string) error {
	if id == "" {
		return fmt.Errorf("ID cannot be empty")
	}

	// GitLab recommends IDs to be unique and descriptive
	// We allow alphanumeric characters, hyphens, and underscores
	validIDPattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !validIDPattern.MatchString(id) {
		return fmt.Errorf("ID contains invalid characters: %s", id)
	}

	if len(id) > 255 {
		return fmt.Errorf("ID too long (max 255 characters): %d", len(id))
	}

	return nil
}

// validateCategory validates vulnerability category
func (v *SchemaValidator) validateCategory(category string) error {
	// For SAST reports, category should typically be "sast"
	// But we allow other categories for flexibility
	if category == "" {
		return fmt.Errorf("category cannot be empty")
	}

	validCategories := map[string]bool{
		"sast":                    true,
		"dependency_scanning":     true,
		"container_scanning":      true,
		"dast":                    true,
		"secret_detection":        true,
		"license_scanning":        true,
		"infrastructure_scanning": true,
	}

	if v.strictMode && !validCategories[category] {
		return fmt.Errorf("invalid category: %s", category)
	}

	return nil
}

// validateSeverity validates vulnerability severity
func (v *SchemaValidator) validateSeverity(severity string) error {
	validSeverities := map[string]bool{
		"Critical": true,
		"High":     true,
		"Medium":   true,
		"Low":      true,
		"Info":     true,
	}

	if !validSeverities[severity] {
		return fmt.Errorf("invalid severity: %s (must be Critical, High, Medium, Low, or Info)", severity)
	}

	return nil
}

// validateConfidence validates vulnerability confidence
func (v *SchemaValidator) validateConfidence(confidence string) error {
	validConfidences := map[string]bool{
		"High":      true,
		"Medium":    true,
		"Low":       true,
		"Unknown":   true,
		"Ignore":    true,
		"Confirmed": true,
		"Tentative": true,
	}

	if !validConfidences[confidence] {
		return fmt.Errorf("invalid confidence: %s", confidence)
	}

	return nil
}

// validateLocation validates vulnerability location
func (v *SchemaValidator) validateLocation(location *GitLabLocation) error {
	var errorList []string

	if location.File == "" {
		errorList = append(errorList, "file is required")
	}

	if location.StartLine < 1 {
		errorList = append(errorList, "start_line must be >= 1")
	}

	if location.EndLine < location.StartLine {
		errorList = append(errorList, "end_line must be >= start_line")
	}

	// Validate file path format (basic validation)
	if strings.Contains(location.File, "..") {
		errorList = append(errorList, "file path cannot contain '..'")
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateIdentifier validates vulnerability identifier
func (v *SchemaValidator) validateIdentifier(identifier *GitLabIdentifier) error {
	var errorList []string

	if identifier.Type == "" {
		errorList = append(errorList, "type is required")
	}

	if identifier.Name == "" {
		errorList = append(errorList, "name is required")
	}

	if identifier.Value == "" {
		errorList = append(errorList, "value is required")
	}

	// Validate URL format if present
	if identifier.URL != "" {
		if !strings.HasPrefix(identifier.URL, "http://") && !strings.HasPrefix(identifier.URL, "https://") {
			errorList = append(errorList, "URL must start with http:// or https://")
		}
	}

	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "; "))
	}

	return nil
}

// validateTimestamp validates timestamp format (GitLab schema format)
func (v *SchemaValidator) validateTimestamp(timestamp string) error {
	// GitLab schema expects format: YYYY-MM-DDTHH:MM:SS (no timezone)
	gitlabPattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$`)
	if !gitlabPattern.MatchString(timestamp) {
		return fmt.Errorf("invalid timestamp format (must be YYYY-MM-DDTHH:MM:SS): %s", timestamp)
	}

	return nil
}

// validateJSONSerialization validates that the report can be serialized to valid JSON
func (v *SchemaValidator) validateJSONSerialization(report *GitLabSecurityReport) error {
	_, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("report cannot be serialized to JSON: %w", err)
	}

	return nil
}

// isValidVersionFormat validates version format (semantic versioning)
func isValidVersionFormat(version string) bool {
	// Basic semantic version pattern: major.minor.patch
	versionPattern := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	return versionPattern.MatchString(version)
}

// SchemaValidationError represents detailed schema validation errors
type SchemaValidationError struct {
	Message string
	Field   string
	Value   interface{}
	Context map[string]interface{}
}

// NewSchemaValidationError creates a new schema validation error
func NewSchemaValidationError(format string, args ...interface{}) *SchemaValidationError {
	return &SchemaValidationError{
		Message: fmt.Sprintf(format, args...),
		Context: make(map[string]interface{}),
	}
}

// WithField adds field context to the validation error
func (e *SchemaValidationError) WithField(field string) *SchemaValidationError {
	e.Field = field
	return e
}

// WithValue adds value context to the validation error
func (e *SchemaValidationError) WithValue(value interface{}) *SchemaValidationError {
	e.Value = value
	return e
}

// WithContext adds additional context to the validation error
func (e *SchemaValidationError) WithContext(key string, value interface{}) *SchemaValidationError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// Error implements the error interface
func (e *SchemaValidationError) Error() string {
	msg := fmt.Sprintf("schema validation error: %s", e.Message)

	if e.Field != "" {
		msg += fmt.Sprintf(" (field: %s)", e.Field)
	}

	if e.Value != nil {
		msg += fmt.Sprintf(" (value: %v)", e.Value)
	}

	return msg
}

// GetDetails returns detailed error information
func (e *SchemaValidationError) GetDetails() map[string]interface{} {
	details := make(map[string]interface{})
	details["message"] = e.Message

	if e.Field != "" {
		details["field"] = e.Field
	}

	if e.Value != nil {
		details["value"] = e.Value
	}

	if len(e.Context) > 0 {
		details["context"] = e.Context
	}

	return details
}
