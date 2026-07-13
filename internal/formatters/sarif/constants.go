// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import "github.com/awslabs/ferret-scan/v2/internal/core"

// SARIF specification constants
const (
	// SARIFSchemaURL is the URL to the SARIF 2.1.0 JSON schema
	SARIFSchemaURL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/refs/heads/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

	// SARIFVersion is the SARIF specification version
	SARIFVersion = "2.1.0"
)

// Tool metadata constants
const (
	// ToolName is the name of the ferret-scan tool
	ToolName = "Ferret Scan"

	// ToolInformationURI is the URL to the ferret-scan repository
	ToolInformationURI = "https://github.com/awslabs/ferret-scan"
)

// SARIF level constants
const (
	// LevelError indicates a serious issue that should be addressed
	LevelError = "error"

	// LevelWarning indicates a potential issue
	LevelWarning = "warning"

	// LevelNote indicates an informational message
	LevelNote = "note"

	// LevelNone indicates a suppressed result
	LevelNone = "none"
)

// SARIF suppression kind constants
const (
	// SuppressionKindInSource indicates the suppression is defined in source code
	SuppressionKindInSource = "inSource"

	// SuppressionKindExternal indicates the suppression is defined externally
	SuppressionKindExternal = "external"
)

// RuleDescription contains the description information for a detection rule
type RuleDescription struct {
	Short string
	Full  string
	Help  string
}

// GetRuleDescription returns the rule description for a given detection type.
// Descriptions are sourced from the central type-metadata registry
// (core.TypeMeta, the single source of truth — v2 gap 3.3); when a type has no
// SARIF description there, the generic fallback below is used (unchanged
// behavior: every sub-type that lacked an entry before still gets the generic
// description now).
func GetRuleDescription(detectionType string) RuleDescription {
	if d, ok := core.TypeMeta(detectionType); ok && d.SARIFShort != "" {
		return RuleDescription{Short: d.SARIFShort, Full: d.SARIFFull, Help: d.SARIFHelp}
	}

	// Return generic description for unknown types
	return RuleDescription{
		Short: detectionType + " Detected",
		Full:  "Sensitive data of type " + detectionType + " was detected in the scanned content.",
		Help:  "Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.",
	}
}
