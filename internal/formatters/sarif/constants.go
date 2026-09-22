// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

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

	// ToolInformationURI is the URL to the ferret-scan repository. Kept as a named
	// constant so existing references stay valid; the value lives in internal/version.
	ToolInformationURI = version.RepositoryURL
)

// srcRootBaseID is the symbolic name for the scan root, used both as every result's
// artifactLocation.uriBaseId and as the single key of run.originalUriBaseIds that defines it.
//
// %SRCROOT% is the conventional spelling — SARIF 2.1.0's own examples use it and GitHub code
// scanning recognises it — and the two sites MUST agree, which is why it is one constant: the
// mapper emitted the literal while nothing defined it, and a uriBaseId with no matching
// originalUriBaseIds key is unresolvable (#711).
const srcRootBaseID = "%SRCROOT%"

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
	// core.DescribeType, not core.TypeMeta: the registry is keyed by SUB-TYPE but was populated at
	// validator level, so 49 of 64 types reached the generic fallback below while carefully written
	// copy sat on family keys no finding ever carries. DescribeType resolves a sub-type to its family
	// per field, which takes SARIF coverage to 64 of 64 (#662).
	if d := core.DescribeType(detectionType); d.SARIFShort != "" {
		return RuleDescription{Short: d.SARIFShort, Full: d.SARIFFull, Help: d.SARIFHelp}
	}

	// Return generic description for unknown types
	return RuleDescription{
		Short: detectionType + " Detected",
		Full:  "Sensitive data of type " + detectionType + " was detected in the scanned content.",
		Help:  "Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.",
	}
}
