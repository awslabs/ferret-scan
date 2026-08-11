// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

// SARIFReport represents the top-level SARIF document structure
// conforming to SARIF 2.1.0 specification
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run
type SARIFRun struct {
	Tool                     SARIFTool             `json:"tool"`
	Results                  []SARIFResult         `json:"results"`
	VersionControlProvenance []SARIFVersionControl `json:"versionControlProvenance,omitempty"`

	// Invocations carries the not-examined disclosure. omitempty, so a scan that
	// examined every file emits nothing new and existing consumers see no change.
	Invocations []SARIFInvocation `json:"invocations,omitempty"`

	// Properties carries run-level metadata. It is currently used for one thing:
	// declaring that --limit truncated the results, and what the true total was.
	//
	// A consumer reading `results` has no way to tell a complete report from a
	// truncated one, and SARIF has no standard field for "this is a partial
	// result set". The properties bag is the spec's designated place for
	// tool-specific metadata, so it is where the disclosure goes rather than
	// inventing a non-standard top-level key that would fail schema validation.
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFVersionControl represents version control information
type SARIFVersionControl struct {
	RepositoryURI string         `json:"repositoryUri"`
	RevisionID    string         `json:"revisionId,omitempty"`
	Branch        string         `json:"branch,omitempty"`
	MappedTo      *SARIFMappedTo `json:"mappedTo,omitempty"`
}

// SARIFMappedTo represents the mapping of repository root to a URI base ID
type SARIFMappedTo struct {
	URIBaseID string `json:"uriBaseId"`
}

// SARIFTool represents the analysis tool that produced the results
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver information
type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []SARIFRule `json:"rules,omitempty"`

	// Notifications declares the descriptors that toolExecutionNotifications refer
	// to. A notification's descriptor is a reference, so without the descriptor
	// declared here the reference dangles.
	//
	// uniqueItems is true on this array in the schema, so a descriptor must be
	// emitted at most once no matter how many notifications cite it.
	Notifications []SARIFRule `json:"notifications,omitempty"`
}

// SARIFInvocation describes the tool run itself.
//
// Added to carry the not-examined disclosure through toolExecutionNotifications,
// whose spec description IS this semantics: "runtime conditions detected by the tool
// during the analysis". No other slot fits — run.additionalProperties is false in
// SARIF 2.1.0, so a bespoke run-level key is not merely non-standard but INVALID,
// and expressing it as a result would manufacture dismissable "PII alerts" in
// GitHub's UI for files that were never read.
//
// ExecutionSuccessful has no omitempty and is deliberately always true: it is the
// object's only REQUIRED member per the schema, and false tells consumers the
// analysis failed, which may cause them to discard the results. The scan succeeded;
// its COVERAGE was incomplete. Those are different claims.
type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification is one runtime condition detected during the run.
//
// Exactly {descriptor, level, message} — notification.additionalProperties IS false
// in the 2.1.0 schema (verified against the OASIS schema), so any extra key makes
// the whole document invalid. That is the opposite of GitLab's scan.messages, which
// leaves additionalProperties open; the two must not share a struct.
//
// Per-file paths ride in the message text rather than in locations[], because
// SARIFLocation embeds a non-pointer Region whose StartLine lacks omitempty and
// would therefore serialise startLine:0 against the schema's minimum of 1.
type SARIFNotification struct {
	Descriptor *SARIFReportingDescriptorRef `json:"descriptor,omitempty"`
	// Level must be one of none/note/warning/error. NOTE: "warning", not "warn" —
	// GitLab's enum uses "warn" and the two are not interchangeable.
	Level   string       `json:"level,omitempty"`
	Message SARIFMessage `json:"message"`
}

// SARIFReportingDescriptorRef points a notification at its descriptor in
// tool.driver.notifications.
type SARIFReportingDescriptorRef struct {
	ID string `json:"id"`
}

// SARIFRule represents a reporting descriptor for a rule
type SARIFRule struct {
	ID               string                 `json:"id"`
	ShortDescription SARIFMessage           `json:"shortDescription"`
	FullDescription  SARIFMessage           `json:"fullDescription,omitempty"`
	Help             SARIFMessage           `json:"help,omitempty"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

// SARIFResult represents a single result (finding) from the analysis
type SARIFResult struct {
	RuleID       string                 `json:"ruleId"`
	Level        string                 `json:"level"`
	Message      SARIFMessage           `json:"message"`
	Locations    []SARIFLocation        `json:"locations,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
	Suppressions []SARIFSuppression     `json:"suppressions,omitempty"`
	Rank         float64                `json:"rank,omitempty"`
}

// SARIFLocation represents the location of a result
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation represents a physical location in a file
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
	ContextRegion    *SARIFRegion          `json:"contextRegion,omitempty"`
}

// SARIFArtifactLocation represents the location of an artifact (file)
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion represents a region within a file
type SARIFRegion struct {
	StartLine   int           `json:"startLine"`
	StartColumn int           `json:"startColumn,omitempty"`
	EndLine     int           `json:"endLine,omitempty"`
	EndColumn   int           `json:"endColumn,omitempty"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

// SARIFSnippet represents a snippet of text from a file
type SARIFSnippet struct {
	Text string `json:"text"`
}

// SARIFMessage represents a message string
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFSuppression represents information about a suppressed result
type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}
