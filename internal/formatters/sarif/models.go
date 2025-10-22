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
}

// SARIFVersionControl represents version control information
type SARIFVersionControl struct {
	RepositoryURI string          `json:"repositoryUri"`
	RevisionID    string          `json:"revisionId,omitempty"`
	Branch        string          `json:"branch,omitempty"`
	MappedTo      *SARIFMappedTo  `json:"mappedTo,omitempty"`
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
