// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// Properties is the standard JUnit <properties> element: name/value pairs describing a suite.
type Properties struct {
	Property []Property `xml:"property"`
}

// Property is one <property name="..." value="..."/>. Both attributes are required by the XSD, so
// an empty list is written as value="" rather than omitted.
type Property struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// scopePropertyPrefix namespaces every key, so a CI system that merges properties from several
// tools' reports cannot confuse ours with theirs.
const scopePropertyPrefix = "ferret-scan."

// buildScopeProperties renders the scope of a NARROWED run as the security-scan suite's properties,
// or returns nil for a run that ran in full, so its report keeps every byte (#904).
//
// JUnit had no in-band signal of narrowing at all, not even the disabled sub-types json, yaml and
// sarif disclose (#623): `--checks SSN` over a file holding an email address gave tests="0"
// failures="0", the document a clean full scan writes.
//
// Lists are comma-joined in sorted order, and a fixed key order, so two reports of one unchanged
// scan compare equal.
func buildScopeProperties(options formatters.FormatterOptions) *Properties {
	s := options.Scan
	if s == nil {
		return nil
	}
	props := []Property{
		{Name: "checks_run", Value: strings.Join(s.ChecksRun, ",")},
		{Name: "checks_not_run", Value: strings.Join(s.ChecksNotRun, ",")},
	}
	if len(s.ChecksNotApplicable) > 0 {
		props = append(props, Property{Name: "checks_not_applicable", Value: strings.Join(s.ChecksNotApplicable, ",")})
	}
	props = append(props, Property{Name: "confidence_levels", Value: strings.Join(s.ConfidenceLevels, ",")})
	if s.Profile != nil {
		props = append(props,
			Property{Name: "profile", Value: s.Profile.Name},
			Property{Name: "profile_selected_by", Value: s.Profile.SelectedBy})
	}
	props = append(props, Property{Name: "config_source", Value: s.Config.Source})
	if s.Config.Name != "" {
		props = append(props, Property{Name: "config_name", Value: s.Config.Name})
	}
	props = append(props, Property{Name: "suppression_rules_enabled", Value: strconv.Itoa(s.Suppressions.RulesEnabled)})
	if options.Stats != nil {
		props = append(props, Property{Name: "suppressed", Value: strconv.Itoa(options.Stats.Suppressed)})
	}
	if pairs := s.DisabledTypePairs(); len(pairs) > 0 {
		props = append(props, Property{Name: "disabled_detection_types", Value: strings.Join(pairs, ",")})
	}
	if s.Tool != nil {
		props = append(props,
			Property{Name: "version", Value: s.Tool.Version},
			Property{Name: "commit", Value: s.Tool.Commit})
	}
	for i := range props {
		props[i].Name = scopePropertyPrefix + props[i].Name
	}
	return &Properties{Property: props}
}
