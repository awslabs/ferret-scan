// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
)

// collectDisabledDetectionTypes asks each configured validator which detection sub-types config
// switched off, and which `disabled_types` entries matched nothing. It is core.DisabledDetectionTypes,
// which carries the reasoning: the VALIDATORS are asked, never the YAML.
//
// The implementation moved to core so that core.ScanContent can answer the same question for the
// validators it builds; the --stdin path reads that answer off the ScanResult, and this file path reads
// it off its own set, so the two cannot disagree about one configuration (#887).
func collectDisabledDetectionTypes(validators map[string]detector.Validator) (disabled, unrecognised map[string][]string) {
	return core.DisabledDetectionTypes(validators)
}

// reportDisabledDetectionTypes writes the coverage disclosure for narrowed detection.
//
// Deliberately NOT gated on --quiet, on non-interactive output, or on pre-commit mode, for the
// reason TM-13 gives for reportConfigProvenance: this is a statement about what governed the scan,
// not progress output, and pre-commit is exactly where a silenced disclosure matters most —
// IsPrecommitEnvironment() is true from environment variables alone, so it takes no flag to
// suppress. Writes to stderr and does not change the exit code.
//
// Two separate messages, because they are opposite failures and want opposite remedies:
// something the operator asked to switch off and IS off (coverage is narrower than it looks), and
// something they asked to switch off that is STILL ON (their config did not take effect).
func reportDisabledDetectionTypes(w io.Writer, disabled, unrecognised map[string][]string) {
	for _, name := range sortedKeys(disabled) {
		fmt.Fprintf(w, "Note: config disabled %d %s detection sub-type(s) for this scan: %s. "+
			"Findings of those sub-types are not reported.\n",
			len(disabled[name]), name, strings.Join(disabled[name], ", "))
	}
	for _, name := range sortedKeys(unrecognised) {
		fmt.Fprintf(w, "Warning: config asked to disable %s sub-type(s) %s, which name nothing this "+
			"validator detects — they had NO effect and detection is still running. Valid values: %s.\n",
			name, strings.Join(unrecognised[name], ", "),
			strings.Join(intellectualproperty.RecognisedSubTypes(), ", "))
	}
}

// sortedKeys keeps both messages in a fixed order. Map iteration is randomized, and a disclosure
// whose lines reorder between runs of an unchanged scan reads as a change that did not happen.
func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
