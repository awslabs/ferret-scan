// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
)

// collectDisabledDetectionTypes asks each configured validator which detection sub-types config
// switched off, and which `disabled_types` entries matched nothing.
//
// It asks the VALIDATORS rather than re-reading config, and that is the whole design. Only the
// intellectual-property validator honours `disabled_types`; the key is inert under any other
// validator's section. A config-derived disclosure would therefore announce reduced coverage that
// did not happen, and a disclosure naming a cause that did not occur sends the operator to fix the
// wrong thing — the same failure as a true disclosure under a false heading.
//
// Only validators actually in the run are present in the map, so a `disabled_types` block for a
// validator excluded by --checks is correctly silent: nothing was disabled because nothing ran.
//
// Both maps are keyed by the check name the operator would type in --checks, not by the config
// section name, because the disclosure is read alongside the flags rather than alongside the YAML.
func collectDisabledDetectionTypes(validators map[string]detector.Validator) (disabled, unrecognised map[string][]string) {
	for name, v := range validators {
		ip, ok := v.(*intellectualproperty.Validator)
		if !ok {
			continue
		}
		if off := ip.DisabledSubTypes(); len(off) > 0 {
			if disabled == nil {
				disabled = make(map[string][]string)
			}
			disabled[name] = off
		}
		if bad := ip.UnrecognisedDisabledSubTypes(); len(bad) > 0 {
			if unrecognised == nil {
				unrecognised = make(map[string][]string)
			}
			unrecognised[name] = bad
		}
	}
	return disabled, unrecognised
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
