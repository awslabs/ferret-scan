// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import "sort"

// recognisedSubTypes is every IP sub-type `disabled_types` can switch off.
//
// Four of them are the pattern names in ValidateContent's ipPatterns slice; the fifth,
// internal_url, is consulted separately. That split is why this list exists as one exported
// thing: the two call sites are 90 lines apart and a sixth sub-type added to one of them would
// otherwise be silently un-disclosable. TestRecognisedSubTypesCoversEveryLookup pins it.
//
// Config is NOT validated against this list when it is parsed — Configure lowercases and stores
// whatever it is given. So a typo'd entry disables nothing, which is the opposite of what the
// operator asked for and was previously silent in every output. See UnrecognisedDisabledSubTypes.
var recognisedSubTypes = []string{
	"copyright",
	"internal_url",
	"patent",
	"trade_secret",
	"trademark",
}

// RecognisedSubTypes returns the sub-type names `disabled_types` understands, sorted.
//
// Returns a copy: the caller is in another package and a shared slice would let it reorder the
// determinism this validator depends on.
func RecognisedSubTypes() []string {
	out := make([]string, len(recognisedSubTypes))
	copy(out, recognisedSubTypes)
	return out
}

// DisabledSubTypes reports which recognised sub-types this configured validator will NOT detect,
// sorted.
//
// This is the validator speaking about its own behaviour rather than the caller re-reading config,
// and that distinction is the point. `disabled_types` is honoured by THIS validator only, so a
// caller that derived the disclosure from config alone would announce reduced coverage for any
// validator whose section happened to carry the key — a disclosure that names a cause that did not
// occur is worse than none, because it sends the operator to fix the wrong thing.
func (v *Validator) DisabledSubTypes() []string {
	var out []string
	for _, name := range recognisedSubTypes {
		if v.disabledTypes[name] {
			out = append(out, name)
		}
	}
	return out
}

// UnrecognisedDisabledSubTypes reports `disabled_types` entries that name nothing this validator
// detects, sorted.
//
// These are inert: the operator asked for detection to be switched off and it stayed ON. Measured
// on the parent commit, a copyright notice with `disabled_types: [copyrite]`:
//
//	disabled_types: [copyright]   0 findings, rc 0, no mention of the disabling
//	disabled_types: [copyrite]    1 finding,  rc 0, no mention of the typo
//
// Both silent, in opposite directions. warnUnknownConfigKeys does not cover this: the KEY
// `disabled_types` is spelled correctly, so nothing was looking at its values.
func (v *Validator) UnrecognisedDisabledSubTypes() []string {
	known := make(map[string]bool, len(recognisedSubTypes))
	for _, name := range recognisedSubTypes {
		known[name] = true
	}

	var out []string
	for name := range v.disabledTypes {
		if !known[name] {
			out = append(out, name)
		}
	}
	// Sorted because it comes from a map, and an unsorted disclosure would vary run to run.
	sort.Strings(out)
	return out
}
