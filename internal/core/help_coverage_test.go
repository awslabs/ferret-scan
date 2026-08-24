// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/help"
)

// `ferret-scan --help checks` and `--help <check_name>` are built by registering every
// validator that implements help.Provider (cmd/main.go), keyed by lower-cased check name.
// Registration is a type assertion, so a validator that stops satisfying the interface does not
// fail to compile — it silently disappears from the checks list and from its own help page,
// with no test noticing.
//
// internal/help/help_order_test.go cannot catch that: it builds fakeProvider values, so it
// tests the ORDERING of whatever it is handed rather than whether the real validators are all
// there. This is the coverage gate, and it derives its expectations from
// validatorConstructors — the documented single source of truth for which validators exist —
// so adding a validator without help fails here rather than shipping a blank page.

func TestEveryValidatorProvidesHelp(t *testing.T) {
	for _, name := range CheckNames() {
		t.Run(name, func(t *testing.T) {
			validators := BuildValidatorSet(map[string]bool{name: true}, nil, nil)
			v, ok := validators[name]
			if !ok {
				t.Fatalf("BuildValidatorSet did not construct %q, so its help cannot be checked", name)
			}

			provider, ok := v.(help.Provider)
			if !ok {
				t.Fatalf("%q does not implement help.Provider, so it is absent from "+
					"`--help checks` and has no `--help %s` page", name, strings.ToLower(name))
			}

			info := provider.GetCheckInfo()

			// The name is the lookup key. A mismatch means `--help <name>` finds nothing even
			// though the provider is registered, because registration keys on info.Name.
			if info.Name != name {
				t.Errorf("GetCheckInfo().Name = %q, want %q: help is registered under the "+
					"value from GetCheckInfo, so a mismatch makes the page unreachable",
					info.Name, name)
			}

			// The checks list prints ShortDescription against each name; an empty one renders
			// a name with a blank column.
			if strings.TrimSpace(info.ShortDescription) == "" {
				t.Errorf("%q has no ShortDescription, so `--help checks` lists it blank", name)
			}
			if strings.TrimSpace(info.DetailedDescription) == "" {
				t.Errorf("%q has no DetailedDescription, so its help page is empty", name)
			}
		})
	}
}

// TestHelpDoesNotLeakInternalNotes keeps developer notes out of user-facing output. `--help
// person_name` printed a raw "// TODO: Document rationale for surname database reduction ..."
// line to users, because the marker sat inside the DetailedDescription string rather than in a
// Go comment.
func TestHelpDoesNotLeakInternalNotes(t *testing.T) {
	markers := []string{"// TODO", "// FIXME", "// XXX", "// HACK", "TODO:", "FIXME:"}

	for _, name := range CheckNames() {
		t.Run(name, func(t *testing.T) {
			validators := BuildValidatorSet(map[string]bool{name: true}, nil, nil)
			provider, ok := validators[name].(help.Provider)
			if !ok {
				t.Skip("no help provider; reported by TestEveryValidatorProvidesHelp")
			}
			info := provider.GetCheckInfo()

			// Every user-visible string on the page, not just the description.
			fields := append([]string{
				info.ShortDescription,
				info.DetailedDescription,
				info.ConfigurationInfo,
			}, info.Patterns...)
			fields = append(fields, info.SupportedFormats...)
			fields = append(fields, info.Examples...)

			for _, text := range fields {
				for _, marker := range markers {
					if strings.Contains(text, marker) {
						t.Errorf("%q help contains %q, which reaches the user verbatim via "+
							"`--help %s`; put developer notes in a Go comment instead",
							name, marker, strings.ToLower(name))
					}
				}
			}
		})
	}
}
