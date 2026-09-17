// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"sort"
	"strings"
	"testing"
)

// The gate for #662: no detection type may reach a report with nothing but a generated placeholder.
//
// Before inheritance, 49 of 64 types had no SARIF description and fell back to
//
//	"<TYPE> Detected" / "Sensitive data of type <TYPE> was detected in the scanned content."
//
// which is the entire explanation a reviewer sees in a code-scanning UI. 37 of 64 had nothing in any
// field. This test is what stops that returning: a NEW sub-type minted by a validator either has copy,
// or inherits it, or fails here.
//
// The allowlist below is deliberately EMPTY. It exists so that if a future type genuinely cannot be
// described yet, the debt is recorded in one visible place and can only shrink — rather than the guard
// being deleted, which is what happens to a test that blocks unrelated work.
var typesAwaitingDescription = map[string]string{}

func TestEveryKnownTypeHasADescription(t *testing.T) {
	missing := TypesWithoutDescription()

	var unexpected []string
	for _, ft := range missing {
		if _, allowed := typesAwaitingDescription[ft]; !allowed {
			unexpected = append(unexpected, ft)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("%d detection type(s) have no SARIF description, directly or by inheritance:\n  %s\n\n"+
			"A type without one is reported as \"<TYPE> Detected / Sensitive data of type <TYPE> was "+
			"detected\", which tells a reviewer nothing — and for a credential or a bank identifier, "+
			"\"should this be here\" is the whole question.\n\nTwo ways to fix it, in preference order:\n"+
			"  1. Map it to its family in typeParent (internal/core/typemeta_inherit.go). A card brand "+
			"belongs to CREDIT_CARD, a token to SECRETS, a document property to METADATA. This is the "+
			"usual answer and needs no new prose.\n"+
			"  2. If it has no family, add a descriptor to supplementalDescriptors.\n\n"+
			"Adding it to typesAwaitingDescription is a last resort and must carry a reason.",
			len(unexpected), strings.Join(unexpected, "\n  "))
	}

	// The allowlist must not rot: an entry that has since been described is a stale exemption that
	// would hide the next regression for that type.
	for ft, why := range typesAwaitingDescription {
		if DescribeType(ft).SARIFShort != "" {
			t.Errorf("%s is in typesAwaitingDescription (%q) but now HAS a description; remove the "+
				"exemption so it is guarded like every other type", ft, why)
		}
		if !knownTypeSet[ft] {
			t.Errorf("%s is exempted but is not a known type at all; the exemption is dead", ft)
		}
	}
}

// TestInheritanceActuallyCarriesTheLoad is the non-vacuity floor.
//
// TestEveryKnownTypeHasADescription would also pass if someone pasted 64 bespoke strings into the
// registry, or if KnownTypes() returned nothing. Neither is what this change did, and the difference
// matters: inheritance is what makes the NEXT sub-type safe.
func TestInheritanceActuallyCarriesTheLoad(t *testing.T) {
	known := KnownTypes()
	if len(known) < 50 {
		t.Fatalf("KnownTypes() returned %d types; every assertion in this file would be near-vacuous",
			len(known))
	}
	if len(typeParent) < 20 {
		t.Errorf("typeParent has only %d entries. Inheritance is the mechanism, and a map this small "+
			"means the coverage is coming from somewhere else — check whether copy was pasted per type "+
			"instead of mapped to a family", len(typeParent))
	}

	inherited := 0
	for _, ft := range known {
		if _, hasOwn := typeDescriptors[ft]; hasOwn {
			if typeDescriptors[ft].SARIFShort != "" {
				continue
			}
		}
		if DescribeType(ft).SARIFShort != "" {
			inherited++
		}
	}
	if inherited < 30 {
		t.Errorf("only %d type(s) get their SARIF description by inheritance; the measured gap this "+
			"change closed was 49, so a number this low means most types are no longer resolving "+
			"through their family", inherited)
	}
	t.Logf("%d of %d types resolve their description through a family", inherited, len(known))
}

// TestEveryParentInTheMapHasADescriptor stops a mapping pointing at nothing.
//
// DescribeType returns the type's own (possibly empty) descriptor when the parent is missing, so a
// typo in a family name degrades silently to the generic fallback — the exact behaviour this change
// exists to remove.
func TestEveryParentInTheMapHasADescriptor(t *testing.T) {
	var bad []string
	for sub, parent := range typeParent {
		d, ok := descriptorFor(parent)
		if !ok {
			bad = append(bad, sub+" -> "+parent+" (no descriptor at all)")
			continue
		}
		if d.SARIFShort == "" {
			bad = append(bad, sub+" -> "+parent+" (parent has no SARIFShort to inherit)")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d mapping(s) point at a family that cannot supply a description:\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

// TestInheritanceIsASingleHop pins the assumption DescribeType is written on.
//
// Every mapping is sub-type → family. A family that is itself mapped would make resolution
// order-dependent and could cycle; DescribeType resolves exactly one hop, so a chain would silently
// return the wrong copy rather than fail.
func TestInheritanceIsASingleHop(t *testing.T) {
	for sub, parent := range typeParent {
		if sub == parent {
			t.Errorf("%s is mapped to itself", sub)
		}
		if grand, chained := typeParent[parent]; chained {
			t.Errorf("%s -> %s -> %s is a chain, but DescribeType resolves a single hop, so %s would "+
				"silently inherit from %s and never see %s. Map %s directly to %s instead.",
				sub, parent, grand, sub, parent, grand, sub, grand)
		}
	}
}

// TestTheRegistryStillWinsEveryFieldItDefines is the guard on descriptorFor's merge direction.
//
// supplementalDescriptors exists only to FILL gaps. If it could override the migrated registry it
// would invalidate typemeta_mirror_test.go, which is what proves the migration from the legacy
// formatter maps lost nothing.
func TestTheRegistryStillWinsEveryFieldItDefines(t *testing.T) {
	for key, reg := range typeDescriptors {
		sup, both := supplementalDescriptors[key]
		if !both {
			continue
		}
		got, _ := descriptorFor(key)
		if reg.SARIFShort != "" && got.SARIFShort != reg.SARIFShort {
			t.Errorf("%s: SARIFShort came out as %q, but the registry defines %q — the supplement "+
				"overrode migrated copy", key, got.SARIFShort, reg.SARIFShort)
		}
		if reg.GitLabCheckDesc != "" && got.GitLabCheckDesc != reg.GitLabCheckDesc {
			t.Errorf("%s: GitLabCheckDesc came out as %q, want the registry's %q",
				key, got.GitLabCheckDesc, reg.GitLabCheckDesc)
		}
		if reg.SARIFSensitivityWeight != 0 && got.SARIFSensitivityWeight != reg.SARIFSensitivityWeight {
			t.Errorf("%s: weight came out as %v, want the registry's %v",
				key, got.SARIFSensitivityWeight, reg.SARIFSensitivityWeight)
		}
		// And the supplement must actually be doing something, or it is dead weight.
		if sup == (TypeDescriptor{}) {
			t.Errorf("%s has an empty supplemental entry", key)
		}
	}
}

// TestDescribeTypeDoesNotInventCopyForAnUnknownType keeps the accessor honest at the edges.
//
// An unknown type must come back empty so its consumer uses its own documented generic fallback. A
// DescribeType that returned something plausible for anything would make the gate above meaningless.
func TestDescribeTypeDoesNotInventCopyForAnUnknownType(t *testing.T) {
	for _, ft := range []string{"", "NOT_A_REAL_TYPE", "visa", "CREDIT_CARD_X"} {
		if d := DescribeType(ft); d != (TypeDescriptor{}) {
			t.Errorf("DescribeType(%q) returned copy (%q); an unrecognised type must resolve to nothing "+
				"so its consumer falls back as documented", ft, d.SARIFShort)
		}
	}
	// Case sensitivity is load-bearing: type names are canonical UPPERCASE, and the gitlab mapper
	// upper-cases before looking up precisely because of that.
	if DescribeType("VISA").SARIFShort == "" {
		t.Errorf("VISA resolves to nothing; the canonical spelling must work")
	}
}

// TestFamilyWeightsAreOrdered checks the six new descriptors against the scale already in use.
//
// The weights were chosen relative to the registry's existing values rather than invented, and the
// ordering carries meaning: a credential is worse than an address. An inversion here would misrank
// findings in every SARIF consumer that sorts on severity.
func TestFamilyWeightsAreOrdered(t *testing.T) {
	w := func(ft string) float64 { return DescribeType(ft).SARIFSensitivityWeight }

	// A card number is the registry's maximum; a document property its minimum.
	if w("VISA") <= w("US_STREET_ADDRESS") {
		t.Errorf("VISA (%v) is not weighted above US_STREET_ADDRESS (%v)", w("VISA"), w("US_STREET_ADDRESS"))
	}
	if w("SLACK_TOKEN") <= w("AUTHOR_INFO") {
		t.Errorf("SLACK_TOKEN (%v) is not weighted above AUTHOR_INFO (%v)", w("SLACK_TOKEN"), w("AUTHOR_INFO"))
	}
	// An MFA seed is a credential, so it must outrank an address and a date of birth.
	if w("OTP_SECRET") <= w("PO_BOX") {
		t.Errorf("OTP_SECRET (%v) is not weighted above PO_BOX (%v)", w("OTP_SECRET"), w("PO_BOX"))
	}
	// Every known type must land inside the documented 0-10 range.
	for _, ft := range KnownTypes() {
		if v := w(ft); v < 0 || v > 10 {
			t.Errorf("%s has weight %v, outside the documented 0-10 scale", ft, v)
		}
	}
}
