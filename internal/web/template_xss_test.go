// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// These tests guard the XSS fixes for security findings HIGH-2 and HIGH-3 by
// asserting invariants on the embedded template. They are intentionally
// structural (the template is client-side JS that Go can't execute here): they
// fail if a future edit reintroduces an unescaped sink at the patterns we fixed.

// TestTemplate_NoTitleAttrWithEscapeHtml locks HIGH-2: a title="..." attribute
// must never be filled with escapeHtml(...), which does NOT escape quotes and so
// allows attribute breakout. Those sinks must use escapeAttr(...).
func TestTemplate_NoTitleAttrWithEscapeHtml(t *testing.T) {
	if strings.Contains(embeddedTemplate, `title="${escapeHtml(`) {
		t.Errorf(`template has title="${escapeHtml(...)}" — escapeHtml does not escape ` +
			`quotes, enabling attribute-breakout XSS (HIGH-2). Use escapeAttr(...) instead.`)
	}
}

// TestTemplate_TitleAttrsUseEscapeAttr is the positive counterpart: every
// interpolated title attribute uses escapeAttr. (Sanity that the fix is present,
// not just that the bad form is absent.)
func TestTemplate_TitleAttrsUseEscapeAttr(t *testing.T) {
	// Any `title="${...}"` interpolation must route through escapeAttr.
	re := regexp.MustCompile(`title="\$\{([a-zA-Z]+)\(`)
	for _, m := range re.FindAllStringSubmatch(embeddedTemplate, -1) {
		if m[1] != "escapeAttr" {
			t.Errorf(`title attribute interpolates via %q; must use escapeAttr for quote safety (HIGH-2)`, m[1])
		}
	}
}

// TestTemplate_SuppressionRuleFieldsEscaped locks HIGH-3: the suppression-list
// row must not interpolate raw rule-sourced values into innerHTML. We assert the
// row's variables are defined via an escaper so a malicious suppression YAML
// value cannot inject markup.
func TestTemplate_SuppressionRuleFieldsEscaped(t *testing.T) {
	// The per-row variables must be escaped at definition. Before the fix these
	// were `const filename = metadata.filename || 'Unknown';` (raw).
	mustEscapeDefs := []string{
		"const filename = escapeAttr(",
		"const fileType = escapeAttr(",
		"const ruleId = escapeAttr(",
	}
	for _, want := range mustEscapeDefs {
		if !strings.Contains(embeddedTemplate, want) {
			t.Errorf("suppression row is missing escaped definition %q — stored XSS risk (HIGH-3)", want)
		}
	}

	// The raw (unescaped) forms must be gone.
	rawForms := []string{
		"const filename = metadata.filename",
		"const fileType = metadata.finding_type",
	}
	for _, bad := range rawForms {
		if strings.Contains(embeddedTemplate, bad) {
			t.Errorf("suppression row still has unescaped definition %q — stored XSS (HIGH-3)", bad)
		}
	}
}

// TestTemplate_EscapeAttrDefined ensures the escapeAttr helper the fixes rely on
// exists and escapes both quote characters (the whole point vs escapeHtml).
func TestTemplate_EscapeAttrDefined(t *testing.T) {
	if !strings.Contains(embeddedTemplate, "function escapeAttr(") {
		t.Fatal("escapeAttr helper is missing from the template")
	}
	// It must escape double and single quotes.
	for _, frag := range []string{`replace(/"/g`, `replace(/'/g`} {
		if !strings.Contains(embeddedTemplate, frag) {
			t.Errorf("escapeAttr does not appear to escape %s — attribute breakout still possible", frag)
		}
	}
}
