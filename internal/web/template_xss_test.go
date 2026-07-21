// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// These tests guard the XSS fixes for security findings HIGH-2 and HIGH-3 by
// asserting invariants on the embedded front-end assets. They are intentionally
// structural (the front-end is client-side JS that Go can't execute here): they
// fail if a future edit reintroduces an unescaped sink at the patterns we fixed.
//
// The client-side JS lives in assets/app.js (embedded, served at /app.js);
// assets/template.html carries only markup. Both are checked where relevant.

// TestAssets_NoTitleAttrWithEscapeHtml locks HIGH-2: a title="..." attribute
// must never be filled with escapeHtml(...), which does NOT escape quotes and so
// allows attribute breakout. Those sinks must use escapeAttr(...).
func TestAssets_NoTitleAttrWithEscapeHtml(t *testing.T) {
	for name, asset := range map[string]string{"template.html": embeddedTemplate, "app.js": embeddedAppJS} {
		if strings.Contains(asset, `title="${escapeHtml(`) {
			t.Errorf(`%s has title="${escapeHtml(...)}" — escapeHtml does not escape `+
				`quotes, enabling attribute-breakout XSS (HIGH-2). Use escapeAttr(...) instead.`, name)
		}
	}
}

// TestAssets_TitleAttrsUseEscapeAttr is the positive counterpart: every
// interpolated title attribute uses escapeAttr. (Sanity that the fix is present,
// not just that the bad form is absent.)
func TestAssets_TitleAttrsUseEscapeAttr(t *testing.T) {
	// Any `title="${...}"` interpolation must route through escapeAttr.
	re := regexp.MustCompile(`title="\$\{([a-zA-Z]+)\(`)
	for _, m := range re.FindAllStringSubmatch(embeddedAppJS, -1) {
		if m[1] != "escapeAttr" {
			t.Errorf(`title attribute interpolates via %q; must use escapeAttr for quote safety (HIGH-2)`, m[1])
		}
	}
}

// TestAppJS_SuppressionRuleFieldsEscaped locks HIGH-3: the suppression-list
// row must not interpolate raw rule-sourced values into innerHTML. We assert the
// row's variables are defined via an escaper so a malicious suppression YAML
// value cannot inject markup.
func TestAppJS_SuppressionRuleFieldsEscaped(t *testing.T) {
	// The per-row variables must be escaped at definition. Before the fix these
	// were `const filename = metadata.filename || 'Unknown';` (raw).
	mustEscapeDefs := []string{
		"const filename = escapeAttr(",
		"const fileType = escapeAttr(",
		"const ruleId = escapeAttr(",
	}
	for _, want := range mustEscapeDefs {
		if !strings.Contains(embeddedAppJS, want) {
			t.Errorf("suppression row is missing escaped definition %q — stored XSS risk (HIGH-3)", want)
		}
	}

	// The raw (unescaped) forms must be gone.
	rawForms := []string{
		"const filename = metadata.filename",
		"const fileType = metadata.finding_type",
	}
	for _, bad := range rawForms {
		if strings.Contains(embeddedAppJS, bad) {
			t.Errorf("suppression row still has unescaped definition %q — stored XSS (HIGH-3)", bad)
		}
	}
}

// TestAppJS_EscapeAttrDefined ensures the escapeAttr helper the fixes rely on
// exists and escapes both quote characters (the whole point vs escapeHtml).
func TestAppJS_EscapeAttrDefined(t *testing.T) {
	if !strings.Contains(embeddedAppJS, "function escapeAttr(") {
		t.Fatal("escapeAttr helper is missing from app.js")
	}
	// It must escape double and single quotes.
	for _, frag := range []string{`replace(/"/g`, `replace(/'/g`} {
		if !strings.Contains(embeddedAppJS, frag) {
			t.Errorf("escapeAttr does not appear to escape %s — attribute breakout still possible", frag)
		}
	}
}

// inlineHandlerRe matches inline event-handler attributes (onclick=, onerror=,
// onchange=, ...) in HTML markup. Kept deliberately broad: any on*= attribute
// in served markup would be blocked by the strict CSP and indicates a
// regression.
var inlineHandlerRe = regexp.MustCompile(`\bon[a-z]+\s*=\s*["']`)

// TestTemplate_NoInlineEventHandlers locks the CSP hardening (issue #147 item
// 1): template.html must not contain inline on*="..." handlers, because the
// CSP is script-src 'self' (no 'unsafe-inline') and the browser would silently
// refuse to run them. Interactivity is bound via data-action / data-change
// delegation in app.js.
func TestTemplate_NoInlineEventHandlers(t *testing.T) {
	if m := inlineHandlerRe.FindAllString(embeddedTemplate, -1); len(m) > 0 {
		t.Errorf("template.html contains %d inline event handler attribute(s) %v — "+
			"blocked by CSP script-src 'self'; use data-action/data-change + the "+
			"delegated dispatcher in app.js", len(m), m)
	}
}

// TestAppJS_NoInlineEventHandlersInFragments extends the same invariant to the
// HTML fragments app.js injects via innerHTML: an on*= attribute inside an
// injected fragment is equally dead under CSP (and was historically an XSS
// escalation channel).
func TestAppJS_NoInlineEventHandlersInFragments(t *testing.T) {
	if m := inlineHandlerRe.FindAllString(embeddedAppJS, -1); len(m) > 0 {
		t.Errorf("app.js contains %d inline event handler attribute(s) %v in "+
			"generated markup — blocked by CSP script-src 'self'; use "+
			"data-action/data-change delegation", len(m), m)
	}
}

// TestTemplate_NoInlineScriptBlocks ensures the template keeps all script in
// the external /app.js asset. An inline <script> block would be blocked by
// script-src 'self'.
func TestTemplate_NoInlineScriptBlocks(t *testing.T) {
	re := regexp.MustCompile(`<script\b[^>]*>`)
	for _, tag := range re.FindAllString(embeddedTemplate, -1) {
		if !strings.Contains(tag, `src=`) {
			t.Errorf("template.html contains inline script block %q — blocked by CSP script-src 'self'; move code to assets/app.js", tag)
		}
	}
	if !strings.Contains(embeddedTemplate, `<script src="/app.js"></script>`) {
		t.Error(`template.html no longer references <script src="/app.js"> — the UI would load with no JS at all`)
	}
}

// TestAppJS_DelegatedActionsCoverMarkup cross-checks that every data-action /
// data-change name referenced in markup (static template + fragments generated
// in app.js) has a dispatcher entry in app.js, so a renamed or missing handler
// fails the build rather than producing a dead button.
func TestAppJS_DelegatedActionsCoverMarkup(t *testing.T) {
	both := embeddedTemplate + embeddedAppJS

	check := func(attr, table string) {
		re := regexp.MustCompile(attr + `="([a-zA-Z0-9]+)"`)
		names := map[string]struct{}{}
		for _, m := range re.FindAllStringSubmatch(both, -1) {
			names[m[1]] = struct{}{}
		}
		if len(names) == 0 {
			t.Fatalf("no %s attributes found — markup/delegation wiring is broken", attr)
		}
		// Extract the dispatcher table body.
		tblRe := regexp.MustCompile(`(?s)const ` + table + ` = \{(.*?)\n\};`)
		tbl := tblRe.FindStringSubmatch(embeddedAppJS)
		if tbl == nil {
			t.Fatalf("dispatcher table %q not found in app.js", table)
		}
		for name := range names {
			if !regexp.MustCompile(`\b` + name + `:`).MatchString(tbl[1]) {
				t.Errorf("%s=%q used in markup but %q has no entry for it — dead control", attr, name, table)
			}
		}
	}

	check("data-action", "clickActions")
	check("data-change", "changeActions")
}
