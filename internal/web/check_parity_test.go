// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// reChecksPush extracts the canonical check names the web UI can request:
// every checks.push('NAME') in the embedded front-end script.
var reChecksPush = regexp.MustCompile(`checks\.push\('([A-Z_]+)'\)`)

// webOnlyChecks are check names the front-end may reference that are not in
// the core registry. COMPREHEND_PII is the disabled GenAI path: its push is
// inside a GENAI_DISABLED comment block but still matches the regex.
var webOnlyChecks = map[string]bool{
	"COMPREHEND_PII": true,
}

// TestWebUI_ChecksMatchCoreRegistry locks the web UI's detection-type list to
// the core validator registry (core.CheckNames, the same source of truth the
// CLI --checks flag validates against). The web check list was previously a
// hand-maintained copy that silently drifted: the six validators added in
// #144 (BANK_ACCOUNT, DATE_OF_BIRTH, DRIVERS_LICENSE, MEDICAL_ID, OTP,
// PHYSICAL_ADDRESS) and VIN were absent, so web users could neither see nor
// deselect them, and "select specific checks" scans silently omitted them.
// This test fails whenever a validator is added to (or removed from) the
// registry without the web UI following.
func TestWebUI_ChecksMatchCoreRegistry(t *testing.T) {
	webChecks := map[string]bool{}
	for _, m := range reChecksPush.FindAllStringSubmatch(embeddedAppJS, -1) {
		if !webOnlyChecks[m[1]] {
			webChecks[m[1]] = true
		}
	}
	if len(webChecks) == 0 {
		t.Fatal("no checks.push('NAME') sites found in embedded app.js — extraction regex or asset broke")
	}

	for _, name := range core.CheckNames() {
		if !webChecks[name] {
			t.Errorf("validator %s is in the core registry but missing from the web UI check list (app.js getSelectedChecks)", name)
		}
		delete(webChecks, name)
	}
	for name := range webChecks {
		t.Errorf("web UI offers check %s which is not in the core registry (stale entry?)", name)
	}
}

// TestWebUI_TemplateHasCheckboxPerCheck asserts every check the script reads
// has a matching checkbox element in the served markup — a script/markup
// mismatch renders as a JS TypeError that silently breaks scan submission.
func TestWebUI_TemplateHasCheckboxPerCheck(t *testing.T) {
	reGetByID := regexp.MustCompile(`document\.getElementById\('([A-Za-z]+)'\)\.checked\)\s*checks\.push`)
	for _, m := range reGetByID.FindAllStringSubmatch(embeddedAppJS, -1) {
		id := m[1]
		if !regexp.MustCompile(`id="` + id + `"`).MatchString(embeddedTemplate) {
			t.Errorf("app.js reads checkbox #%s but template.html has no element with that id", id)
		}
	}
}
