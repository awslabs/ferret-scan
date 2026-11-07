// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"io"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// A report is scanned too: by this tool in a self-scan, by a reviewer's pre-commit hook when the
// report is committed. The scope block must not make a clean report self-flag (#904 item 6), which a
// 40-hex commit does: it scans as API_KEY_OR_SECRET. The block carries a 12-hex commit instead.

// stampedCommit is a full 40-hex commit id, as goreleaser injects through .Commit.
const stampedCommit = "5fecf59c1decc766139bfe5af752e80884d120c4"

func scanText(t *testing.T, name, content string) []string {
	t.Helper()
	res, err := core.ScanContent(content, core.ContentScanConfig{VirtualPath: name, LogWriter: io.Discard})
	if err != nil {
		t.Fatalf("scanning %s: %v", name, err)
	}
	var found []string
	for _, m := range res.Matches {
		found = append(found, m.Type+" "+m.Text)
	}
	return found
}

func TestEveryFormatsNarrowedCleanReportScansClean(t *testing.T) {
	savedVersion, savedCommit := version.Version, version.GitCommit
	t.Cleanup(func() { version.Version, version.GitCommit = savedVersion, savedCommit })
	version.Version, version.GitCommit = "2.5.3", stampedCommit

	// Every field the block can carry, at its widest: a profile, a working-directory config name, a
	// not-applicable check, a disabled sub-type, suppression counts, a hidden band.
	scope := formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun:               []string{"CREDIT_CARD", "EMAIL", "IP_ADDRESS", "PHONE", "SECRETS", "SSN"},
		AllChecks:               core.CheckNames(),
		ChecksNotApplicable:     []string{"METADATA"},
		ConfidenceLevel:         map[string]bool{"high": true, "medium": true},
		DisabledDetectionTypes:  map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}},
		Profile:                 &formatters.ScanProfile{Name: "precommit", SelectedBy: formatters.ProfileSelectedByPrecommit},
		Config:                  formatters.ScanConfigSource{Source: formatters.ConfigSourceWorkingDirectory, Name: ".ferret-scan.yaml"},
		SuppressionRulesEnabled: 12,
	})
	if scope == nil {
		t.Fatal("no scope")
	}
	opts := formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true},
		NoColor:         true,
		Stats: &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, Suppressed: 512,
			DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}},
		Scan: scope,
	}

	// The formats whose block names the build. text keeps to one line, gitlab-sast's schema has no
	// commit slot, csv has no block.
	carriesCommit := map[string]bool{"json": true, "yaml": true, "junit": true, "sarif": true}
	for _, name := range formatters.List() {
		out, err := formatters.Export(name, nil, nil, opts)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(out, stampedCommit) {
			t.Errorf("%s carries the 40-hex commit:\n%s", name, out)
		}
		if carriesCommit[name] && !strings.Contains(out, stampedCommit[:12]) {
			t.Errorf("%s does not carry the 12-hex commit:\n%s", name, out)
		}
		if found := scanText(t, "report."+name, out); len(found) > 0 {
			t.Errorf("%s: a clean, narrowed report self-flags when scanned: %v\n%s", name, found, out)
		}
	}
}

// TestTheSelfScanCanSeeAFortyHexCommit is the control for the test above: the same scanner, the same
// path, on the one value the block deliberately does not carry. Without it, a scanner that reported
// nothing at all would pass the precision test.
func TestTheSelfScanCanSeeAFortyHexCommit(t *testing.T) {
	doc := "{\n  \"scan\": {\n    \"tool\": {\n      \"commit\": \"" + stampedCommit + "\"\n    }\n  }\n}\n"
	if found := scanText(t, "report.json", doc); len(found) == 0 {
		t.Fatal("a 40-hex commit in a report scanned clean, so TestEveryFormatsNarrowedCleanReportScansClean " +
			"cannot tell a 12-hex block from a 40-hex one")
	}
}
