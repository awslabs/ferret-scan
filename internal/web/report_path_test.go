// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/paths"
)

// exportFor exports a scan in the given format the way the browser does since #923: /export is
// sent the scan_id /scan returned, under the same session, and formats the result the server kept.
func exportFor(t *testing.T, h http.Handler, cookie *http.Cookie, format string, scanID string) string {
	t.Helper()
	code, body := exportIDs(t, h, cookie, format, []string{scanID}, false, false)
	if code != http.StatusOK {
		t.Fatalf("/export %s: status %d: %s", format, code, body)
	}
	return body
}

// The web UI and the CLI must agree about what a report path IS, and the web UI must never
// publish the server's temp directory.
//
// FormatterOptions.SourceRoot is deliberately NOT set on either of this package's formatter
// option sites, and that is a positive decision rather than the omission #716 read it as.
// An upload is scanned from a random temp file, but handleScan rewrites every match's
// Filename to the sanitized name the operator uploaded BEFORE any formatter runs, so what
// reaches a formatter is already relative — and formatters.RelativeToRoot returns a
// relative path untouched, consulting no root at all. Setting SourceRoot to the temp
// directory would therefore change no byte of output while implying the temp path still
// reaches a formatter.
//
// These assertions are what makes that safe to rely on: if the rename is ever dropped, the
// absolute temp path reaches the report and this test says so.
func TestWebReportPathsAreTheUploadedName(t *testing.T) {
	const ssn = "Employee SSN: 452-11-9384\n"

	h := parityServer(t)
	scan, cookie := sessionScan(t, h, nil, "payroll.txt", []byte(ssn), []string{"SSN"})
	if !scan.Success || len(scan.Results) != 1 {
		t.Fatalf("control: success=%v results=%d, want one finding — every assertion below "+
			"is vacuous without it", scan.Success, len(scan.Results))
	}
	if got := scan.Results[0].Filename; got != "payroll.txt" {
		t.Fatalf("/scan reported filename %q, want the uploaded name; a temp path here reaches "+
			"every export format", got)
	}

	tempDir := paths.GetTempDir()

	for _, format := range []string{"gitlab-sast", "json", "sarif", "csv"} {
		t.Run(format, func(t *testing.T) {
			out := exportFor(t, h, cookie, format, scan.ScanID)

			if !strings.Contains(out, "payroll.txt") {
				t.Errorf("the export does not name the uploaded file at all:\n%s", out)
			}
			// Non-vacuous: tempDir is a real absolute directory on every platform, and the
			// upload it scanned genuinely lived there. Both spellings are checked, because a
			// Windows path reaches a JSON report with its separators escaped and a
			// native-only comparison would pass vacuously there.
			for _, spelling := range []string{tempDir, filepath.ToSlash(tempDir)} {
				if strings.Contains(out, spelling) {
					t.Errorf("the export carries the server's temp directory %q:\n%s", spelling, out)
				}
			}
			if strings.Contains(out, "ferret_upload_") {
				t.Errorf("the export carries the generated temp FILENAME:\n%s", out)
			}
		})
	}
}

// A vulnerability must not name two different paths in two different fields (#712). The web
// path is where a disagreement would have been least visible, because the operator never
// sees the temp path the scan actually used.
func TestWebGitLabDescriptionAgreesWithLocation(t *testing.T) {
	h := parityServer(t)
	scan, cookie := sessionScan(t, h, nil, "payroll.txt", []byte("Employee SSN: 452-11-9384\n"), []string{"SSN"})
	if !scan.Success || len(scan.Results) != 1 {
		t.Fatalf("control: success=%v results=%d, want one finding", scan.Success, len(scan.Results))
	}

	var report struct {
		Vulnerabilities []struct {
			Description string `json:"description"`
			Location    struct {
				File string `json:"file"`
			} `json:"location"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(exportFor(t, h, cookie, "gitlab-sast", scan.ScanID)), &report); err != nil {
		t.Fatalf("gitlab-sast export is not JSON: %v", err)
	}
	if len(report.Vulnerabilities) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1", len(report.Vulnerabilities))
	}

	vuln := report.Vulnerabilities[0]
	if vuln.Location.File != "payroll.txt" {
		t.Errorf("location.file = %q, want the uploaded name", vuln.Location.File)
	}
	if want := "**Location:** " + vuln.Location.File + " "; !strings.Contains(vuln.Description, want) {
		t.Errorf("the description does not carry the SAME path as location.file (%q):\n%s",
			vuln.Location.File, vuln.Description)
	}
}
