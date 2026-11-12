// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
)

// reExportSelect captures the export-format <select> in the embedded template, and reOptionValue each
// <option value="..."> inside it.
var (
	reExportSelect = regexp.MustCompile(`(?s)<select id="exportFormat"[^>]*>(.*?)</select>`)
	reOptionValue  = regexp.MustCompile(`<option value="([^"]*)"`)
)

// TestWebUI_ExportOptionsMatchFormatterRegistry holds the export menu to the formatter registry.
//
// /export serves any name in formatters.List(), but the <option> list the operator picks from is
// hand-written in template.html, so a new formatter would be reachable by API and invisible in the UI,
// and a removed one would stay in the menu and fail on click (#907). Same class as
// TestWebUI_ChecksMatchCoreRegistry, which found seven validators the check list had lost.
func TestWebUI_ExportOptionsMatchFormatterRegistry(t *testing.T) {
	m := reExportSelect.FindStringSubmatch(embeddedTemplate)
	if m == nil {
		t.Fatal(`no <select id="exportFormat"> in the embedded template: the extraction regex or the template broke`)
	}
	ui := map[string]bool{}
	for _, o := range reOptionValue.FindAllStringSubmatch(m[1], -1) {
		ui[o[1]] = true
	}
	if len(ui) == 0 {
		t.Fatal("the export <select> has no <option value=...>: the extraction regex or the template broke")
	}
	registry := formatters.List()
	for _, name := range registry {
		if !ui[name] {
			t.Errorf("format %q is in formatters.List() (so /export serves it) but missing from the export menu in template.html", name)
		}
		delete(ui, name)
	}
	for name := range ui {
		t.Errorf("the export menu offers %q, which is not in formatters.List(): /export answers it with an error", name)
	}
}

// exportFixtureCases are the golden cases whose findings make the fixed match sets: plain text with
// five types across all three bands, and an Office document whose findings carry extractor metadata.
var exportFixtureCases = []string{"file_txt_mixed_pii", "file_docx_body_and_metadata"}

func goldenFileCase(t *testing.T, name string) goldencorpus.FileCase {
	t.Helper()
	for _, fc := range goldencorpus.FileCases {
		if fc.Name == name {
			return fc
		}
	}
	t.Fatalf("golden file case %q is gone; pick another fixture for the export parity test", name)
	return goldencorpus.FileCase{}
}

// cliMatches is what the CLI's scan of the same bytes gives, under the name the web reports: the case
// scanned through core.ScanFile with preprocessors on, then given what runFullCLIScan gives every web
// finding, the upload name as Filename (and in any metadata string naming the scanned path) and an
// explanation (the web annotates every finding; the CLI does with --explain).
func cliMatches(t *testing.T, fc goldencorpus.FileCase) []detector.Match {
	t.Helper()
	upload := filepath.Base(fc.Filename)
	native := filepath.ToSlash(filepath.Join(t.TempDir(), upload))
	if err := os.WriteFile(native, fc.Content, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := core.ScanFile(core.ScanConfig{
		FilePath:            native,
		Checks:              fc.Checks,
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanFile(%s): %v", fc.Name, err)
	}
	for i := range res.Matches {
		res.Matches[i].Filename = upload
		for k, v := range res.Matches[i].Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, native) {
				res.Matches[i].Metadata[k] = strings.ReplaceAll(s, native, upload)
			}
		}
	}
	explain.Annotate(res.Matches, explain.NewSignalSynthesizer())
	if len(res.Matches) == 0 {
		t.Fatalf("the export fixture %s produced no findings", fc.Name)
	}
	return res.Matches
}

// cliScope is the scope block the CLI's --file report carries for the case's checks under an
// explicit empty --config: cmd's fileScanScope over the validator set main() builds.
func cliScope(fc goldencorpus.FileCase) *formatters.ScanScope {
	validators := core.BuildValidatorSet(core.ParseChecksToRun(fc.Checks), nil, nil)
	run := make([]string, 0, len(validators))
	for name := range validators {
		run = append(run, name)
	}
	disabled, _ := core.DisabledDetectionTypes(validators)
	return formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun:              run,
		AllChecks:              core.CheckNames(),
		ConfidenceLevel:        map[string]bool{"high": true, "medium": true, "low": true},
		DisabledDetectionTypes: disabled,
		Config:                 formatters.ScanConfigSource{Source: formatters.ConfigSourceExplicit},
	})
}

// sessionScan posts one file to /scan the way the front-end does, carrying cookie (nil for none), and
// returns the response and the session cookie the server set or accepted.
func sessionScan(t *testing.T, h http.Handler, cookie *http.Cookie, relPath string, content []byte, checks []string) (ScanResponse, *http.Cookie) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	w, err := mw.CreateFormFile("files", path.Base(relPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	checkField := "all"
	if len(checks) > 0 {
		checkField = strings.Join(checks, ",")
	}
	for k, v := range map[string]string{"relative_path": relPath, "checks": checkField, "confidence": "all", "verbose": "false", "recursive": "false"} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/scan %s: HTTP %d: %s", relPath, rec.Code, truncate(rec.Body.String(), 300))
	}
	var resp ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("/scan %s: response is not JSON (%v)", relPath, err)
	}
	if !resp.Success {
		t.Fatalf("/scan %s: success=false: %s", relPath, resp.Error)
	}
	if resp.ScanID == "" {
		t.Fatalf("/scan %s returned no scan_id, so /export has nothing to name (#923)", relPath)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == scanSessionCookie {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie must be HttpOnly and SameSite=Strict: %+v", c)
			}
			cookie = &http.Cookie{Name: c.Name, Value: c.Value}
		}
	}
	if cookie == nil {
		t.Fatalf("/scan %s set no %s cookie", relPath, scanSessionCookie)
	}
	return resp, cookie
}

// exportIDs posts {format, scan_ids, show_match, verbose} to /export and returns the status and body.
func exportIDs(t *testing.T, h http.Handler, cookie *http.Cookie, format string, ids []string, showMatch, verbose bool) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"format": format, "scan_ids": ids, "show_match": showMatch, "verbose": verbose})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/export", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// reJUnitTime matches the JUnit duration attributes, which measure the formatting call itself.
var reJUnitTime = regexp.MustCompile(`\btime="[0-9.]+"`)

// normalizeExportBody strips what differs between two renders of the same matches: the wall-clock
// timestamps goldencorpus.NormalizeOutput already replaces (gitlab-sast scan.start_time and
// scan.end_time, the INTELLECTUAL_PROPERTY reconstruction_timestamp metadata value), JUnit time="..."
// durations, and JSON key order (NormalizeOutput canonicalises json, sarif and gitlab-sast).
func normalizeExportBody(format, s string) string {
	return reJUnitTime.ReplaceAllString(goldencorpus.NormalizeOutput(format, s), `time="<DURATION>"`)
}

// exportOptions are the four combinations of the two switches /export takes.
var exportOptions = []struct{ showMatch, verbose bool }{{false, false}, {true, false}, {false, true}, {true, true}}

func registryFormats(t *testing.T) []string {
	t.Helper()
	formats := formatters.List()
	sort.Strings(formats)
	if len(formats) < 7 {
		t.Fatalf("formatters.List() has %d entries; the registry imports broke", len(formats))
	}
	return formats
}

// TestWebExportMatchesCLIFormatter holds /export to the CLI's formatters with nothing allowed to
// differ (#923). For each fixture case, the file is uploaded to /scan, and the body /export returns for
// that scan_id, in every format the registry serves and under each of the four show_match/verbose
// combinations, must equal formatters.Export of the CLI's scan of the same bytes with the CLI's
// options: all three bands, NoColor and the switches. Only timestamps and
// JSON key order are normalised.
//
// Before #923 /export rebuilt findings from the browser's JSON and this test carried three allowed
// losses (the explanation, the context keywords, the typed metadata) that changed 18, 6 and 2 of 28
// bodies.
func TestWebExportMatchesCLIFormatter(t *testing.T) {
	h := parityServer(t)
	for _, name := range exportFixtureCases {
		fc := goldenFileCase(t, name)
		resp, cookie := sessionScan(t, h, nil, filepath.Base(fc.Filename), fc.Content, fc.Checks)
		want := cliMatches(t, fc)
		for _, format := range registryFormats(t) {
			for _, opt := range exportOptions {
				code, got := exportIDs(t, h, cookie, format, []string{resp.ScanID}, opt.showMatch, opt.verbose)
				if code != http.StatusOK {
					t.Fatalf("/export %s %s: HTTP %d: %s", name, format, code, truncate(got, 300))
				}
				cli, err := formatters.Export(format, want, []detector.SuppressedMatch{}, formatters.FormatterOptions{
					ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
					Verbose:         opt.verbose,
					NoColor:         true,
					ShowMatch:       opt.showMatch,
				})
				if err != nil {
					t.Fatalf("formatters.Export(%s): %v", format, err)
				}
				if g, w := normalizeExportBody(format, got), normalizeExportBody(format, cli); g != w {
					t.Errorf("/export %s %s (show_match=%v verbose=%v) differs from formatters.Export for the same %d findings:\n%s",
						name, format, opt.showMatch, opt.verbose, len(want), firstDifference(w, g))
				}
			}
		}
	}
}

// manyFindings is a text file with n distinct reserved-domain email addresses, one per line.
func manyFindings(n int) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("Contact: jane.doe")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("@example.com\n")
	}
	return []byte(b.String())
}

// countResults counts the findings in a json export, under either key a reader may meet.
func countResults(t *testing.T, body string) int {
	t.Helper()
	var d map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("export is not JSON: %v", err)
	}
	raw := d["findings"]
	if len(raw) == 0 {
		raw = d["results"]
	}
	var rs []json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &rs); err != nil {
			t.Fatalf("results is not a list: %v", err)
		}
	}
	return len(rs)
}

// TestWebExportLargeScans is #923's size half: 782 findings answered HTTP 400, because the browser
// posted every result back in one body under the 1 MiB JSON cap. The export now names the scan, so
// 782 and 5,000 findings export in every format and the json export holds every one of them.
func TestWebExportLargeScans(t *testing.T) {
	h := parityServer(t)
	for _, n := range []int{782, 5000} {
		resp, cookie := sessionScan(t, h, nil, "many.txt", manyFindings(n), []string{"EMAIL"})
		if len(resp.Results) != n {
			t.Fatalf("/scan of %d addresses returned %d findings; the fixture no longer yields one per line", n, len(resp.Results))
		}
		for _, format := range registryFormats(t) {
			code, body := exportIDs(t, h, cookie, format, []string{resp.ScanID}, false, false)
			if code != http.StatusOK {
				t.Fatalf("/export %s of %d findings: HTTP %d: %s", format, n, code, truncate(body, 300))
			}
			if format == "json" {
				if got := countResults(t, body); got != n {
					t.Errorf("/export json of a %d-finding scan holds %d findings", n, got)
				}
			}
		}
	}
}

// TestWebExportMergesTheRunsScans: the front-end uploads one file per /scan and exports the run, so
// /export takes several ids and formats their findings as one report, as the CLI's scan of the same
// files does.
func TestWebExportMergesTheRunsScans(t *testing.T) {
	h := parityServer(t)
	a, cookie := sessionScan(t, h, nil, "a.txt", manyFindings(3), []string{"EMAIL"})
	b, _ := sessionScan(t, h, cookie, "b.txt", manyFindings(4), []string{"EMAIL"})
	code, body := exportIDs(t, h, cookie, "json", []string{a.ScanID, b.ScanID, a.ScanID}, true, false)
	if code != http.StatusOK {
		t.Fatalf("/export of two scans: HTTP %d: %s", code, truncate(body, 300))
	}
	if got := countResults(t, body); got != 7 {
		t.Errorf("/export of a 3- and a 4-finding scan (one id repeated) holds %d findings, want 7", got)
	}

	c, _ := sessionScan(t, h, cookie, "c.txt", manyFindings(2), []string{"EMAIL", "SSN"})
	if code, _ := exportIDs(t, h, cookie, "json", []string{a.ScanID, c.ScanID}, false, false); code != http.StatusBadRequest {
		t.Errorf("/export merged scans run with different checks: HTTP %d, want 400", code)
	}
}

// TestWebExportIsScopedToItsSession: a scan id reaches its result only from the session that ran the
// scan, so an id seen elsewhere (a log, a shared screen) does not export another browser's findings.
func TestWebExportIsScopedToItsSession(t *testing.T) {
	h := parityServer(t)
	resp, _ := sessionScan(t, h, nil, "a.txt", manyFindings(2), []string{"EMAIL"})
	other := &http.Cookie{Name: scanSessionCookie, Value: strings.Repeat("ab", 16)}
	for name, c := range map[string]*http.Cookie{"no cookie": nil, "another session": other} {
		code, body := exportIDs(t, h, c, "json", []string{resp.ScanID}, true, false)
		if code != http.StatusNotFound {
			t.Errorf("%s: /export of another session's scan answered HTTP %d, want 404", name, code)
		}
		if strings.Contains(body, "jane.doe") {
			t.Errorf("%s: the refusal carries a finding", name)
		}
	}
}

// TestWebExportRefusesPostedFindings: the lossy path is gone, and a caller still posting findings is
// told what to send instead of receiving an empty report.
func TestWebExportRefusesPostedFindings(t *testing.T) {
	h := parityServer(t)
	body, _ := json.Marshal(map[string]any{"format": "json", "results": []map[string]any{{"text": "x", "type": "EMAIL"}}})
	req := httptest.NewRequest(http.MethodPost, "/export", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "scan_ids") {
		t.Errorf("/export with results and no scan_ids: HTTP %d %q, want 400 naming scan_ids", rec.Code, truncate(rec.Body.String(), 200))
	}
}

// TestScanStoreBounds pins the three bounds: age, entry count, and total findings, oldest first.
func TestScanStoreBounds(t *testing.T) {
	const sess = "0123456789abcdef0123456789abcdef"
	s := newScanStore()
	clock := s.now()
	s.now = func() time.Time { return clock }

	first, err := s.put(sess, &storedScan{})
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(scanTTL + time.Second)
	if _, _, ok := s.get(sess, []string{first}); ok {
		t.Error("an entry older than scanTTL is still returned")
	}

	ids := make([]string, 0, maxStoredScans+1)
	for i := 0; i <= maxStoredScans; i++ {
		id, err := s.put(sess, &storedScan{matches: make([]detector.Match, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if len(s.entries) != maxStoredScans {
		t.Errorf("store holds %d entries, bound is %d", len(s.entries), maxStoredScans)
	}
	if _, _, ok := s.get(sess, ids[:1]); ok {
		t.Error("the oldest entry survived the count bound")
	}
	if _, _, ok := s.get(sess, ids[len(ids)-1:]); !ok {
		t.Error("the newest entry was evicted")
	}

	big := &storedScan{matches: make([]detector.Match, maxStoredFindings)}
	if _, err := s.put(sess, big); err != nil {
		t.Fatal(err)
	}
	if len(s.entries) != 1 || s.findings != maxStoredFindings {
		t.Errorf("after a full-size entry the store holds %d entries and %d findings, want 1 and %d", len(s.entries), s.findings, maxStoredFindings)
	}
}

// firstDifference shows the first differing line of two bodies, the CLI's first.
func firstDifference(cli, web string) string {
	a, b := strings.Split(cli, "\n"), strings.Split(web, "\n")
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return "  line " + strconv.Itoa(i+1) + "\n  cli:     " + truncate(x, 400) + "\n  /export: " + truncate(y, 400)
		}
	}
	return "  (no line differs; the bodies differ in length only)"
}
