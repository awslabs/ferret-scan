// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// handleScan used to fall straight through to the literal "all"/"all" when the
// request omitted confidence/checks, so a config file was honored by the CLI and
// silently ignored by the web UI. Scanning one file with `defaults: {checks: SSN}`
// gave 1 finding on the command line and 3 in the browser.
//
// For a tool whose job is deciding what counts as sensitive, two answers from one
// config is the defect: the operator believes they narrowed the scan and the UI
// quietly widened it again. These tests pin the precedence
// (request parameter > config file > built-in default) through the real HTTP
// handler, because the bug lived in the handler, not in the scan engine.

// fixtureWithThreeTypes writes a file that yields SSN, EMAIL and PHONE findings, so
// a checks restriction is visible as a change in the reported types rather than
// merely a change in count.
func fixtureWithThreeTypes(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mixed.txt")
	body := "ssn 449-87-4100 mail a@corp.example.com phone 415-555-2671\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

// writeConfig writes a config file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return p
}

// postScan drives ws.handleScan directly with a multipart upload and returns the
// distinct finding types. query may be empty.
func postScan(t *testing.T, ws *WebServer, filePath, query string) map[string]bool {
	t.Helper()

	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("files", filepath.Base(filePath))
	if err != nil {
		t.Fatalf("multipart: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("multipart write: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	url := "/scan"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()

	ws.handleScan(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleScan returned %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool `json:"success"`
		Results []struct {
			Type string `json:"type"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v\nbody: %s", err, rec.Body.String())
	}

	types := map[string]bool{}
	for _, r := range resp.Results {
		types[r.Type] = true
	}
	return types
}

// TestWebHonorsConfigChecks is the regression: with no request parameters, the
// config file's checks must scope the scan exactly as it does on the CLI.
func TestWebHonorsConfigChecks(t *testing.T) {
	fixture := fixtureWithThreeTypes(t)

	// Control: no config -> everything is reported.
	wsAll := NewWebServerWithOptions("0", "127.0.0.1", "", "", nil)
	all := postScan(t, wsAll, fixture, "")
	if len(all) < 2 {
		t.Fatalf("fixture is not discriminating: unrestricted scan found types %v; "+
			"a checks restriction below could not be observed", all)
	}

	// Restricted by config only.
	cfg := writeConfig(t, "defaults:\n  checks: SSN\n")
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfg, "", nil)
	got := postScan(t, ws, fixture, "")

	if !got["SSN"] {
		t.Errorf("config restricted checks to SSN but no SSN was reported (types %v)", got)
	}
	for typ := range got {
		if typ != "SSN" {
			t.Errorf("type %q was reported despite `defaults: {checks: SSN}` in the config; "+
				"web mode is ignoring the config file (types %v, unrestricted was %v)",
				typ, got, all)
		}
	}
}

// TestWebRequestParamStillOverridesConfig guards the other direction. The fix must
// not make the config authoritative over an explicit choice in the UI.
func TestWebRequestParamStillOverridesConfig(t *testing.T) {
	fixture := fixtureWithThreeTypes(t)
	cfg := writeConfig(t, "defaults:\n  checks: SSN\n")
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfg, "", nil)

	got := postScan(t, ws, fixture, "checks=SSN,EMAIL,PHONE")

	if len(got) < 2 {
		t.Errorf("an explicit checks parameter must win over the config file, but only "+
			"%v was reported — the config is overriding the user's request", got)
	}
}

// TestWebFallsBackToBuiltInDefault is the non-vacuity floor: with neither a request
// parameter nor a config value, the handler must still scan everything. Without this
// a fix that defaulted to "no checks" would satisfy the first test and break the UI.
func TestWebFallsBackToBuiltInDefault(t *testing.T) {
	fixture := fixtureWithThreeTypes(t)

	// A config that says nothing about checks or confidence.
	cfg := writeConfig(t, "defaults:\n  format: json\n")
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfg, "", nil)

	got := postScan(t, ws, fixture, "")
	if len(got) < 2 {
		t.Errorf("with no checks in the request or the config, the scan should fall back "+
			"to all checks, but only %v was reported", got)
	}
}
