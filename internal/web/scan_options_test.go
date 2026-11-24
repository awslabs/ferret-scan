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
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
)

// #925: --profile, --disable-ip-types, --validator-budget and --debug used to be accepted (or refused)
// and ignored by --web. These tests drive the real /scan handler, which is where the flags land.

type optScanResponse struct {
	Success    bool `json:"success"`
	Incomplete bool `json:"incomplete"`
	Results    []struct {
		Type string `json:"type"`
	} `json:"results"`
}

func (r optScanResponse) types() map[string]bool {
	m := map[string]bool{}
	for _, x := range r.Results {
		m[x.Type] = true
	}
	return m
}

// optScan uploads body as name through ws.handleScan.
func optScan(t *testing.T, ws *WebServer, name, body string) optScanResponse {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("files", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, body); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	ws.handleScan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handleScan returned %d: %s", rec.Code, rec.Body.String())
	}
	var resp optScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return resp
}

// startForOptions runs the part of Start() that validates the options, without a listener.
func startForOptions(t *testing.T, cfgPath string, o ScanOptions) (*WebServer, error) {
	t.Helper()
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfgPath, "", nil)
	ws.SetScanOptions(o)
	// A port that cannot be bound makes Start return after the validation and before serving; an
	// invalid bind address does that without opening a listener.
	ws.bindAddr = "256.256.256.256"
	err := ws.Start()
	if err != nil && strings.Contains(err.Error(), "refusing to start") {
		return ws, err
	}
	return ws, nil
}

const optMixed = "ssn 449-87-4100 mail a@corp.example.com\nCopyright (c) 2024 Example Corporation. All rights reserved.\n"

func TestWebProfileAppliesToScan(t *testing.T) {
	cfg := writeConfig(t, "defaults:\n  checks: all\nprofiles:\n  ssnonly:\n    checks: SSN\n    enable_preprocessors: true\n")

	plain, err := startForOptions(t, cfg, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	all := optScan(t, plain, "m.txt", optMixed).types()
	if len(all) < 2 {
		t.Fatalf("fixture is not discriminating: %v", all)
	}

	ws, err := startForOptions(t, cfg, ScanOptions{ProfileName: "ssnonly"})
	if err != nil {
		t.Fatal(err)
	}
	got := optScan(t, ws, "m.txt", optMixed).types()
	t.Logf("types without --profile: %v; with --profile ssnonly: %v", all, got)
	if !got["SSN"] || len(got) != 1 {
		t.Errorf("--profile ssnonly (checks: SSN) must restrict the scan to SSN, got %v (no profile: %v)", got, all)
	}
}

func TestWebProfileLosesToTheForm(t *testing.T) {
	cfg := writeConfig(t, "profiles:\n  ssnonly:\n    checks: SSN\n    enable_preprocessors: true\n")
	ws, err := startForOptions(t, cfg, ScanOptions{ProfileName: "ssnonly"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("checks", "SSN,EMAIL")
	fw, _ := mw.CreateFormFile("files", "m.txt")
	_, _ = io.WriteString(fw, optMixed)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/scan", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	ws.handleScan(rec, req)
	var resp optScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if got := resp.types(); !got["SSN"] || len(got) < 2 {
		t.Errorf("an explicit checks field must win over the profile, got %v", got)
	}
}

func TestWebUnknownProfileRefusesToStart(t *testing.T) {
	cfg := writeConfig(t, "profiles:\n  real:\n    checks: SSN\n")
	_, err := startForOptions(t, cfg, ScanOptions{ProfileName: "typo"})
	if err == nil || !strings.Contains(err.Error(), "Profile 'typo' not found") {
		t.Fatalf("an unknown --profile must refuse to start naming the profile, got %v", err)
	}
	if _, err := startForOptions(t, cfg, ScanOptions{ProfileName: "real"}); err != nil {
		t.Fatalf("a defined profile must not refuse: %v", err)
	}
}

func TestWebDisableIPTypesAppliesToScan(t *testing.T) {
	const body = "Copyright (c) 2024 Example Corporation. All rights reserved.\n"
	plain, _ := startForOptions(t, "", ScanOptions{})
	if !optScan(t, plain, "c.txt", body).types()["INTELLECTUAL_PROPERTY"] {
		t.Fatal("control: the copyright notice must be reported without --disable-ip-types")
	}
	ws, _ := startForOptions(t, "", ScanOptions{DisableIPTypes: []string{"copyright"}})
	got := optScan(t, ws, "c.txt", body).types()
	t.Logf("types without the flag: %v; with --disable-ip-types copyright: %v", optScan(t, plain, "c.txt", body).types(), got)
	if got["INTELLECTUAL_PROPERTY"] {
		t.Errorf("--disable-ip-types copyright must drop the copyright finding, got %v", got)
	}
}

func TestWebValidatorBudgetAppliesToScan(t *testing.T) {
	plain, _ := startForOptions(t, "", ScanOptions{})
	if optScan(t, plain, "m.txt", optMixed).Incomplete {
		t.Fatal("control: a scan without a budget must be complete")
	}
	budgets := map[string]execguard.ValidatorBudget{} // what --validator-budget all=1ns expands to
	for _, name := range core.CheckNames() {
		budgets[name] = execguard.ValidatorBudget{TimeLimit: time.Nanosecond}
	}
	ws, _ := startForOptions(t, "", ScanOptions{ValidatorBudgets: budgets})
	if !optScan(t, ws, "m.txt", optMixed).Incomplete {
		t.Errorf("--validator-budget all=1ns must make the scan incomplete, as on --file")
	}
}

// captureStderr runs fn with os.Stderr replaced by a pipe and returns what fn wrote to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() { b, _ := io.ReadAll(r); done <- string(b) }()
	func() {
		defer func() { os.Stderr = saved; w.Close() }()
		fn()
	}()
	return <-done
}

func TestWebDebugWritesToServerStderrNotTheResponse(t *testing.T) {
	const ssn = "449-87-4100"
	run := func(debug bool) (stderr string, resp string) {
		ws, _ := startForOptions(t, "", ScanOptions{Debug: debug})
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, _ := mw.CreateFormFile("files", "d.txt")
		_, _ = io.WriteString(fw, "ssn "+ssn+"\n")
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/scan", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		stderr = captureStderr(t, func() { ws.handleScan(rec, req) })
		return stderr, rec.Body.String()
	}
	off, offBody := run(false)
	on, onBody := run(true)
	t.Logf("stderr with --debug:\n%.600s", on)
	if len(on) <= len(off) {
		t.Errorf("--debug must add debug lines to stderr: %d bytes with, %d without", len(on), len(off))
	}
	if len(onBody) != len(offBody) && !strings.Contains(onBody, `"success":true`) {
		t.Errorf("debug must not change the /scan response")
	}
	if strings.Contains(strings.ToLower(onBody), "debug") {
		t.Errorf("debug lines must stay out of the /scan response")
	}
	if strings.Contains(on, ssn) {
		t.Errorf("the debug log carries the matched value %q", ssn)
	}
}

// A profile's own validator settings reach the scan (ScanConfig.Profile), and --disable-ip-types still
// outranks the profile's list, as docs/configuration.md says it does on --file.
func TestWebProfileValidatorSettingsAndFlagPrecedence(t *testing.T) {
	const body = "Copyright (c) 2024 Example Corporation. All rights reserved.\n"
	cfg := writeConfig(t, "profiles:\n  nocopy:\n    checks: all\n    enable_preprocessors: true\n"+
		"    validators:\n      intellectual_property:\n        disabled_types:\n          - copyright\n")

	ws, err := startForOptions(t, cfg, ScanOptions{ProfileName: "nocopy"})
	if err != nil {
		t.Fatal(err)
	}
	if got := optScan(t, ws, "c.txt", body).types(); got["INTELLECTUAL_PROPERTY"] {
		t.Errorf("the profile disables copyright, but a copyright finding was reported: %v", got)
	}

	ws, err = startForOptions(t, cfg, ScanOptions{ProfileName: "nocopy", DisableIPTypes: []string{"patent"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := optScan(t, ws, "c.txt", body).types(); !got["INTELLECTUAL_PROPERTY"] {
		t.Errorf("--disable-ip-types patent replaces the profile's list, so copyright must be reported again: %v", got)
	}
}
