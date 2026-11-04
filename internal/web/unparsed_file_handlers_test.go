// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// Every web UI action that writes the suppression file, against a file that does not parse (#880). The
// manager loads such a file as empty; a create used to write that empty state plus the new rule over
// the operator's file, an enable reported success having changed nothing, and the rest answered
// "not found". Each is now a 409 naming the YAML error, and the file is byte-identical.

// brokenTail is the issue's one bad edit.
const brokenTail = "    - id: SUP-00000003\n      hash: [unclosed\n"

// webWithBrokenFile is webWithTwoRules with brokenTail appended, so its file no longer parses.
func webWithBrokenFile(t *testing.T) (*WebServer, string, string) {
	t.Helper()
	ws, path := webWithTwoRules(t)
	broken := fileBytes(t, path) + brokenTail
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	return ws, path, broken
}

func TestEveryWriteToAFileThatDidNotParseIsA409(t *testing.T) {
	ws, path, before := webWithBrokenFile(t)
	// The YAML error the reply must name, with its line.
	_, yamlErr := suppressions.CheckSuppressionFile([]byte(before))
	if yamlErr == nil || !strings.HasPrefix(yamlErr.Error(), "yaml: line ") {
		t.Fatalf("the fixture's YAML error is %v, want one naming a line", yamlErr)
	}
	finding := map[string]any{"type": "SSN", "text": "another-value", "filename": "roster.txt", "line_number": 10}
	one := map[string]any{"id": "SUP-00000001", "reason": "x", "created_by": "y", "enabled": true}
	many := map[string]any{"ids": []string{"SUP-00000001"}, "expires_at": nil}
	restore := map[string]any{"rules": []any{map[string]any{
		"ID": "SUP-00000009", "Hash": strings.Repeat("ab", 32), "Enabled": true, "position": 0,
	}}}
	for name, call := range map[string]func() (int, map[string]any){
		"create": func() (int, map[string]any) {
			return post(t, ws.handleSuppressionsCreate, "/", map[string]any{"reason": "r", "finding_data": finding})
		},
		"edit":                   func() (int, map[string]any) { return post(t, ws.handleSuppressionsEdit, "/", one) },
		"remove":                 func() (int, map[string]any) { return post(t, ws.handleSuppressionsRemove, "/", one) },
		"enable":                 func() (int, map[string]any) { return post(t, ws.handleSuppressionsEnable, "/", one) },
		"disable":                func() (int, map[string]any) { return post(t, ws.handleSuppressionsDisable, "/", one) },
		"bulk-enable":            func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkEnable, "/", many) },
		"bulk-disable":           func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkDisable, "/", many) },
		"bulk-delete":            func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkDelete, "/", many) },
		"bulk-update-expiration": func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkUpdateExpiration, "/", many) },
		"bulk-create findings": func() (int, map[string]any) {
			return post(t, ws.handleSuppressionsBulkCreate, "/", map[string]any{"reason": "r", "findings": []any{finding}})
		},
		"bulk-create rules (undo of a delete)": func() (int, map[string]any) {
			return post(t, ws.handleSuppressionsBulkCreate, "/", restore)
		},
	} {
		code, reply := call()
		msg, _ := reply["error"].(string)
		if code != http.StatusConflict || reply["success"] != false {
			t.Errorf("%s on a file that did not parse: %d %v, want 409", name, code, reply)
			continue
		}
		want := "suppression file " + path + " could not be parsed (" + yamlErr.Error() + "); " +
			"fix it or move it aside before regenerating; nothing was written"
		if msg != want {
			t.Errorf("%s: error %q\nwant %q", name, msg, want)
		}
	}
	if after := fileBytes(t, path); after != before {
		t.Errorf("a refused action rewrote the file that did not parse:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestTheReadOnlyEndpointsStillAnswer are the controls on the same file: the list (empty, because the
// file loaded as empty), the hash check, and the download, which hands back the file as it is so it
// can be fixed.
func TestTheReadOnlyEndpointsStillAnswer(t *testing.T) {
	ws, path, before := webWithBrokenFile(t)

	rec := httptest.NewRecorder()
	ws.handleSuppressions(rec, httptest.NewRequest(http.MethodGet, "/suppressions", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /suppressions: %d %s", rec.Code, rec.Body.String())
	}
	if code, reply := post(t, ws.handleSuppressionsCheckHash, "/", map[string]any{"finding_data": map[string]any{"type": "SSN"}}); code != http.StatusOK || reply["hash"] == nil {
		t.Errorf("check-hash: %d %v", code, reply)
	}
	rec = httptest.NewRecorder()
	ws.handleSuppressionsDownload(rec, httptest.NewRequest(http.MethodGet, "/suppressions/download", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != before {
		t.Errorf("download: %d, body equal to the file: %v", rec.Code, rec.Body.String() == before)
	}
	if fileBytes(t, path) != before {
		t.Error("a read-only endpoint rewrote the file")
	}
}

// TestAFixedFileIsWritableAgain: the server's cached manager reloads when the file changes, so once the
// operator fixes the file the same create succeeds, and a server whose file does not exist yet still
// creates it.
func TestAFixedFileIsWritableAgain(t *testing.T) {
	ws, path, broken := webWithBrokenFile(t)
	create := map[string]any{"reason": "r", "finding_data": map[string]any{"type": "SSN", "text": "v", "filename": "roster.txt", "line_number": 10}}
	if code, _ := post(t, ws.handleSuppressionsCreate, "/", create); code != http.StatusConflict {
		t.Fatalf("create on the broken file: %d, want 409", code)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSuffix(broken, brokenTail)), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if code, reply := post(t, ws.handleSuppressionsCreate, "/", create); code != http.StatusOK {
		t.Fatalf("create on the fixed file: %d %v", code, reply)
	}
	if got := len(rulesOnDisk(t, path)); got != 3 {
		t.Errorf("the fixed file holds %d rules after a create, want 3", got)
	}

	missing := filepath.Join(t.TempDir(), "new", "suppressions.yaml")
	fresh := NewWebServerWithOptions("0", "127.0.0.1", "", missing, nil)
	if code, reply := post(t, fresh.handleSuppressionsCreate, "/", create); code != http.StatusOK {
		t.Fatalf("create with no file yet: %d %v", code, reply)
	}
	if got := len(rulesOnDisk(t, missing)); got != 1 {
		t.Errorf("the created file holds %d rules, want 1", got)
	}
}
