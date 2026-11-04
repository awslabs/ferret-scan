// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// The web UI's suppression handlers, driven with the bodies app.js sends (#866). Before the fix: an
// edit dropped the expiry whatever it sent, the add dialog's expiry was ignored, the undo of a delete
// restored nothing and reported success, an action on a duplicated id changed whichever rule came
// first, and a file named q&a.txt was hashed as qa.txt.

var (
	ruleExpiry = time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)
	newExpiry  = time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)
)

// handlerMatch is a finding to hang a rule on; the handlers never see its text.
func handlerMatch(line int) detector.Match {
	return detector.Match{Type: "SSN", Text: "fixture-value", Filename: "roster.txt", LineNumber: line, Validator: "ssn"}
}

// webWithTwoRules is a server whose suppression file holds two enabled rules: SUP-00000001 expiring
// 2027-06-30 and SUP-00000002 with no expiry.
func webWithTwoRules(t *testing.T) (*WebServer, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "suppressions.yaml")
	mgr := suppressions.NewSuppressionManager(path)
	at := ruleExpiry
	if err := mgr.AddSuppression(handlerMatch(1), "first", "tester", &at); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddSuppression(handlerMatch(2), "second", "tester", nil); err != nil {
		t.Fatal(err)
	}
	return NewWebServerWithOptions("0", "127.0.0.1", "", path, nil), path
}

// post sends body (marshalled unless it is already a string) to a handler and decodes the reply.
func post(t *testing.T, h http.HandlerFunc, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, ok := body.(string)
	if !ok {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		raw = string(b)
	}
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(raw)))
	var reply map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &reply)
	return rec.Code, reply
}

// rulesOnDisk reloads the file, so an assertion reads what was saved rather than what is cached.
func rulesOnDisk(t *testing.T, path string) []suppressions.SuppressionRule {
	t.Helper()
	return suppressions.NewSuppressionManager(path).ListSuppressions()
}

func fileBytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func expiryOf(t *testing.T, path, id string) *time.Time {
	t.Helper()
	for _, r := range rulesOnDisk(t, path) {
		if r.ID == id {
			return r.ExpiresAt
		}
	}
	t.Fatalf("no rule %s on disk", id)
	return nil
}

func sameInstant(a *time.Time, b time.Time) bool { return a != nil && a.Equal(b) }

func TestEditKeepsSetsAndClearsTheExpiry(t *testing.T) {
	edit := func(ws *WebServer, extra string) (int, map[string]any) {
		return post(t, ws.handleSuppressionsEdit, "/suppressions/edit",
			`{"id":"SUP-00000001","reason":"edited","created_by":"tester","enabled":true`+extra+`}`)
	}

	t.Run("a new date is set", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		if code, reply := edit(ws, `,"expires_at":"2027-12-31T00:00:00.000Z"`); code != 200 || reply["success"] != true {
			t.Fatalf("edit: %d %v", code, reply)
		}
		if got := expiryOf(t, path, "SUP-00000001"); !sameInstant(got, newExpiry) {
			t.Errorf("expires_at = %v after an edit that set 2027-12-31", got)
		}
	})
	t.Run("the modal re-sending the same date keeps it", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		edit(ws, `,"expires_at":"2027-06-30T00:00:00.000Z"`)
		if got := expiryOf(t, path, "SUP-00000001"); !sameInstant(got, ruleExpiry) {
			t.Errorf("expires_at = %v after a reason-only edit; the edit made the rule permanent", got)
		}
	})
	t.Run("an omitted expires_at keeps it", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		edit(ws, ``)
		if got := expiryOf(t, path, "SUP-00000001"); !sameInstant(got, ruleExpiry) {
			t.Errorf("expires_at = %v after an edit that did not mention it", got)
		}
	})
	t.Run("null clears it", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		edit(ws, `,"expires_at":null`)
		if got := expiryOf(t, path, "SUP-00000001"); got != nil {
			t.Errorf("expires_at = %v after an edit that sent null", got)
		}
	})
	t.Run("a value that is not a date is a 400 and changes nothing", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		before := fileBytes(t, path)
		code, reply := edit(ws, `,"expires_at":"not-a-date"`)
		if code != http.StatusBadRequest || reply["success"] != false {
			t.Errorf("edit with expires_at \"not-a-date\": %d %v, want 400", code, reply)
		}
		if fileBytes(t, path) != before {
			t.Error("a refused edit rewrote the suppression file")
		}
	})
	t.Run("the undo of an edit puts the expiry back", func(t *testing.T) {
		ws, path := webWithTwoRules(t)
		edit(ws, `,"expires_at":"2027-12-31T00:00:00.000Z"`)
		// What undoLastOperation sends for an edit.
		post(t, ws.handleSuppressionsEdit, "/suppressions/edit", map[string]any{
			"id": "SUP-00000001", "reason": "first", "created_by": "tester", "enabled": true,
			"expires_at": ruleExpiry.Format(time.RFC3339),
		})
		if got := expiryOf(t, path, "SUP-00000001"); !sameInstant(got, ruleExpiry) {
			t.Errorf("expires_at = %v after the undo, want the original 2027-06-30", got)
		}
	})
}

func TestCreateStoresTheExpiryItIsGiven(t *testing.T) {
	ws, path := webWithTwoRules(t)
	finding := func(line int) map[string]any {
		return map[string]any{"type": "SSN", "text": "another-value", "filename": "roster.txt", "line_number": line}
	}
	week := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Second)
	if code, reply := post(t, ws.handleSuppressionsCreate, "/suppressions/create", map[string]any{
		"reason": "with expiry", "expires_at": week.Format(time.RFC3339), "finding_data": finding(10),
	}); code != 200 || reply["success"] != true {
		t.Fatalf("create: %d %v", code, reply)
	}
	if code, _ := post(t, ws.handleSuppressionsCreate, "/suppressions/create", map[string]any{
		"reason": "without", "finding_data": finding(11),
	}); code != 200 {
		t.Fatalf("create without expiry: %d", code)
	}
	before := fileBytes(t, path)
	if code, _ := post(t, ws.handleSuppressionsCreate, "/suppressions/create", map[string]any{
		"reason": "bad", "expires_at": "next tuesday", "finding_data": finding(12),
	}); code != http.StatusBadRequest {
		t.Errorf("create with expires_at \"next tuesday\": %d, want 400", code)
	}
	if fileBytes(t, path) != before {
		t.Error("a refused create rewrote the suppression file")
	}

	rules := rulesOnDisk(t, path)
	if len(rules) != 4 {
		t.Fatalf("%d rules, want 4", len(rules))
	}
	if !sameInstant(rules[2].ExpiresAt, week) {
		t.Errorf("the created rule's expires_at = %v, want %v: create ignored the expiry it was sent", rules[2].ExpiresAt, week)
	}
	if !rules[2].Enabled || rules[3].ExpiresAt != nil {
		t.Errorf("created rules: %+v", rules[2:])
	}
}

// TestUndoOfADeleteRestoresTheRuleAsItWas: remove, then post what undoLastOperation sends — the rule
// as GET /suppressions listed it, with its position — and the file is byte-identical to before.
func TestUndoOfADeleteRestoresTheRuleAsItWas(t *testing.T) {
	ws, path := webWithTwoRules(t)
	before := fileBytes(t, path)

	rec := httptest.NewRecorder()
	ws.handleSuppressions(rec, httptest.NewRequest(http.MethodGet, "/suppressions", nil))
	var listed struct {
		Rules []map[string]any `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed.Rules) != 2 {
		t.Fatalf("GET /suppressions: %v %s", err, rec.Body.String())
	}

	if code, reply := post(t, ws.handleSuppressionsRemove, "/suppressions/remove", map[string]any{"id": "SUP-00000001"}); code != 200 {
		t.Fatalf("remove: %d %v", code, reply)
	}
	restore := map[string]any{}
	for k, v := range listed.Rules[0] {
		restore[k] = v
	}
	restore["position"] = 0
	code, reply := post(t, ws.handleSuppressionsBulkCreate, "/suppressions/bulk-create", map[string]any{"rules": []any{restore}})
	if code != 200 || reply["success"] != true || reply["created"] != float64(1) {
		t.Fatalf("undo-delete: %d %v", code, reply)
	}
	if after := fileBytes(t, path); after != before {
		t.Errorf("the undo did not restore the file:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// Restoring it again creates nothing, and says so instead of reporting success.
	code, reply = post(t, ws.handleSuppressionsBulkCreate, "/suppressions/bulk-create", map[string]any{"rules": []any{restore}})
	if code != 200 || reply["success"] != false || reply["created"] != float64(0) {
		t.Errorf("restoring a rule that exists: %d %v, want success false and created 0", code, reply)
	}
	if failed, _ := reply["failed"].([]any); len(failed) != 1 {
		t.Errorf("failed = %v, want the one refusal named", reply["failed"])
	}
}

// TestADuplicatedIDIsRefused: with two rules sharing an id, every id-keyed action is a 409 and the file
// is untouched, instead of acting on whichever rule comes first.
func TestADuplicatedIDIsRefused(t *testing.T) {
	ws, path := webWithTwoRules(t)
	dup := strings.Replace(fileBytes(t, path), "id: SUP-00000002", "id: SUP-00000001", 1)
	if err := os.WriteFile(path, []byte(dup), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, path)
	one := map[string]any{"id": "SUP-00000001", "reason": "x", "created_by": "y", "enabled": false}
	many := map[string]any{"ids": []string{"SUP-00000001"}, "expires_at": nil}
	for name, call := range map[string]func() (int, map[string]any){
		"disable":                func() (int, map[string]any) { return post(t, ws.handleSuppressionsDisable, "/", one) },
		"remove":                 func() (int, map[string]any) { return post(t, ws.handleSuppressionsRemove, "/", one) },
		"edit":                   func() (int, map[string]any) { return post(t, ws.handleSuppressionsEdit, "/", one) },
		"enable":                 func() (int, map[string]any) { return post(t, ws.handleSuppressionsEnable, "/", one) },
		"bulk-enable":            func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkEnable, "/", many) },
		"bulk-disable":           func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkDisable, "/", many) },
		"bulk-delete":            func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkDelete, "/", many) },
		"bulk-update-expiration": func() (int, map[string]any) { return post(t, ws.handleSuppressionsBulkUpdateExpiration, "/", many) },
	} {
		if code, reply := call(); code != http.StatusConflict || reply["success"] != false {
			t.Errorf("%s on a duplicated id: %d %v, want 409", name, code, reply)
		}
	}
	if fileBytes(t, path) != before {
		t.Error("an action on a duplicated id rewrote the suppression file")
	}
}

// TestEnableAndBulkExpirationAreUnchanged are the controls: both already kept or applied the expiry.
func TestEnableAndBulkExpirationAreUnchanged(t *testing.T) {
	ws, path := webWithTwoRules(t)
	post(t, ws.handleSuppressionsDisable, "/", map[string]any{"id": "SUP-00000001"})
	post(t, ws.handleSuppressionsEnable, "/", map[string]any{"id": "SUP-00000001"})
	if got := expiryOf(t, path, "SUP-00000001"); !sameInstant(got, ruleExpiry) {
		t.Errorf("disable then enable left expires_at = %v", got)
	}
	post(t, ws.handleSuppressionsBulkUpdateExpiration, "/", map[string]any{"ids": []string{"SUP-00000001", "SUP-00000002"}, "expires_at": newExpiry.Format(time.RFC3339)})
	for _, id := range []string{"SUP-00000001", "SUP-00000002"} {
		if got := expiryOf(t, path, id); !sameInstant(got, newExpiry) {
			t.Errorf("bulk-update-expiration left %s at %v", id, got)
		}
	}
	post(t, ws.handleSuppressionsBulkUpdateExpiration, "/", map[string]any{"ids": []string{"SUP-00000002"}})
	if got := expiryOf(t, path, "SUP-00000002"); got != nil {
		t.Errorf("bulk-update-expiration with expires_at omitted left %v; its contract is omitted = permanent", got)
	}
}

// TestAFilenameWithStrippedCharactersKeepsItsIdentity: the web scan hashed sanitizeFilenameForDisplay's
// copy of the upload name, which drops & (and < > " '), so q&a.txt and its CLI rules never met.
func TestAFilenameWithStrippedCharactersKeepsItsIdentity(t *testing.T) {
	dir := t.TempDir()
	content := []byte("Contact: jane.roe@contoso-example.net\ncard number: 4539000000123457\n")
	cliPath := filepath.Join(dir, "q&a.txt")
	if err := os.WriteFile(cliPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	upload := filepath.Join(dir, "ferret_upload_1_0_probe.txt") // the temp name the web scan reads
	if err := os.WriteFile(upload, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cliScan := func(t *testing.T) []detector.Match {
		t.Helper()
		result, err := core.ScanFileCtx(context.Background(), core.ScanConfig{FilePath: cliPath, EnablePreprocessors: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Matches) != 2 {
			t.Fatalf("the CLI scan found %d findings, want 2: the fixture is not detected", len(result.Matches))
		}
		return result.Matches
	}

	t.Run("a CLI rule suppresses in the web scan", func(t *testing.T) {
		rules := filepath.Join(t.TempDir(), "rules.yaml")
		if err := suppressions.NewSuppressionManager(rules).GenerateSuppressionRules(cliScan(t), "cli", true); err != nil {
			t.Fatal(err)
		}
		ws := NewWebServerWithOptions("0", "127.0.0.1", "", rules, nil)
		unsuppressed, suppressed, _, _, err := ws.runFullCLIScan(context.Background(), upload, "q&a.txt", "all", "", false, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(suppressed) != 2 || len(unsuppressed) != 0 {
			t.Errorf("the web scan of q&a.txt suppressed %d of 2 with the CLI's rules; the upload was hashed under "+
				"another name", len(suppressed))
		}
		for _, m := range unsuppressed {
			t.Logf("unsuppressed, filename %q", m.Filename)
		}
	})

	t.Run("a web rule suppresses on the CLI", func(t *testing.T) {
		rules := filepath.Join(t.TempDir(), "rules.yaml")
		ws := NewWebServerWithOptions("0", "127.0.0.1", "", rules, nil)
		unsuppressed, _, _, _, err := ws.runFullCLIScan(context.Background(), upload, "q&a.txt", "all", "", false, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range unsuppressed {
			// What app.js posts from a result row (it sends the context fields the hash needs).
			body := map[string]any{"reason": "web", "finding_data": map[string]any{
				"type": m.Type, "text": m.Text, "filename": m.Filename, "line_number": m.LineNumber,
				"confidence": m.Confidence, "full_line": m.Context.FullLine,
				"before_text": m.Context.BeforeText, "after_text": m.Context.AfterText,
			}}
			if code, reply := post(t, ws.handleSuppressionsCreate, "/suppressions/create", body); code != 200 {
				t.Fatalf("create: %d %v", code, reply)
			}
		}
		mgr := suppressions.NewSuppressionManager(rules)
		n := 0
		for _, m := range cliScan(t) {
			if ok, _ := mgr.IsSuppressed(m); ok {
				n++
			}
		}
		if n != 2 {
			t.Errorf("rules created in the web UI for q&a.txt suppressed %d of 2 on the CLI", n)
		}
	})
}
