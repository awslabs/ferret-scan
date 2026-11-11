// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/router"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

const (
	// attachmentAuthor is the author of BOTH embedded documents, so their two AUTHOR_INFO findings
	// differ only by member. The metadata path names those findings "<container> -> <member>"; text
	// in an embedded document's body is attributed to the container, so the value lives in docProps.
	attachmentAuthor = "Jordan Alvarez"
	// containerAuthor is the container's own author: the control, named by the upload alone.
	containerAuthor = "Morgan Ellis"
	// containerSSN is a value in an upload's own text.
	containerSSN = "536-90-4271"
)

// coreProps is a docProps/core.xml part naming creator as the author.
func coreProps(creator string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>` + creator + `</dc:creator></cp:coreProperties>`)
}

// minimalDocx builds a valid OOXML word document in memory (TEST_PLAN dimension 12: no fixture on
// disk), with extras as additional package parts.
func minimalDocx(t *testing.T, body string, extras map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	parts := map[string][]byte{
		"[Content_Types].xml": []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`</Types>`),
		"_rels/.rels": []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`),
		"word/document.xml": []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`),
	}
	for k, v := range extras {
		parts[k] = v
	}
	names := make([]string, 0, len(parts))
	for k := range parts {
		names = append(names, k)
	}
	sort.Strings(names)
	// [Content_Types].xml sorts first, as OPC requires.
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if _, err := w.Write(parts[name]); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// twoAttachmentDocx is a document whose two embedded documents have the same author.
func twoAttachmentDocx(t *testing.T) []byte {
	t.Helper()
	child := minimalDocx(t, "Embedded child document.", map[string][]byte{"docProps/core.xml": coreProps(attachmentAuthor)})
	return minimalDocx(t, "Outer body.", map[string][]byte{
		"docProps/core.xml":               coreProps(containerAuthor),
		"word/embeddings/oleObject1.docx": child,
		"word/embeddings/oleObject2.docx": child,
	})
}

// webServerWith builds a WebServer the way Start() does, with an empty strict-loaded config and the
// given suppression file, and returns its handler.
func webServerWith(t *testing.T, suppressionFile string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfgPath, suppressionFile, nil)
	cfg, err := config.LoadConfigStrict(cfgPath)
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	ws.cachedConfig = cfg
	if err := ws.setupRoutesWithValidation(); err != nil {
		t.Fatalf("setup routes: %v", err)
	}
	return ws.createSecureServer("0").Handler
}

// postUpload posts one file to /scan with the given checks, as the front end does for a dropped file.
func postUpload(t *testing.T, h http.Handler, name, relPath, checks string, content []byte) ScanResponse {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("files", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"checks": checks, "confidence": "all"}
	if relPath != "" {
		fields["relative_path"] = relPath
	}
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/scan %s: HTTP %d: %s", name, rec.Code, truncate(rec.Body.String(), 300))
	}
	var resp ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("/scan %s: not JSON (%v): %s", name, err, truncate(rec.Body.String(), 300))
	}
	if !resp.Success {
		t.Fatalf("/scan %s: success=false: %s", name, resp.Error)
	}
	return resp
}

// TestAttachmentFindingsKeepTheirMemberName holds /scan to the CLI's name for a finding inside an
// embedded attachment: "<upload> -> <member>". It used to be the upload alone, so the two attachments
// below, which carry the same value, produced two findings with one name (#924). Fails on the parent
// commit, where both are "reports/outer.docx".
func TestAttachmentFindingsKeepTheirMemberName(t *testing.T) {
	resp := postUpload(t, webServerWith(t, filepath.Join(t.TempDir(), "none.yaml")), "outer.docx", "reports/outer.docx", "METADATA", twoAttachmentDocx(t))

	var members, container []string
	for _, r := range resp.Results {
		if r.Type != "AUTHOR_INFO" {
			continue
		}
		switch {
		case strings.Contains(r.Text, attachmentAuthor):
			members = append(members, r.Filename)
		case strings.Contains(r.Text, containerAuthor):
			container = append(container, r.Filename)
		}
	}
	sort.Strings(members)
	want := []string{"reports/outer.docx -> oleObject1.docx", "reports/outer.docx -> oleObject2.docx"}
	if strings.Join(members, "|") != strings.Join(want, "|") {
		t.Errorf("the attachments' AUTHOR_INFO findings are named %q; want %q", members, want)
	}
	// The control: the container's own finding is named by the upload alone, as before.
	if len(container) != 1 || container[0] != "reports/outer.docx" {
		t.Errorf("the container's own AUTHOR_INFO finding is named %q; want [reports/outer.docx]", container)
	}
}

// TestCLIRuleSuppressesAttachmentFindingOnTheWeb is the suppression half: a rule the CLI generates for
// a finding inside an attachment must suppress the same finding uploaded to /scan. The hash folds in
// filepath.Base of the name, and the CLI's name keeps the member, so the web's name has to as well.
// Fails on the parent commit, where the attachment findings stay unsuppressed.
func TestCLIRuleSuppressesAttachmentFindingOnTheWeb(t *testing.T) {
	dir := t.TempDir()
	docx := twoAttachmentDocx(t)
	onDisk := filepath.Join(dir, "outer.docx")
	if err := os.WriteFile(onDisk, docx, 0o600); err != nil {
		t.Fatal(err)
	}
	cli, err := core.ScanFile(core.ScanConfig{
		FilePath:            filepath.ToSlash(onDisk),
		Checks:              []string{"METADATA"},
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	var cliMembers int
	for _, m := range cli.Matches {
		if strings.Contains(m.Filename, memberSeparator) {
			cliMembers++
		}
	}
	if cliMembers < 2 || cliMembers == len(cli.Matches) {
		t.Fatalf("the CLI scan of the fixture found %d findings, %d inside attachments; this test needs both "+
			"kinds (at least 2 inside attachments) to show anything", len(cli.Matches), cliMembers)
	}

	rules := filepath.Join(dir, "rules.yaml")
	if err := suppressions.NewSuppressionManager(rules).GenerateSuppressionRules(cli.Matches, "generated by the CLI", true); err != nil {
		t.Fatalf("generate rules: %v", err)
	}

	resp := postUpload(t, webServerWith(t, rules), "outer.docx", "", "METADATA", docx)
	if len(resp.Results) != 0 || len(resp.Suppressed) != len(cli.Matches) {
		var left []string
		for _, r := range resp.Results {
			left = append(left, r.Type+" in "+r.Filename)
		}
		t.Fatalf("with the CLI's %d rules (%d for findings inside attachments), /scan returned %d unsuppressed "+
			"(%q) and %d suppressed; want 0 and %d", len(cli.Matches), cliMembers, len(resp.Results), left,
			len(resp.Suppressed), len(cli.Matches))
	}
}

// TestWebRuleForTheUploadNameStillSuppresses keeps a rule created in the web UI before #924 working:
// it hashed a finding inside an attachment under the upload's name alone, and must still suppress
// that finding now that the finding is named by its member. Passes on the parent commit, which named
// it that way; fails if suppressedUnderUploadName stops trying the older name.
func TestWebRuleForTheUploadNameStillSuppresses(t *testing.T) {
	dir := t.TempDir()
	docx := twoAttachmentDocx(t)
	onDisk := filepath.Join(dir, "outer.docx")
	if err := os.WriteFile(onDisk, docx, 0o600); err != nil {
		t.Fatal(err)
	}
	scanned, err := core.ScanFile(core.ScanConfig{
		FilePath:            filepath.ToSlash(onDisk),
		Checks:              []string{"METADATA"},
		EnablePreprocessors: true,
		LogWriter:           io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	// The findings as /scan named them before: every one by the upload alone.
	legacy := append([]detector.Match(nil), scanned.Matches...)
	for i := range legacy {
		legacy[i].Filename = "outer.docx"
	}
	rules := filepath.Join(dir, "rules.yaml")
	if err := suppressions.NewSuppressionManager(rules).GenerateSuppressionRules(legacy, "created in the web UI", true); err != nil {
		t.Fatalf("generate rules: %v", err)
	}

	resp := postUpload(t, webServerWith(t, rules), "outer.docx", "", "METADATA", docx)
	if len(resp.Results) != 0 {
		var left []string
		for _, r := range resp.Results {
			left = append(left, r.Type+" in "+r.Filename)
		}
		t.Fatalf("rules written for the upload's name left %d finding(s) unsuppressed: %q", len(resp.Results), left)
	}
}

// TestNULTextUploadIsDisclosedAsCannotParse holds /scan to the CLI for a text file carrying a NUL
// byte: the router refuses it (router.ReasonRefusedNotText), the CLI reports it as `cannot parse`, and
// the web used to answer success with no finding and no disclosure, because the refusal was judged by
// router.CanProcessType, which sniffs such a file as not-text (2 of the 639 public corpus files,
// #924). Fails on the parent commit.
func TestNULTextUploadIsDisclosedAsCannotParse(t *testing.T) {
	content := []byte("name,employee_id,ssn\nAlice Moreno,1001," + containerSSN + "\ntrailer\x00\n")
	resp := postUpload(t, webServerWith(t, filepath.Join(t.TempDir(), "none.yaml")), "export.csv", "", "SSN", content)
	if !resp.Incomplete {
		t.Fatalf("a text upload the router refused for its NUL byte is presented as examined: %+v", resp)
	}
	if len(resp.NotExamined) != 1 || resp.NotExamined[0].Path != "export.csv" || resp.NotExamined[0].Cause != "cannot parse" {
		t.Fatalf("not_examined = %+v; want export.csv with cause %q, as the CLI reports it", resp.NotExamined, "cannot parse")
	}
	if !strings.HasPrefix(resp.NotExamined[0].Detail, router.ReasonRefusedNotText) {
		t.Errorf("detail %q does not carry the router's reason", resp.NotExamined[0].Detail)
	}
}

// TestRouterRefusalOfNULTextIsCannotParse pins the constructor: the NUL refusal is lost coverage
// whatever router.CanProcessType says, and its cause is the CLI's.
func TestRouterRefusalOfNULTextIsCannotParse(t *testing.T) {
	r := routerRefusal("export.csv", router.ReasonRefusedNotText+": file is text but contains NUL byte(s)", false)
	if !r.coverageGap {
		t.Error("a text file the router refused for a NUL byte is lost coverage and must be disclosed")
	}
	if r.cause != coverage.CauseUnparseable || r.cause.String() != "cannot parse" {
		t.Errorf("cause = %q, want %q", r.cause.String(), "cannot parse")
	}
}

// TestUploadMatchName covers the renaming rule on its own: the temp file is replaced by the upload in
// both spellings the producers use, the member is kept, and anything else is the upload alone.
func TestUploadMatchName(t *testing.T) {
	const temp = "/srv/tmp/ferret_upload_1_0_42.pptx"
	for _, tc := range []struct{ scanned, want string }{
		{temp, "deck/slides.pptx"},
		{"ferret_upload_1_0_42.pptx -> image3.png", "deck/slides.pptx -> image3.png"},
		{temp + " -> ppt/media/image3.png", "deck/slides.pptx -> ppt/media/image3.png"},
		{"ferret_upload_1_0_42.pptx -> ", "deck/slides.pptx"},
		{"other.pptx -> image3.png", "deck/slides.pptx"},
	} {
		if got := uploadMatchName(tc.scanned, temp, "deck/slides.pptx"); got != tc.want {
			t.Errorf("uploadMatchName(%q) = %q, want %q", tc.scanned, got, tc.want)
		}
	}
}
