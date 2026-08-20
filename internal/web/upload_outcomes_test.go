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
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// scanResponseFor uploads the given (filename, content) pairs to /scan and returns the decoded
// response. checks narrows the validator set so the assertions do not depend on every
// validator's behaviour.
func scanResponseFor(t *testing.T, checks string, files ...[2]string) ScanResponse {
	t.Helper()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, f := range files {
		w, err := mw.CreateFormFile("files", f[0])
		if err != nil {
			t.Fatalf("CreateFormFile(%q): %v", f[0], err)
		}
		if _, err := w.Write([]byte(f[1])); err != nil {
			t.Fatalf("write %q: %v", f[0], err)
		}
	}
	if err := mw.WriteField("checks", checks); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("confidence", "all"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	ws := NewWebServerWithOptions("0", "127.0.0.1", "", "", nil)
	req := httptest.NewRequest(http.MethodPost, "/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	ws.handleScan(rec, req)

	var got ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, rec.Body.String())
	}
	return got
}

// A file the tool cannot scan must not discard the findings of the files uploaded with it.
//
// The batch loop used to `sendError` and return on the first per-file error, throwing away every
// match already collected and never looking at the remaining files. Measured before the fix:
// uploading a file containing an SSN together with one unsupported .bin returned
// `success: false` with ZERO results, while the CLI reported the same SSN at HIGH 100 and exited
// 0 (#416).
//
// This matters because dragging a folder in is the web UI's primary interaction, and ordinary
// folders hold files this tool cannot scan — .DS_Store, Thumbs.db, partial downloads. Any one of
// them turned a scan that had already found real PII into "scan failed", and the operator's
// reasonable response to that is to retry rather than to look at results.
func TestUnsupportedFileDoesNotDiscardTheBatch(t *testing.T) {
	const ssn = "Employee SSN: 452-11-9384\n"
	// Binary bytes with no recognizable type: unscannable at any size.
	opaque := string(bytes.Repeat([]byte{0x00, 0x01, 0x02, 0xff, 0xfe}, 400))

	// Control first: the SSN file alone must report, or the rest of this test proves nothing.
	alone := scanResponseFor(t, "SSN", [2]string{"payroll.txt", ssn})
	if !alone.Success || len(alone.Results) != 1 {
		t.Fatalf("control: success=%v results=%d, want success with 1 finding — the batch "+
			"assertion below is vacuous without it", alone.Success, len(alone.Results))
	}

	// The same file, uploaded beside one the tool cannot scan.
	both := scanResponseFor(t, "SSN",
		[2]string{"payroll.txt", ssn},
		[2]string{"partial.bin", opaque})

	if !both.Success {
		t.Errorf("success=false with error %q: one unscannable file failed the whole request, so "+
			"a real finding in another file is reported as nothing", both.Error)
	}
	if len(both.Results) != 1 {
		t.Errorf("results=%d, want 1: the SSN in payroll.txt must survive an unscannable sibling. "+
			"A finding the tool made and then discarded is worse than one it never made, because "+
			"the operator is told the scan failed rather than that findings were dropped",
			len(both.Results))
	}
}

// An unsupported type is a benign skip, not a coverage loss — the same call the CLI makes via
// router.CanProcessType. Reporting it as incomplete would train operators to ignore the signal
// that matters.
func TestUnsupportedTypeAloneIsNotReportedAsLostCoverage(t *testing.T) {
	opaque := string(bytes.Repeat([]byte{0x00, 0x01, 0x02, 0xff, 0xfe}, 400))
	got := scanResponseFor(t, "SSN", [2]string{"partial.bin", opaque})

	if !got.Success {
		t.Errorf("success=false (error %q): an unsupported type is a benign skip on the CLI "+
			"(exit 0, no findings), and the two surfaces must agree", got.Error)
	}
	if got.Incomplete {
		t.Errorf("incomplete=true (%q): nothing was ever findable in this file, so declaring lost "+
			"coverage overstates it — that is the distinction router.CanProcessType exists to make",
			got.IncompleteReason)
	}
	if len(got.Results) != 0 {
		t.Errorf("results=%d, want 0", len(got.Results))
	}
}

// The error text returned to the client must name the file the OPERATOR uploaded, never the
// server's temp path.
//
// Before the fix the message read
//
//	file type not supported for processing: /var/folders/…/T/ferret_upload_1787252445_0_3245715044.bin
//
// which the uploader cannot act on and which discloses the server's filesystem layout and upload
// naming scheme.
func TestResponsesNeverNameTheServerTempPath(t *testing.T) {
	// A corrupt .docx is the cheap case that actually REACHES the disclosure channel: the
	// router accepts it by extension, extraction then fails, and the reason is reported. An
	// unsupported type would not do — it is a benign skip that emits nothing, so asserting
	// "no temp path" against it passes whether or not the path is there.
	cases := map[string][2]string{
		"corrupt .docx": {"quarterly.docx", string(bytes.Repeat([]byte{0x50, 0x4b, 0x03, 0x04, 0x00, 0xff}, 200))},
		"corrupt .pdf":  {"invoice.pdf", "%PDF-1.4\n" + string(bytes.Repeat([]byte{0xff}, 500))},
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			got := scanResponseFor(t, "SSN", file)
			if !got.Incomplete {
				t.Fatalf("incomplete=false, so nothing was disclosed and this assertion is "+
					"vacuous; reason=%q err=%q", got.IncompleteReason, got.Error)
			}
			for field, s := range map[string]string{
				"error":             got.Error,
				"incomplete_reason": got.IncompleteReason,
			} {
				if strings.Contains(s, "ferret_upload_") {
					t.Errorf("%s names the server's temp file (%q): the operator has no use for it "+
						"and it discloses the upload naming scheme", field, s)
				}
			}
			if !strings.Contains(got.IncompleteReason, file[0]) {
				t.Errorf("incomplete_reason %q does not name the uploaded file %q, so the operator "+
					"cannot tell which file lost coverage", got.IncompleteReason, file[0])
			}
		})
	}
}

// An upload over the limit must be REFUSED and DISCLOSED, never truncated and reported as a
// clean scan.
//
// io.LimitReader + io.Copy returns no error when the limit is reached — it simply stops — so a
// 150MB upload was silently cut to 100MB, scanned, and reported as `success: true` with whatever
// the first 100MB happened to hold. Measured before the fix: an SSN at the 110MB mark produced
// zero findings and no signal of any kind, while the CLI refused the same file and disclosed
// `file too large to scan` at exit 3 (#415).
//
// This is the one case that has to move real bytes: the refusal triggers on how much was
// copied, so nothing smaller exercises it. The body is streamed rather than built in memory, and
// its content is zeros, so the cost is I/O rather than RAM.
func TestOversizeUploadIsRefusedAndDisclosed(t *testing.T) {
	if testing.Short() {
		t.Skip("moves router.MaxFileSize+ bytes through a multipart body")
	}

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer func() { _ = pw.Close() }()
		w, err := mw.CreateFormFile("files", "recording.txt")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		// One byte past the limit is all that is needed to be over it.
		if _, err := io.CopyN(w, zeroReader{}, router.MaxFileSize+1); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := mw.WriteField("checks", "SSN"); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := mw.WriteField("confidence", "all"); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = mw.Close()
	}()

	ws := NewWebServerWithOptions("0", "127.0.0.1", "", "", nil)
	req := httptest.NewRequest(http.MethodPost, "/scan", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	ws.handleScan(rec, req)

	var got ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response is not JSON (%v): %s", err, truncate(rec.Body.String(), 200))
	}

	if !got.Incomplete {
		t.Errorf("incomplete=false: an upload the tool refused for size was reported as a " +
			"complete scan. Everything past the limit went unread, and nothing said so — which is " +
			"the same artifact the CLI's `file too large to scan` disclosure exists to prevent")
	}
	if !strings.Contains(got.IncompleteReason, "too large") {
		t.Errorf("incomplete_reason = %q, want it to name the size limit as the cause; an operator "+
			"cannot act on a reason that does not say what happened", got.IncompleteReason)
	}
	if strings.Contains(got.IncompleteReason, "ferret_upload_") {
		t.Errorf("incomplete_reason names the server temp path: %q", got.IncompleteReason)
	}
}

// zeroReader is an endless source of zero bytes, so the oversize body above costs no memory.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// Every JSON endpoint must bound the body it decodes.
//
// json.NewDecoder(r.Body) reads until EOF, so one large POST was decoded in full — measured, a
// 3MB body was read and acted on (#380). http.MaxBytesReader is the right tool rather than
// io.LimitReader: it makes the read FAIL past the cap instead of silently returning a truncated
// value, which is the same distinction that made the upload path truncate silently (#415).
func TestJSONEndpointsBoundTheRequestBody(t *testing.T) {
	oversize, err := json.Marshal(map[string]string{
		"id":     "x",
		"reason": strings.Repeat("A", maxJSONRequestBytes+1024),
	})
	if err != nil {
		t.Fatal(err)
	}
	small, err := json.Marshal(map[string]string{"id": "no-such-rule", "reason": "ok"})
	if err != nil {
		t.Fatal(err)
	}

	ws := NewWebServerWithOptions("0", "127.0.0.1", "", "", nil)
	// Called directly rather than through the mux: routes are registered when the server
	// starts, and these tests construct the server without starting it.
	endpoints := map[string]http.HandlerFunc{
		"/suppressions/remove": ws.handleSuppressionsRemove,
		"/suppressions/create": ws.handleSuppressionsCreate,
		"/export":              ws.handleExport,
	}

	for ep, handler := range endpoints {
		t.Run(ep, func(t *testing.T) {
			post := func(payload []byte) string {
				req := httptest.NewRequest(http.MethodPost, ep, bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				handler(rec, req)
				return rec.Body.String()
			}

			// A body past the cap must be REFUSED at decode, not truncated and acted upon.
			if body := post(oversize); !strings.Contains(body, "Invalid JSON in request body") {
				t.Errorf("oversize body was not refused at decode; response=%s", truncate(body, 160))
			}
			// A legitimate small body must still decode — otherwise the cap is indistinguishable
			// from the endpoint being broken.
			if body := post(small); strings.Contains(body, "Invalid JSON in request body") {
				t.Errorf("a %d-byte body was refused, so the cap is rejecting legitimate requests; "+
					"response=%s", len(small), truncate(body, 160))
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
