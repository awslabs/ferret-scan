// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// startedWebServer builds a WebServer the way Start() does (strict-loaded empty config, routes behind
// the security middleware), then serves createSecureServer's http.Server, with writeTimeout in place
// of the production WriteTimeout, on a 127.0.0.1 listener it picks itself. It returns the base URL.
func startedWebServer(t *testing.T, writeTimeout time.Duration) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfgPath, filepath.Join(dir, "no-such-suppressions.yaml"), nil)
	cfg, err := config.LoadConfigStrict(cfgPath)
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	ws.cachedConfig = cfg
	if err := ws.setupRoutesWithValidation(); err != nil {
		t.Fatalf("setup routes: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	srv := ws.createSecureServer("0")
	srv.WriteTimeout = writeTimeout
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// pausedBody is a request body that delivers head, waits for pause, then delivers tail, so the
// handler is still reading the upload when pause has elapsed.
type pausedBody struct {
	head, tail []byte
	pause      time.Duration
	paused     bool
}

func (p *pausedBody) Read(b []byte) (int, error) {
	if len(p.head) > 0 {
		n := copy(b, p.head)
		p.head = p.head[n:]
		return n, nil
	}
	if !p.paused {
		p.paused = true
		time.Sleep(p.pause)
	}
	if len(p.tail) > 0 {
		n := copy(b, p.tail)
		p.tail = p.tail[n:]
		return n, nil
	}
	return 0, io.EOF
}

// TestScanThatOutlastsTheWriteTimeoutStillAnswers holds /scan to answering however long the request
// took before its response started.
//
// The server's WriteTimeout is a connection deadline set when the request headers have been read, so
// it covers everything /scan does before it writes: reading the upload and scanning it. On main a
// scan longer than 30 s found the deadline past, the response write failed, and the client got an
// empty reply with no status line (#922: a 29,938,764-byte CSV, 8,812 findings on the CLI, `curl:
// (52) Empty reply from server` after 39.4 s on /scan).
//
// Here the server's WriteTimeout is 50 ms and the client pauses for 300 ms in the middle of the
// upload, so /scan cannot start its response until six write timeouts after the headers. That makes
// the outcome independent of how fast this machine scans: the fixture is one line, and the pause is a
// sleep in the client, not a race against the scan. Fails on the parent commit, where /scan's write
// deadline is the one set at the headers ("EOF" from the client, no response).
func TestScanThatOutlastsTheWriteTimeoutStillAnswers(t *testing.T) {
	const (
		writeTimeout = 50 * time.Millisecond
		pause        = 300 * time.Millisecond
	)
	base := startedWebServer(t, writeTimeout)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("checks", "SSN"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("confidence", "all"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("files", "payroll.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("Employee SSN: 452-11-9384\n")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := body.Bytes()
	half := len(raw) / 2

	req, err := http.NewRequest(http.MethodPost, base+"/scan", &pausedBody{head: raw[:half], tail: raw[half:], pause: pause})
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(raw))
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("/scan gave no response %v after the request started (the write deadline set at the "+
			"headers had passed when the response started, #922): %v", time.Since(start).Round(time.Millisecond), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("/scan: HTTP %d: %s", resp.StatusCode, truncate(string(b), 300))
	}
	var got ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("/scan response is not JSON: %v", err)
	}
	if !got.Success || len(got.Results) != 1 || got.Results[0].Type != "SSN" {
		t.Fatalf("/scan: success=%v, %d result(s) %+v; want the one SSN", got.Success, len(got.Results), got.Results)
	}
	if elapsed := time.Since(start); elapsed < pause {
		t.Fatalf("the request took %v, less than the %v pause: the body was not delivered in two parts, "+
			"so this test did not outlast the write timeout", elapsed, pause)
	}
}

// deadlineRecorder is a ResponseWriter that records the write deadlines set through
// http.ResponseController and how many body bytes had been written when each was set.
type deadlineRecorder struct {
	header    http.Header
	written   int
	deadlines []time.Time
	writtenAt []int
}

func (r *deadlineRecorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}
func (r *deadlineRecorder) Write(p []byte) (int, error) { r.written += len(p); return len(p), nil }
func (r *deadlineRecorder) WriteHeader(int)             {}
func (r *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	r.deadlines = append(r.deadlines, t)
	r.writtenAt = append(r.writtenAt, r.written)
	return nil
}

// TestWriteDeadlineStartsAtTheResponse pins what the /scan wrapper does with the deadline: nothing
// while the handler works, then exactly one deadline, timeout from the first write and set before any
// byte of it, so a client that stops reading is still cut off. A handler that writes nothing gets the
// deadline when it returns, for the implicit response the server then writes.
func TestWriteDeadlineStartsAtTheResponse(t *testing.T) {
	const timeout = 7 * time.Second
	t.Run("set once, at the first write", func(t *testing.T) {
		rec := &deadlineRecorder{}
		var before time.Time
		h := writeDeadlineFromResponseStart(timeout, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if len(rec.deadlines) != 0 {
				t.Errorf("a deadline was set before the handler wrote: %v", rec.deadlines)
			}
			before = time.Now()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("first"))
			_, _ = w.Write([]byte("second"))
		}))
		h.ServeHTTP(rec, &http.Request{})
		after := time.Now()
		if len(rec.deadlines) != 1 {
			t.Fatalf("got %d deadlines, want exactly 1: %v", len(rec.deadlines), rec.deadlines)
		}
		if rec.writtenAt[0] != 0 {
			t.Errorf("the deadline was set after %d bytes had been written; it must precede the first", rec.writtenAt[0])
		}
		if d := rec.deadlines[0]; d.Before(before.Add(timeout)) || d.After(after.Add(timeout)) {
			t.Errorf("deadline %v is not %v after the first write (between %v and %v)", d, timeout, before.Add(timeout), after.Add(timeout))
		}
	})
	t.Run("a flush counts as the first write", func(t *testing.T) {
		rec := &flushRecorder{}
		h := writeDeadlineFromResponseStart(timeout, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = http.NewResponseController(w).Flush()
		}))
		h.ServeHTTP(rec, &http.Request{})
		if len(rec.deadlines) != 1 || rec.flushes != 1 || rec.deadlineFirst != true {
			t.Fatalf("deadlines=%d flushes=%d deadline-before-flush=%v; want one deadline set before the one flush",
				len(rec.deadlines), rec.flushes, rec.deadlineFirst)
		}
	})
	t.Run("a handler that writes nothing", func(t *testing.T) {
		rec := &deadlineRecorder{}
		writeDeadlineFromResponseStart(timeout, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, &http.Request{})
		if len(rec.deadlines) != 1 {
			t.Fatalf("got %d deadlines, want 1 for the implicit response", len(rec.deadlines))
		}
	})
}

// flushRecorder is a deadlineRecorder that can also be flushed, recording whether the deadline came
// first.
type flushRecorder struct {
	deadlineRecorder
	flushes       int
	deadlineFirst bool
}

func (r *flushRecorder) FlushError() error {
	if r.flushes == 0 && len(r.deadlines) == 1 {
		r.deadlineFirst = true
	}
	r.flushes++
	return nil
}
