// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"time"
)

// responseWriteTimeout bounds writing one response, so a client that stops reading cannot hold a
// connection and its buffered response for ever. It is the http.Server's WriteTimeout, and the
// budget /scan re-arms when it starts its response (writeDeadlineFromResponseStart).
const responseWriteTimeout = 30 * time.Second

// writeDeadlineFromResponseStart measures the write deadline from the moment next starts its
// response, instead of from the end of the request headers.
//
// http.Server sets WriteTimeout as a connection deadline when it finishes reading the request
// headers, so for an ordinary handler it covers the handler's whole run, not just the write. /scan
// reads the upload and scans it before it writes a byte, and a scan longer than the timeout found
// its deadline already past: the response write failed and the connection closed with no status
// line. Measured on a 29,938,764-byte CSV: the CLI reported 8,812 findings in 41.5 s, /scan
// answered `curl: (52) Empty reply from server` after 39.4 s and the findings were discarded
// (#922).
//
// The read side is untouched: ReadHeaderTimeout and ReadTimeout still bound reading the request,
// and the scan is bounded per file by the worker pool's job timeout (parallel.DefaultJobTimeout),
// which reports a cut-short file as incomplete. What changes is when the write budget starts: the
// deadline is re-armed to timeout from the first WriteHeader, Write or Flush, so the response gets
// the whole budget and a client that stops reading is still cut off when it expires.
func writeDeadlineFromResponseStart(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dw := &deadlineAtFirstWrite{ResponseWriter: w, timeout: timeout}
		next.ServeHTTP(dw, r)
		// A handler that returned without writing still gets a response: the server writes the
		// implicit 200 after this returns, so that write gets the budget too.
		dw.arm()
	})
}

// deadlineAtFirstWrite re-arms the connection's write deadline once, on the first call that can
// put bytes on the wire.
type deadlineAtFirstWrite struct {
	http.ResponseWriter
	timeout time.Duration
	armed   bool
}

func (d *deadlineAtFirstWrite) arm() {
	if d.armed {
		return
	}
	d.armed = true
	// A writer with no connection behind it (httptest.ResponseRecorder) answers
	// http.ErrNotSupported; there is no deadline to move, so the error is not a failure.
	_ = http.NewResponseController(d.ResponseWriter).SetWriteDeadline(time.Now().Add(d.timeout))
}

func (d *deadlineAtFirstWrite) WriteHeader(code int) {
	d.arm()
	d.ResponseWriter.WriteHeader(code)
}

func (d *deadlineAtFirstWrite) Write(p []byte) (int, error) {
	d.arm()
	return d.ResponseWriter.Write(p)
}

// FlushError is what http.ResponseController.Flush calls, so a flush before the first write is
// re-armed as well.
func (d *deadlineAtFirstWrite) FlushError() error {
	d.arm()
	return http.NewResponseController(d.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the connection's own writer.
func (d *deadlineAtFirstWrite) Unwrap() http.ResponseWriter { return d.ResponseWriter }
