// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"io"
	"os"
	"strings"
	"testing"
)

// TestLogErrorContextIsSorted pins the order of the context= fields in a logged
// error. LogError printed them by ranging err.Context (a map), so two logs of
// the identical failure came out with the fields in different orders and could
// not be diffed or matched by a fixed grep pattern.
func TestLogErrorContextIsSorted(t *testing.T) {
	logger := NewErrorLogger(LogLevelDebug)
	mkErr := func() *MediaProcessingError {
		return &MediaProcessingError{
			ErrorType: ErrorTypeParsingFailed,
			FilePath:  "/test/photo.jpg",
			Message:   "boom",
			Context: map[string]interface{}{
				"zone":      "exif",
				"attempt":   2,
				"offset":    1024,
				"format":    "jpeg",
				"extractor": "exiflib",
				"bytes":     4096,
			},
		}
	}

	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		out := captureLogOutput(t, func() { logger.LogError(mkErr()) })
		start := strings.Index(out, "context=[")
		if start < 0 {
			t.Fatalf("no context= section in log output: %q", out)
		}
		rest := out[start+len("context=["):]
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			t.Fatalf("unterminated context= section: %q", out)
		}
		seen[rest[:end]]++
	}
	if len(seen) != 1 {
		t.Fatalf("context field order varied across 100 runs: %d distinct orders %v", len(seen), seen)
	}
	const want = "attempt=2 bytes=4096 extractor=exiflib format=jpeg offset=1024 zone=exif"
	if _, ok := seen[want]; !ok {
		t.Fatalf("context fields = %v, want %q", seen, want)
	}
}

// TestLogErrorContextKeepsEveryField guards against the sort dropping a field:
// diagnostic context that silently disappears is worse than unordered context.
func TestLogErrorContextKeepsEveryField(t *testing.T) {
	logger := NewErrorLogger(LogLevelDebug)
	ctx := map[string]interface{}{"a": 1, "bb": 2, "ccc": 3, "dddd": 4, "e": 5}
	out := captureLogOutput(t, func() {
		logger.LogError(&MediaProcessingError{
			ErrorType: ErrorTypeParsingFailed,
			FilePath:  "/test/x.jpg",
			Message:   "boom",
			Context:   ctx,
		})
	})
	for key := range ctx {
		if !strings.Contains(out, key+"=") {
			t.Fatalf("context key %q missing from log output: %q", key, out)
		}
	}
}

// TestLogErrorNoContextSection covers the len == 0 branch: an error with no
// context must not grow an empty context=[] suffix.
func TestLogErrorNoContextSection(t *testing.T) {
	logger := NewErrorLogger(LogLevelDebug)
	out := captureLogOutput(t, func() {
		logger.LogError(&MediaProcessingError{
			ErrorType: ErrorTypeParsingFailed,
			FilePath:  "/test/x.jpg",
			Message:   "boom",
		})
	})
	if strings.Contains(out, "context=") {
		t.Fatalf("unexpected context= section for an error with no context: %q", out)
	}
}

// captureLogOutput redirects os.Stdout for the duration of fn. LogError writes
// with fmt.Printf, so there is no injectable writer to use instead.
func captureLogOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	// STDERR, not stdout. LogError used to write to stdout, which corrupted every
	// machine artifact: `--format json > report.json` produced a file starting
	// "[ERROR] media processing failed for ..." and a consumer got a parse error
	// instead of a report. These tests captured stdout, so they were the thing
	// pinning the wrong stream in place.
	//
	// What they ASSERT is unchanged — the context= fields are sorted and complete.
	// Only the stream they listen on moved.
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}
	return out
}
