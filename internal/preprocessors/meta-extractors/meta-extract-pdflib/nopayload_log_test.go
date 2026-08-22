// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractpdflib

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BSC4 gate for this extractor's FERRET_DEBUG output.
//
// The package's five debug lines write straight to os.Stderr behind an
// os.Getenv("FERRET_DEBUG") check, not through the observability observer. That is why
// internal/preprocessors/nopayload_log_test.go never covered them even though it imports this
// package: it captures the OBSERVER's writer, and these sites bypass it. Two of the five
// printed raw extracted values (#382):
//
//	[DEBUG] PDF Metadata: After info dictionary - Creator: 'Marcus Whitfield SSN 449-87-4100', ...
//	[DEBUG] PDF Metadata: Pattern matched! Found value: 'Marcus Whitfield SSN 449-87-4100'
//
// Creator and Producer are exactly what the METADATA validator reports as findings, so this
// wrote the finding to stderr before any formatter could mask it — while
// pdf_metadata_preprocessor.go was already logging Producer as "[HIDDEN] (len=%d)".

// sentinel values planted in the fixtures. None may appear in the debug output.
const (
	sentinelName   = "Marcus Whitfield SSN 449-87-4100"
	sentinelSecret = "token AKIA_TESTONLY_EXAMPLE"
)

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
//
// Mirrors captureLogOutput in internal/preprocessors: these sites write to the process fd, so
// capturing the observer's buffer would prove nothing about them.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
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

// writePDF builds a small valid PDF with a correct xref table and startxref offset. A
// structurally broken file would be rejected before reaching the debug sites, and the test
// would pass while covering nothing.
func writePDF(t *testing.T, dir, name string, objects []string, infoRef bool) string {
	t.Helper()

	var buf strings.Builder
	buf.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objects))
	for _, obj := range objects {
		offsets = append(offsets, buf.Len())
		buf.WriteString(obj)
	}
	xref := buf.Len()

	buf.WriteString("xref\n0 " + itoa(len(objects)+1) + "\n")
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		buf.WriteString(pad10(off) + " 00000 n \n")
	}
	buf.WriteString("trailer\n<< /Size " + itoa(len(objects)+1) + " /Root 1 0 R")
	if infoRef {
		buf.WriteString(" /Info 4 0 R")
	}
	buf.WriteString(" >>\nstartxref\n" + itoa(xref) + "\n%%EOF\n")

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func pad10(n int) string {
	s := itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}

var baseObjects = []string{
	"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
	"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
	"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n",
}

// TestInfoDictionaryValuesAreNotPrinted covers the site reached when the trailer names an
// /Info dictionary.
func TestInfoDictionaryValuesAreNotPrinted(t *testing.T) {
	dir := t.TempDir()
	path := writePDF(t, dir, "info.pdf", append(append([]string{}, baseObjects...),
		"4 0 obj\n<< /Creator ("+sentinelName+") /Producer ("+sentinelSecret+") >>\nendobj\n"),
		true)

	t.Setenv("FERRET_DEBUG", "1")
	var meta *Metadata
	out := captureStderr(t, func() {
		var err error
		meta, err = ExtractMetadata(path)
		if err != nil {
			t.Errorf("ExtractMetadata: %v", err)
		}
	})

	// Non-vacuity, two ways. The extractor must actually have read the values — otherwise
	// there is nothing to leak — and the debug site must have run.
	if meta == nil || meta.Creator != sentinelName {
		t.Fatalf("extractor did not read /Creator (got %q), so this test cannot detect a leak",
			creatorOf(meta))
	}
	if !strings.Contains(out, "After info dictionary") {
		t.Fatalf("the info-dictionary debug site did not run, so it is not covered.\n--- stderr ---\n%s", out)
	}

	assertNoSentinel(t, out)
}

// TestDirectFieldCaptureIsNotPrinted covers the fallback path: no /Info reference in the
// trailer, and a multi-line dictionary starting with /Title, so all three info-dictionary
// approaches miss and the whole-file regex in extractDirectField runs.
func TestDirectFieldCaptureIsNotPrinted(t *testing.T) {
	dir := t.TempDir()
	path := writePDF(t, dir, "noinfo.pdf", append(append([]string{}, baseObjects...),
		"4 0 obj\n<<\n/Title (Quarterly Report)\n/Creator ("+sentinelName+")\n>>\nendobj\n"),
		false)

	t.Setenv("FERRET_DEBUG", "1")
	var meta *Metadata
	out := captureStderr(t, func() {
		var err error
		meta, err = ExtractMetadata(path)
		if err != nil {
			t.Errorf("ExtractMetadata: %v", err)
		}
	})

	if meta == nil || meta.Creator != sentinelName {
		t.Fatalf("the fallback path did not recover /Creator (got %q), so this fixture no "+
			"longer exercises extractDirectField", creatorOf(meta))
	}
	if !strings.Contains(out, "Pattern matched") {
		t.Fatalf("the pattern-match debug site did not run, so it is not covered.\n--- stderr ---\n%s", out)
	}

	assertNoSentinel(t, out)
}

// TestDebugLineStillNamesTheField keeps the fix from being a blunt deletion. Masking the value
// is the point; losing the field name would make the line useless for the debugging it exists
// for.
func TestDebugLineStillNamesTheField(t *testing.T) {
	dir := t.TempDir()
	path := writePDF(t, dir, "noinfo.pdf", append(append([]string{}, baseObjects...),
		"4 0 obj\n<<\n/Title (Quarterly Report)\n/Creator ("+sentinelName+")\n>>\nendobj\n"),
		false)

	t.Setenv("FERRET_DEBUG", "1")
	out := captureStderr(t, func() {
		if _, err := ExtractMetadata(path); err != nil {
			t.Errorf("ExtractMetadata: %v", err)
		}
	})

	for _, want := range []string{"Creator", "len="} {
		if !strings.Contains(out, want) {
			t.Errorf("debug output no longer contains %q, so the masking removed the "+
				"diagnostic value too.\n--- stderr ---\n%s", want, out)
		}
	}
}

func assertNoSentinel(t *testing.T, out string) {
	t.Helper()
	if out == "" {
		t.Fatal("no stderr captured, so this test cannot detect a leak")
	}
	for _, s := range []string{sentinelName, sentinelSecret, "449-87-4100", "AKIA_TESTONLY_EXAMPLE"} {
		if strings.Contains(out, s) {
			t.Errorf("document content %q leaked into FERRET_DEBUG output (BSC4).\n--- stderr ---\n%s",
				s, out)
		}
	}
}

func creatorOf(m *Metadata) string {
	if m == nil {
		return "<nil metadata>"
	}
	return m.Creator
}
