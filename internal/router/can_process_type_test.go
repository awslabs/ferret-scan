// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"testing"
)

// CanProcessType must answer "would we process this TYPE" without consulting size.
//
// CanProcessFile cannot be used for this: its own size gate returns "File too large"
// before the type is considered, so asking it about an oversize file is circular —
// which is why the discovery-time warning decision carried a hardcoded 11-extension
// list instead, duplicated at three call sites. See #324.
func TestCanProcessTypeIgnoresSize(t *testing.T) {
	dir := t.TempDir()

	// A text file well over MaxFileSize. Sparse: Truncate extends the length without
	// allocating the bytes.
	//
	// The leading text must fill more than the 512-byte sniff window. Truncate extends
	// with NULs, so writing only a line or two leaves the rest of the window zeroed and
	// the sniff correctly calls the file binary — a fixture bug that reads exactly like
	// a code bug.
	big := filepath.Join(dir, "big_report.txt")
	f, err := os.Create(big) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ { // 40 * 31 bytes = 1240 bytes of real text
		if _, err := f.WriteString("Quarterly report text content.\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	info, err := os.Stat(big)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= MaxFileSize {
		t.Fatalf("fixture is %d bytes, expected over the %d limit", info.Size(), MaxFileSize)
	}

	// The whole point: over the limit, still a processable TYPE.
	if !CanProcessType(big, true) {
		t.Error("an oversize TEXT file reported as not processable — the size must not " +
			"participate, or the caller cannot tell a coverage loss from a non-event")
	}

	// And CanProcessFile still refuses it, for contrast: that is the circularity this
	// function exists to break.
	if ok, reason := CanProcessFile(newRouterForTest(t), big, true); ok {
		t.Errorf("CanProcessFile accepted an oversize file (reason %q)", reason)
	}
}

// newRouterForTest builds a router with the default preprocessors registered.
func newRouterForTest(t *testing.T) *FileRouter {
	t.Helper()
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(nil)
	return fr
}

// CanProcessFile is a method; this shim keeps the contrast assertion above readable.
func CanProcessFile(fr *FileRouter, path string, enablePreprocessors bool) (bool, string) {
	return fr.CanProcessFile(path, enablePreprocessors)
}

// Media types are processable when preprocessors are on, because their METADATA is
// extracted and scanned. An oversize video that went unscanned is therefore a real
// coverage loss, not a non-event — the previous hardcoded list called it a non-event.
func TestCanProcessTypeMediaDependsOnPreprocessors(t *testing.T) {
	dir := t.TempDir()
	vid := filepath.Join(dir, "clip.mp4")
	if err := os.WriteFile(vid, []byte{0x00, 0x00, 0x00, 0x18, 'f', 't', 'y', 'p'}, 0o600); err != nil {
		t.Fatal(err)
	}

	if !CanProcessType(vid, true) {
		t.Error("a video is not processable with preprocessors enabled, but its metadata " +
			"is extracted and scanned")
	}
	if CanProcessType(vid, false) {
		t.Error("a video reported processable with preprocessors DISABLED; nothing would " +
			"have read it, so refusing it for size loses nothing")
	}
}

// A type nothing handles must be reported not-processable at any size, so a size
// refusal for it stays silent. This is the case the old extension list could never
// cover: browser partial downloads have random suffixes.
func TestCanProcessTypeRejectsOpaqueBinary(t *testing.T) {
	dir := t.TempDir()

	// Random-suffix partial download holding binary bytes.
	partial := filepath.Join(dir, ".com.brave.Browser.ABCdef")
	body := make([]byte, 600) // NUL bytes: not text under any encoding sniff
	if err := os.WriteFile(partial, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if CanProcessType(partial, true) {
		t.Error("an opaque binary blob reported processable; a size refusal for it would " +
			"produce a warning about a file that could never have been scanned")
	}

	// A missing path is not processable, and must not panic.
	if CanProcessType(filepath.Join(dir, "nope.txt"), true) {
		t.Error("a nonexistent path reported processable")
	}
}

// A plain text file is processable regardless of the preprocessor setting: text needs
// no preprocessor.
func TestCanProcessTypeTextNeedsNoPreprocessors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(p, []byte("plain text content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, enable := range []bool{true, false} {
		if !CanProcessType(p, enable) {
			t.Errorf("text file reported not processable with enablePreprocessors=%v", enable)
		}
	}
}
