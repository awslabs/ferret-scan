// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRedactFile_WritesRedactedCopyWithoutRawValues(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	// Reserved documentation values.
	src := writeTemp(t, in, "leak.txt", "card 5500-0000-0000-0004 email jordan@example.com\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Strategy:  "format_preserving",
		Checks:    []string{"all"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if res.RedactedFilePath == "" {
		t.Fatal("expected a redacted file path")
	}
	if res.RedactionCount == 0 {
		t.Error("expected at least one redaction")
	}

	data, err := os.ReadFile(res.RedactedFilePath)
	if err != nil {
		t.Fatalf("redacted file not readable: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "5500-0000-0000-0004") {
		t.Errorf("redacted output still contains raw card number:\n%s", content)
	}
	if strings.Contains(content, "jordan@example.com") {
		t.Errorf("redacted output still contains raw email:\n%s", content)
	}
	// Output preserves the source file type.
	if filepath.Ext(res.RedactedFilePath) != ".txt" {
		t.Errorf("expected .txt output, got %s", res.RedactedFilePath)
	}
}

func TestRedactFile_CleanFileIsCopiedThrough(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	src := writeTemp(t, in, "clean.txt", "nothing sensitive here\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if _, err := os.Stat(res.RedactedFilePath); err != nil {
		t.Errorf("expected a passed-through copy for a clean file: %v", err)
	}
}

// TestRedactFile_UnredactableFileTypeIsAnError pins the hard-error guard. A
// source file has no registered redactor, so its findings cannot be masked. The
// only safe outcome is an error: returning success would hand the caller a path
// that RedactFile's own doc comment calls "safe to share", and RedactionCount
// would read 0 — indistinguishable from a genuinely clean file. The clean-file
// passthrough made that worse by copying the original there verbatim.
func TestRedactFile_UnredactableFileTypeIsAnError(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	// Reserved documentation values, in a file whose findings cannot be masked.
	//
	// Re-fixtured for #358, exactly as the previous comment here said it would have to be.
	// The fixture used to be a video with its values in udta, because video had no redactor
	// at all; now it has one, so that file redacts and this guard would never fire. What the
	// test is about is the invariant, not the format.
	//
	// The replacement keeps its values in a "uuid" atom — the XMP form — which is scanned (a
	// chunk scan reaches it and reports the key) and which the video redactor deliberately
	// refuses, because its metadata walk is scoped to udta and meta and it will not claim to
	// have removed a value it cannot locate. That is a STRONGER version of the same guard: the
	// error now comes from a registered redactor declining, rather than from no redactor
	// existing, and it is the path a caller actually hits.
	src := writeRefusedVideo(t, in, "creds.mp4")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Checks:    []string{"all"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err == nil {
		t.Fatalf("expected an error for an unredactable file type; got result %+v", res)
	}
	if !strings.Contains(err.Error(), "could not redact") {
		t.Errorf("error should say redaction failed, got: %v", err)
	}
	if res != nil {
		t.Errorf("no result may be returned alongside the error, got %+v", res)
	}

	// And nothing may have been written under the output dir — the leak was a
	// cleartext copy at a path the caller treats as sanitized.
	err = filepath.Walk(out, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return werr
		}
		data, rerr := os.ReadFile(path) // #nosec G304 - test-controlled temp path
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(data), "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("cleartext value was copied to the output path %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking output dir: %v", err)
	}
}

func TestRedactFile_DefaultsToFormatPreserving(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	src := writeTemp(t, in, "e.txt", "email jordan@example.com\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if res.Strategy != "format_preserving" {
		t.Errorf("expected default strategy format_preserving, got %q", res.Strategy)
	}
}

// writeRefusedVideo writes a minimal MP4 whose reserved documentation values live in a uuid
// (XMP) atom, for tests that need a file which IS scanned but whose findings cannot be masked.
//
// Hand-built rather than produced by ffmpeg, which is not on every CI runner. Measured on this
// exact shape: the scan reports AWS_ACCESS_KEY at MEDIUM 84, and redaction writes no file and
// reports "no video metadata region found", because the redactor's walk covers udta and meta —
// where every value the extractor can attribute to a tag lives — and not a uuid payload.
//
// Deliberately NOT a udta/ilst video any more: that is now redactable (#358).
func writeRefusedVideo(t *testing.T, dir, name string) string {
	t.Helper()

	atom := func(kind string, payload []byte) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(8+len(payload)))
		out = append(out, []byte(kind)...)
		return append(out, payload...)
	}

	xmp := append(bytes.Repeat([]byte{0x11}, 16),
		[]byte("<x:xmpmeta><desc>key AKIAIOSFODNN7EXAMPLE contact jordan@example.com</desc></x:xmpmeta>")...)
	out := append(atom("ftyp", []byte("isomiso2mp41")), atom("moov", atom("mvhd", make([]byte, 100)))...)
	out = append(out, atom("uuid", xmp)...)

	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}
