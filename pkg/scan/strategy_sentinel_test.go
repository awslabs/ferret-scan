// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

const sentinelEmail, sentinelCard = "jane.doe@example.com", "4123456789012349"

// sentinelMP3 is an ID3v2.3 tag with two text frames, then one MPEG frame header: the minimal
// layout the audio redactor's own tests write.
func sentinelMP3() []byte {
	var body bytes.Buffer
	for _, f := range [][2]string{{"TIT2", "Card " + sentinelCard}, {"TPE1", "Email " + sentinelEmail}} {
		payload := append([]byte{0x00}, f[1]...) // encoding byte 0x00 (ISO-8859-1), then the value
		body.WriteString(f[0])
		_ = binary.Write(&body, binary.BigEndian, uint32(len(payload))) // v2.3 frame sizes are plain
		body.Write([]byte{0x00, 0x00})                                  // flags
		body.Write(payload)
	}
	n := body.Len() // the tag size is synchsafe: 7 bits per byte
	tag := []byte{'I', 'D', '3', 0x03, 0x00, 0x00, byte(n >> 21 & 0x7F), byte(n >> 14 & 0x7F), byte(n >> 7 & 0x7F), byte(n & 0x7F)}
	return append(append(tag, body.Bytes()...), 0xFF, 0xFB, 0x90, 0x00)
}

// #863's library box: a format that refuses the requested strategy (audio and legacy Office take
// simple and format_preserving, not synthetic) is told apart from every other redaction failure by
// errors.Is(err, ErrStrategyNotSupported), not by reading the message. The message is the one the
// CLI and existing callers already read, so its shape is pinned too.
func TestRedactFileRefusalWrapsErrStrategyNotSupported(t *testing.T) {
	for name, data := range map[string][]byte{
		"a.mp3": sentinelMP3(),
		"w.doc": olefixture.LegacyDoc("Email "+sentinelEmail+"\rCard "+sentinelCard+"\r", nil),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, name)
			if err := os.WriteFile(src, data, 0o600); err != nil {
				t.Fatal(err)
			}
			opts := func(s RedactStrategy) RedactFileOptions {
				return RedactFileOptions{
					OutputDir: filepath.Join(dir, "out-"+s.String()), Strategy: s,
					Checks: []string{"EMAIL", "CREDIT_CARD"}, DisableConfigDiscovery: true,
				}
			}

			res, err := RedactFile(src, opts(StrategySynthetic))
			if err == nil {
				t.Fatalf("synthetic returned %+v with no error; want a refusal", res)
			}
			if !errors.Is(err, ErrStrategyNotSupported) {
				t.Errorf("errors.Is(err, ErrStrategyNotSupported) = false for the refusal: %v", err)
			}
			if errors.Is(err, ErrIncomplete) {
				t.Errorf("a refusal is not an incomplete scan, but errors.Is(err, ErrIncomplete): %v", err)
			}
			want := "could not redact " + src + ": redaction strategy not supported for this file type: "
			if !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "not synthetic") {
				t.Errorf("refusal text changed:\n got %q\nwant prefix %q, naming synthetic", err.Error(), want)
			}
			if res != nil {
				t.Errorf("a refused file returned a result: %+v", res)
			}
			_ = filepath.WalkDir(filepath.Join(dir, "out-synthetic"), func(p string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					t.Errorf("a refused file left output: %s", p)
				}
				return nil
			})

			// Controls: the strategies the format declares still redact, with no error.
			for _, s := range []RedactStrategy{StrategySimple, StrategyFormatPreserving} {
				r, err := RedactFile(src, opts(s))
				if err != nil || r == nil || r.RedactionCount == 0 {
					t.Fatalf("%v: result %+v, err %v; want a redacted copy", s, r, err)
				}
				out, err := os.ReadFile(r.RedactedFilePath)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(out, []byte(sentinelEmail)) || bytes.Contains(out, []byte(sentinelCard)) {
					t.Errorf("%v: a value survived in %s", s, r.RedactedFilePath)
				}
			}

			// Another failure is not a refusal: a ctx done before the scan is ErrIncomplete only.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, err = RedactFileContext(ctx, src, opts(StrategySynthetic))
			if err == nil || !errors.Is(err, ErrIncomplete) || errors.Is(err, ErrStrategyNotSupported) {
				t.Errorf("cancelled ctx: err = %v; want ErrIncomplete and not ErrStrategyNotSupported", err)
			}
		})
	}
}
