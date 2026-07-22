// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestRedactDocument_EncodingRoundTrip locks the transcode contract for the
// file redaction path: matches are produced against DECODED text, so the
// redactor must decode the same way before masking, and must write the
// redacted output back in the ORIGINAL encoding (BOM included) so a redacted
// UTF-16 file (PowerShell transcript, .reg export) remains valid for its
// native tooling. A regression here is a silent redaction hole: searching
// raw UTF-16 bytes for a UTF-8 match text finds nothing and the sensitive
// value survives.
func TestRedactDocument_EncodingRoundTrip(t *testing.T) {
	const secret = "449-87-4100"
	const content = "Employee SSN " + secret + " on file.\r\nsecond line clean.\r\n"

	match := detector.Match{
		Text:       secret,
		LineNumber: 1,
		Type:       "SSN",
		Confidence: 100,
		Validator:  "ssn",
	}

	encodings := []preprocessors.TextEncoding{
		preprocessors.EncodingUTF8,
		preprocessors.EncodingUTF8BOM,
		preprocessors.EncodingUTF16LE,
		preprocessors.EncodingUTF16BE,
		preprocessors.EncodingUTF16LENoBOM,
		preprocessors.EncodingUTF16BENoBOM,
	}

	for _, enc := range encodings {
		t.Run(enc.String(), func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "in.txt")
			dst := filepath.Join(dir, "out.txt")
			if err := os.WriteFile(src, preprocessors.EncodeFromUTF8(content, enc), 0o600); err != nil {
				t.Fatal(err)
			}

			r := NewPlainTextRedactor(nil, nil)
			if _, err := r.RedactDocument(src, dst, []detector.Match{match}, redactors.RedactionSimple); err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}

			raw, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}

			// Output must still BE the original encoding.
			if got := preprocessors.DetectTextEncoding(raw); got != enc {
				t.Errorf("output encoding = %v, want %v", got, enc)
			}

			decoded, ok := preprocessors.DecodeToUTF8(raw, enc)
			if !ok {
				t.Fatal("output not decodable")
			}
			if strings.Contains(decoded, secret) {
				t.Errorf("SECRET SURVIVED redaction in %v output", enc)
			}
			if !strings.Contains(decoded, "REDACTED") {
				t.Errorf("no redaction marker in output: %q", decoded)
			}
			if !strings.Contains(decoded, "second line clean.") {
				t.Errorf("non-sensitive content damaged: %q", decoded)
			}
		})
	}
}
