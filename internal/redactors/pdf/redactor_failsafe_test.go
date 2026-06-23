// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pdf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
	"github.com/awslabs/ferret-scan/internal/redactors"
)

// A minimal but structurally valid single-page PDF that pdfcpu can parse.
const minimalPDF = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 58 >>
stream
BT /F1 12 Tf 20 100 Td (secret sk_live_ABCDEF value) Tj ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
0000000241 00000 n
0000000350 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
422
%%EOF
`

func sampleMatches() []detector.Match {
	return []detector.Match{{
		Text:       "sk_live_ABCDEF",
		LineNumber: 1,
		Type:       "STRIPE_KEY",
		Confidence: 95,
	}}
}

// TestRedactDocument_FailsSafeWhenNotImplemented asserts the PDF redactor
// refuses to report success while leaving content unredacted. Previously both
// the position path (placeholder text) and applyPDFRedaction (logging stub)
// produced a byte-for-byte copy of the input yet returned Success:true.
func TestRedactDocument_FailsSafeWhenNotImplemented(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	out := filepath.Join(dir, "out.pdf")
	if err := os.WriteFile(in, []byte(minimalPDF), 0600); err != nil {
		t.Fatalf("write input pdf: %v", err)
	}

	r := NewPDFRedactor(nil, nil)
	result, err := r.RedactDocument(in, out, sampleMatches(), redactors.RedactionSimple)

	if err == nil {
		t.Fatal("expected RedactDocument to return an error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on failure, got %+v", result)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error should explain redaction is unimplemented, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no output file should be produced when redaction is refused; stat err = %v", statErr)
	}
}

// TestRedactContent_FailsSafeWhenNotImplemented covers the content-based path,
// which only wrote a companion _redacted.txt and never modified the PDF itself.
func TestRedactContent_FailsSafeWhenNotImplemented(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	out := filepath.Join(dir, "out.pdf")
	if err := os.WriteFile(in, []byte(minimalPDF), 0600); err != nil {
		t.Fatalf("write input pdf: %v", err)
	}

	content := &preprocessors.ProcessedContent{
		OriginalPath: in,
		Text:         "secret sk_live_ABCDEF value",
		Format:       "pdf",
	}

	r := NewPDFRedactor(nil, nil)
	result, err := r.RedactContent(content, out, sampleMatches(), redactors.RedactionSimple)

	if err == nil {
		t.Fatal("expected RedactContent to return an error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on failure, got %+v", result)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no output file should be produced when redaction is refused; stat err = %v", statErr)
	}
}
