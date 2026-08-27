// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package json

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestAMarshalFailureIsReturnedNotPrintedAsTheDocument is the severe half of #520.
//
// The formatter used to do `return fmt.Sprintf("Error formatting JSON: %v", err)` — handing the error
// text back as the DOCUMENT. So stdout received `Error formatting JSON: ...` where the report should
// have been, and because no error was returned the process exited **0**. Measured on a 1,009-file
// directory: 57,786 findings and 58,703,546 bytes became 52 bytes with a green exit code, so a CI job
// doing `... --format json > findings.json` saw an empty finding set and passed.
//
// The Formatter interface has always returned an error and cmd/main.go has always exited 1 on it; only
// this function declined to use the channel.
//
// The trigger here is a metadata value encoding/json cannot marshal for a reason OTHER than being a
// non-finite number, because non-finite numbers are now dropped upstream by shared.SanitizeMetadata —
// so a numeric fixture would test the upstream guard instead of this error path.
func TestAMarshalFailureIsReturnedNotPrintedAsTheDocument(t *testing.T) {
	matches := []detector.Match{{
		Text: "value", Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		// A func cannot be marshalled and is not a number, so it reaches the encoder.
		Metadata: map[string]interface{}{"unmarshalable": func() {}},
	}}

	f := NewFormatter()
	out, err := f.Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})

	if err == nil {
		t.Fatalf("a marshal failure returned no error, so the process would exit 0.\n"+
			"  output was: %.120q", out)
	}
	if out != "" {
		t.Errorf("the error was also placed in the output, where a consumer cannot tell it from a "+
			"report: %.120q", out)
	}
	if strings.Contains(out, "Error formatting") {
		t.Error("the error text is being returned AS the document")
	}
}

// TestAnOrdinaryReportStillFormatsAndReturnsNoError keeps the above from passing on a formatter that
// simply always errors.
func TestAnOrdinaryReportStillFormatsAndReturnsNoError(t *testing.T) {
	matches := []detector.Match{{
		Text: "value", Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Metadata: map[string]interface{}{"ip_type": "copyright", "confidence_adjustment": 12.5},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("an ordinary report failed to format: %v", err)
	}
	if !strings.Contains(out, "\"results\"") {
		t.Errorf("the output does not look like a report: %.200q", out)
	}
	if strings.Contains(out, "Error formatting") {
		t.Errorf("an error string reached a successful document: %.200q", out)
	}
}

// TestACleanScanStillReturnsADocumentAndNoError: zero findings must remain a successful empty report
// rather than being conflated with a failure, which is what the exit code now distinguishes.
func TestACleanScanStillReturnsADocumentAndNoError(t *testing.T) {
	out, err := NewFormatter().Format(nil, nil, formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("a clean scan returned an error: %v", err)
	}
	if !strings.Contains(out, "\"results\"") {
		t.Errorf("a clean scan produced no report body: %.200q", out)
	}
}
