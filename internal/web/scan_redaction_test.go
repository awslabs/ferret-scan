// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
	formatterShared "github.com/awslabs/ferret-scan/internal/formatters/shared"
	"github.com/awslabs/ferret-scan/internal/suppressions"
)

// scanFormatterOptions mirrors the options the /scan handler uses to render the
// JSON that is delivered to the operator's browser. Keep this in lockstep with
// handleScan: the web UI redacts client-side, so /scan must receive the real
// value (ShowMatch) and the context fields (Verbose) the suppression hash
// depends on. This test exists because a deny-by-default change to the shared
// JSON formatter once silently broke this contract.
func scanFormatterOptions() formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		Verbose:         true,
		ShowMatch:       true,
	}
}

// TestScanJSON_DeliversRealDataForClientSideRedaction asserts that the JSON the
// /scan endpoint sends to the browser carries the real matched value and the
// raw context fields. The web UI hides them client-side (🔒 click-to-reveal),
// so redacting them server-side would blank the reveal toggle.
func TestScanJSON_DeliversRealDataForClientSideRedaction(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	const fullLine = "Robert Aragon\t" + secret + "\t489-36-8350"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 5,
		Type:       "CREDIT_CARD",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
		Context: detector.ContextInfo{
			FullLine:   fullLine,
			BeforeText: "header row",
			AfterText:  "footer row",
		},
		Metadata: map[string]interface{}{"card_type": "VISA"},
	}}

	out, err := formatters.Export("json", matches, nil, scanFormatterOptions())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	var resp formatterShared.JSONResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	r := resp.Results[0]
	if r.Text != secret {
		t.Errorf("scan JSON Text = %q, want real value %q (UI redacts client-side)", r.Text, secret)
	}
	if r.FullLine != fullLine {
		t.Errorf("scan JSON full_line = %q, want %q (suppression hash depends on it)", r.FullLine, fullLine)
	}
	if r.BeforeText != "header row" || r.AfterText != "footer row" {
		t.Errorf("scan JSON dropped before/after context: before=%q after=%q", r.BeforeText, r.AfterText)
	}
}

// TestScanJSON_SuppressionHashRoundTrips is the load-bearing regression test:
// the hash computed at scan time (from the real detector.Match) must equal the
// hash the web UI recomputes from the fields it parsed out of the /scan JSON.
// If /scan redacts text/context, the browser feeds [HIDDEN]/"" into
// GenerateFindingHashFromData and the resulting suppression rule never matches
// the finding it was created for.
func TestScanJSON_SuppressionHashRoundTrips(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	match := detector.Match{
		Text:       secret,
		LineNumber: 5,
		Type:       "CREDIT_CARD",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
		Context: detector.ContextInfo{
			FullLine:   "Robert Aragon\t" + secret,
			BeforeText: "before",
			AfterText:  "after",
		},
	}

	// Scan-time hash: the manager hashes the real match (IsSuppressed path).
	mgr := suppressions.NewSuppressionManager("")
	scanHash, err := mgr.GenerateFindingHashFromData(map[string]interface{}{
		"type":        match.Type,
		"text":        match.Text,
		"filename":    match.Filename,
		"line_number": float64(match.LineNumber),
		"confidence":  match.Confidence,
		"full_line":   match.Context.FullLine,
		"before_text": match.Context.BeforeText,
		"after_text":  match.Context.AfterText,
	})
	if err != nil {
		t.Fatalf("scan hash: %v", err)
	}

	// Render the /scan JSON, parse it the way the browser does, then recompute
	// the hash from the parsed fields (the /suppressions/create path).
	out, err := formatters.Export("json", []detector.Match{match}, nil, scanFormatterOptions())
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	var resp formatterShared.JSONResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	r := resp.Results[0]
	uiHash, err := mgr.GenerateFindingHashFromData(map[string]interface{}{
		"type":        r.Type,
		"text":        r.Text,
		"filename":    r.Filename,
		"line_number": float64(r.LineNumber),
		"confidence":  r.Confidence,
		"full_line":   r.FullLine,
		"before_text": r.BeforeText,
		"after_text":  r.AfterText,
	})
	if err != nil {
		t.Fatalf("ui hash: %v", err)
	}

	if scanHash != uiHash {
		t.Errorf("suppression hash mismatch:\n scan-time = %s\n web-ui    = %s\n"+
			"the /scan JSON must carry real text+context so the UI recomputes the same hash", scanHash, uiHash)
	}
}
