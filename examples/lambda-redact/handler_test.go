// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/pkg/redact"
)

// TestParseStrategy_Valid pins the wire-level strategy → enum mapping.
// Empty string is allowed and maps to FormatPreserving (the default);
// the explicit "format_preserving" string also maps to it.
func TestParseStrategy_Valid(t *testing.T) {
	cases := []struct {
		in   string
		want redact.Strategy
	}{
		{"simple", redact.Simple},
		{"format_preserving", redact.FormatPreserving},
		{"", redact.FormatPreserving},
		{"synthetic", redact.Synthetic},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseStrategy(tc.in)
			if err != nil {
				t.Fatalf("parseStrategy(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseStrategy(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestParseStrategy_RejectsInvalid pins the public contract: unknown
// strategy strings produce an error rather than silently falling
// through to the default. Silent fallback would hide a typo'd client
// config and produce confusingly different redactions than the caller
// asked for.
func TestParseStrategy_RejectsInvalid(t *testing.T) {
	cases := []string{
		"foo",
		"FORMAT_PRESERVING", // case-sensitive; uppercase is rejected
		"format-preserving", // hyphen instead of underscore
		"none",
		"raw",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := parseStrategy(in)
			if err == nil {
				t.Errorf("parseStrategy(%q) accepted invalid value, want error", in)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid strategy") {
				t.Errorf("parseStrategy(%q) error message should mention 'invalid strategy', got: %v", in, err)
			}
		})
	}
}

// TestParseCSV_EdgeCases pins the env-var parsing shape: trims spaces
// per entry, drops empty entries (including from trailing/double commas),
// and treats an empty input as no entries.
func TestParseCSV_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty input", "", nil},
		{"single value", "EMAIL", []string{"EMAIL"}},
		{"two values", "EMAIL,SSN", []string{"EMAIL", "SSN"}},
		{"spaces around values", " EMAIL , SSN ", []string{"EMAIL", "SSN"}},
		{"trailing comma", "EMAIL,SSN,", []string{"EMAIL", "SSN"}},
		{"leading comma", ",EMAIL,SSN", []string{"EMAIL", "SSN"}},
		{"double commas", "EMAIL,,SSN", []string{"EMAIL", "SSN"}},
		{"only whitespace entries", " , , ", nil},
		{"mixed whitespace and values", " a, ,b ", []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCSV(tc.in)
			// Normalize nil-vs-empty: an empty result and a nil slice are
			// equivalent for our purposes (both produce no checks to enable).
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseCSV(%q) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestBuildResponse_OmitsFindingsByDefault pins the side-channel guard
// as a property of the handler code (not just the deployed system).
//
// includeFindings=false MUST leave Response.FindingsByType nil, and
// the resulting JSON encoding MUST NOT contain the findings_by_type
// field at all (the `omitempty` tag relies on the field being nil,
// not just empty).
//
// This is the most security-relevant test in this file: a regression
// here turns the response into a per-tenant data-classification
// side-channel, even though no payload bytes are exposed.
func TestBuildResponse_OmitsFindingsByDefault(t *testing.T) {
	resp := buildResponse(
		"redacted text",
		map[string]int{"EMAIL": 1, "SSN": 2},
		42,
		"req-abc-123",
		false, // the default — DO NOT include findings on the wire
	)

	if resp.FindingsByType != nil {
		t.Errorf("buildResponse(includeFindings=false) populated FindingsByType: %v", resp.FindingsByType)
	}
	if resp.Redacted != "redacted text" {
		t.Errorf("Redacted not propagated: got %q", resp.Redacted)
	}
	if resp.RequestID != "req-abc-123" {
		t.Errorf("RequestID not propagated: got %q", resp.RequestID)
	}
	if resp.DurationMS != 42 {
		t.Errorf("DurationMS not propagated: got %d", resp.DurationMS)
	}

	// Marshal as if we were sending it on the wire and assert the
	// findings_by_type field is genuinely absent — not just present
	// with a nil/empty value. JSON omission relies on `omitempty` +
	// nil; a zero-length-but-non-nil map would still serialize as `{}`.
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body), "findings_by_type") {
		t.Errorf("findings_by_type leaked into wire format: %s", body)
	}
	// Cross-check that the other fields ARE present.
	for _, expect := range []string{`"redacted":"redacted text"`, `"request_id":"req-abc-123"`, `"duration_ms":42`} {
		if !strings.Contains(string(body), expect) {
			t.Errorf("expected %s in wire format, got: %s", expect, body)
		}
	}
}

// TestBuildResponse_IncludesFindingsWhenOptedIn is the symmetric test:
// when the operator explicitly flips FERRET_INCLUDE_FINDINGS=true,
// FindingsByType MUST be populated and serialize on the wire.
//
// Without this pair, the omits-by-default test could pass even if
// FindingsByType were never populated under any condition.
func TestBuildResponse_IncludesFindingsWhenOptedIn(t *testing.T) {
	wantFindings := map[string]int{"EMAIL": 1, "SSN": 2}

	resp := buildResponse(
		"redacted text",
		wantFindings,
		42,
		"req-abc-123",
		true, // explicitly opt in
	)

	if !reflect.DeepEqual(resp.FindingsByType, wantFindings) {
		t.Errorf("buildResponse(includeFindings=true) FindingsByType = %v; want %v", resp.FindingsByType, wantFindings)
	}

	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(body), `"findings_by_type":`) {
		t.Errorf("findings_by_type missing from wire format: %s", body)
	}
	// Both per-type counts should appear; map iteration order is
	// random but both keys must be present somewhere in the output.
	for _, key := range []string{`"EMAIL":1`, `"SSN":2`} {
		if !strings.Contains(string(body), key) {
			t.Errorf("expected %s in wire format, got: %s", key, body)
		}
	}
}

// TestBuildResponse_EmptyFindingsBehavior documents the interaction
// between the `omitempty` tag and an empty (but non-nil) findings map.
// Go's json package treats both nil and zero-length maps as "empty"
// for omitempty purposes, so even with includeFindings=true an empty
// map is elided from the wire format.
//
// This is a deliberate trade-off: callers that need to distinguish
// "nothing matched" from "the gateway didn't tell us" must check the
// HTTP status code and trust that 200 + no field means the same
// thing as 200 + empty field. We keep the omitempty tag because it
// is what makes the side-channel guard work in the includeFindings=
// false case; without it, FindingsByType would render as `null` and
// the wire format would still leak the existence of the per-type
// counts feature.
func TestBuildResponse_EmptyFindingsBehavior(t *testing.T) {
	emptyMap := map[string]int{}

	// includeFindings=false: field omitted (the security-relevant case).
	respOmitted := buildResponse("ok", emptyMap, 1, "rid", false)
	body, err := json.Marshal(respOmitted)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body), "findings_by_type") {
		t.Errorf("includeFindings=false leaked findings_by_type with empty map: %s", body)
	}

	// includeFindings=true with empty map: ALSO omitted by omitempty.
	// Documented behavior; not a leak (the empty case is harmless).
	respIncluded := buildResponse("ok", emptyMap, 1, "rid", true)
	body2, err := json.Marshal(respIncluded)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body2), "findings_by_type") {
		t.Errorf("empty findings map should be omitted by omitempty, got: %s", body2)
	}
}
