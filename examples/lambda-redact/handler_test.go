// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/awslabs/ferret-scan/pkg/redact"
)

// ---------------------------------------------------------------------
// parseStrategy / parseCSV — lightweight env-parsing helpers
// ---------------------------------------------------------------------

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
//
// Critical: the error MUST be the fixed-shape ErrInvalidStrategy
// sentinel and MUST NOT include the caller's value. Echoing the
// value would leak input bytes into the wire error envelope, since
// errorCategory strips only the request_id= prefix.
func TestParseStrategy_RejectsInvalid(t *testing.T) {
	cases := []string{
		"foo",
		"FORMAT_PRESERVING", // case-sensitive; uppercase is rejected
		"format-preserving", // hyphen instead of underscore
		"none",
		"raw",
		"LEAK_CANARY_payload", // verify NO echo of input
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := parseStrategy(in)
			if err == nil {
				t.Errorf("parseStrategy(%q) accepted invalid value, want error", in)
				return
			}
			if !errors.Is(err, ErrInvalidStrategy) {
				t.Errorf("parseStrategy(%q) error is not ErrInvalidStrategy: %v", in, err)
			}
			// Critical leak check: error message MUST NOT contain the
			// caller's input value.
			if strings.Contains(err.Error(), in) {
				t.Errorf("parseStrategy(%q) error echoes caller input: %v", in, err)
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

// ---------------------------------------------------------------------
// buildResponse — side-channel guard
// ---------------------------------------------------------------------

// TestBuildResponse_OmitsFindingsByDefault pins the side-channel guard
// as a property of the handler code (not just the deployed system).
//
// includeFindings=false MUST leave both Response.FindingsByType (nil
// map) and Response.FindingsCount (nil pointer) unset, and the
// resulting JSON encoding MUST NOT contain either field. The two
// signals are gated by the same toggle: reporting one without the
// other would either confuse callers or inflate side-channel risk
// by emitting the same information in two places.
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
		"gw-rid-456",
		false, // the default — DO NOT include findings on the wire
	)

	if resp.FindingsByType != nil {
		t.Errorf("buildResponse(includeFindings=false) populated FindingsByType: %v", resp.FindingsByType)
	}
	if resp.FindingsCount != nil {
		t.Errorf("buildResponse(includeFindings=false) populated FindingsCount: %d", *resp.FindingsCount)
	}
	if resp.Redacted != "redacted text" {
		t.Errorf("Redacted not propagated: got %q", resp.Redacted)
	}
	if resp.RequestID != "req-abc-123" {
		t.Errorf("RequestID not propagated: got %q", resp.RequestID)
	}
	if resp.GatewayRequestID != "gw-rid-456" {
		t.Errorf("GatewayRequestID not propagated: got %q", resp.GatewayRequestID)
	}
	if resp.DurationMS != 42 {
		t.Errorf("DurationMS not propagated: got %d", resp.DurationMS)
	}

	// Marshal as if we were sending it on the wire and assert BOTH
	// findings_* fields are genuinely absent — not just present with a
	// nil/empty value. JSON omission relies on `omitempty` + nil; a
	// zero-length-but-non-nil map would still serialize as `{}`.
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body), "findings_by_type") {
		t.Errorf("findings_by_type leaked into wire format: %s", body)
	}
	if strings.Contains(string(body), "findings_count") {
		t.Errorf("findings_count leaked into wire format: %s", body)
	}
	// Cross-check that the other fields ARE present.
	for _, expect := range []string{
		`"redacted":"redacted text"`,
		`"request_id":"req-abc-123"`,
		`"gateway_request_id":"gw-rid-456"`,
		`"duration_ms":42`,
	} {
		if !strings.Contains(string(body), expect) {
			t.Errorf("expected %s in wire format, got: %s", expect, body)
		}
	}
}

// TestBuildResponse_IncludesFindingsWhenOptedIn is the symmetric test:
// when the operator explicitly flips FERRET_INCLUDE_FINDINGS=true,
// FindingsByType MUST be populated AND FindingsCount MUST equal the
// sum of per-type counts. The two signals are gated by the same toggle.
//
// Without this pair, the omits-by-default test could pass even if
// FindingsByType were never populated under any condition.
func TestBuildResponse_IncludesFindingsWhenOptedIn(t *testing.T) {
	wantFindings := map[string]int{"EMAIL": 1, "SSN": 2}
	wantTotal := 3 // 1 + 2

	resp := buildResponse(
		"redacted text",
		wantFindings,
		42,
		"req-abc-123",
		"gw-rid-456",
		true, // explicitly opt in
	)

	if !reflect.DeepEqual(resp.FindingsByType, wantFindings) {
		t.Errorf("buildResponse(includeFindings=true) FindingsByType = %v; want %v", resp.FindingsByType, wantFindings)
	}
	if resp.FindingsCount == nil {
		t.Fatalf("buildResponse(includeFindings=true) left FindingsCount nil")
	}
	if *resp.FindingsCount != wantTotal {
		t.Errorf("FindingsCount = %d; want %d (sum of per-type)", *resp.FindingsCount, wantTotal)
	}

	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(body), `"findings_by_type":`) {
		t.Errorf("findings_by_type missing from wire format: %s", body)
	}
	if !strings.Contains(string(body), `"findings_count":3`) {
		t.Errorf("findings_count missing or wrong in wire format: %s", body)
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
//
// FindingsCount, by contrast, is a *int with omitempty: when total
// is 0 (empty findings map), the pointer is set but to a zero value,
// and Go's json omitempty for a *int triggers ONLY when the pointer
// itself is nil — a *int pointing to 0 still serializes as "0".
// That's the documented behavior we pin here.
func TestBuildResponse_EmptyFindingsBehavior(t *testing.T) {
	emptyMap := map[string]int{}

	// includeFindings=false: BOTH fields omitted (the security-relevant case).
	respOmitted := buildResponse("ok", emptyMap, 1, "rid", "gw-rid", false)
	body, err := json.Marshal(respOmitted)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body), "findings_by_type") {
		t.Errorf("includeFindings=false leaked findings_by_type with empty map: %s", body)
	}
	if strings.Contains(string(body), "findings_count") {
		t.Errorf("includeFindings=false leaked findings_count with empty map: %s", body)
	}

	// includeFindings=true with empty map: findings_by_type is omitted
	// by omitempty (empty map = "empty"), but findings_count IS present
	// with value 0 (a *int pointer to 0 is not nil). This documents
	// the asymmetry — both signals follow the same TOGGLE but Go's
	// omitempty rules render them differently for the empty case.
	respIncluded := buildResponse("ok", emptyMap, 1, "rid", "gw-rid", true)
	body2, err := json.Marshal(respIncluded)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(body2), "findings_by_type") {
		t.Errorf("empty findings map should be omitted by omitempty, got: %s", body2)
	}
	if !strings.Contains(string(body2), `"findings_count":0`) {
		t.Errorf("expected findings_count:0 with empty map and includeFindings=true, got: %s", body2)
	}
}

// ---------------------------------------------------------------------
// HTTP wrapper — error mapping and envelope shape
// ---------------------------------------------------------------------
//
// handleHTTP is the production Lambda entry point. The unit tests
// below exercise its body parsing, status-code mapping, and
// error-envelope shape WITHOUT spinning up a real Lambda runtime.
//
// These tests caught two real issues during live deployment that
// would otherwise have shipped:
//
//  1. The original handler.go had `func handle(ctx, Request)` —
//     under API Gateway HTTP API v2, Lambda passed the wrapper
//     event (events.APIGatewayV2HTTPRequest) and `Request{}` came
//     out empty. Every redaction failed with "text is required."
//
//  2. Without the centralized errorStatus/errorCategory helpers,
//     every error path either echoed the input (leak) or
//     returned 200 with an error body (caller can't tell from
//     the success path).

func TestErrorStatus_ClientErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"ErrEmptyText sentinel", redact.ErrEmptyText, 400},
		{"ErrTextTooLarge sentinel", redact.ErrTextTooLarge, 400},
		{"ErrInvalidStrategy sentinel", ErrInvalidStrategy, 400},
		{"text is required (string-matched)", errors.New("request_id=x: text is required"), 400},
		{"text exceeds limit (string-matched)", errors.New("request_id=x: text exceeds 100MB limit"), 400},
		{"NUL byte / binary content (string-matched)", errors.New("request_id=x: text contains binary content (NUL byte detected)"), 400},
		{"engine closed → 503", redact.ErrEngineClosed, 503},
		{"unknown error → 500", errors.New("request_id=x: redaction failed"), 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorStatus(tc.err); got != tc.want {
				t.Errorf("errorStatus(%v) = %d; want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestErrorCategory_StripsPrefix(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"with prefix", errors.New("request_id=abc: text is required"), "text is required"},
		{"without prefix", errors.New("plain message"), "plain message"},
		{"empty after colon", errors.New("request_id=abc: "), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorCategory(tc.err); got != tc.want {
				t.Errorf("errorCategory(%q) = %q; want %q", tc.err.Error(), got, tc.want)
			}
		})
	}
}

func TestErrorResponse_PreservesGatewayRequestID(t *testing.T) {
	// errorResponse must always set gateway_request_id (it's the
	// canonical correlation key) and pass through the caller's
	// request_id when present. Critical: this is the chokepoint
	// for the "every error has both correlation IDs" guarantee.
	resp := errorResponse(400, "text is required", "caller-rid", "gw-rid-789")

	if resp.StatusCode != 400 {
		t.Errorf("StatusCode: got %d, want 400", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var body errorBody
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("response body is not valid JSON: %v (%q)", err, resp.Body)
	}
	if body.Error != "text is required" {
		t.Errorf("Error field: got %q, want 'text is required'", body.Error)
	}
	if body.RequestID != "caller-rid" {
		t.Errorf("RequestID field: got %q, want 'caller-rid'", body.RequestID)
	}
	if body.GatewayRequestID != "gw-rid-789" {
		t.Errorf("GatewayRequestID field: got %q, want 'gw-rid-789'", body.GatewayRequestID)
	}
}

func TestErrorResponse_OmitsRequestIDWhenUnset(t *testing.T) {
	// When the caller didn't supply a label, the wire response must
	// omit request_id rather than emit "" — see the Response struct's
	// omitempty contract. errorBody follows the same convention.
	resp := errorResponse(400, "text is required", "", "gw-rid-789")

	// Parse and check FIELD presence, not just struct values: the
	// omitempty behavior is what we're pinning. A "" in the struct
	// isn't enough; the wire bytes must not contain "request_id".
	if strings.Contains(resp.Body, `"request_id"`) {
		t.Errorf("request_id leaked into wire format with empty label: %s", resp.Body)
	}
	// gateway_request_id is always emitted, even with an empty
	// caller-supplied label.
	if !strings.Contains(resp.Body, `"gateway_request_id":"gw-rid-789"`) {
		t.Errorf("gateway_request_id missing from wire format: %s", resp.Body)
	}
}

// ---------------------------------------------------------------------
// redactCore — request validation and error mapping
// ---------------------------------------------------------------------

// TestRedactCore_MissingTextField pins the empty-text fast-path: a
// Request with no Text field set (or with Text="") returns an error
// that errorStatus maps to 400. The handler must NOT call into the
// engine for empty input — that's an unconditional client error.
func TestRedactCore_MissingTextField(t *testing.T) {
	cases := []struct {
		name string
		req  Request
	}{
		{"empty text field", Request{Text: ""}},
		{"omitted text field (zero value)", Request{Label: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := redactCore(context.Background(), tc.req, "gw-rid")
			if err == nil {
				t.Fatalf("redactCore with empty text should error, got nil")
			}
			if !strings.Contains(err.Error(), "text is required") {
				t.Errorf("expected 'text is required' in error, got: %v", err)
			}
			if got := errorStatus(err); got != 400 {
				t.Errorf("errorStatus = %d; want 400 for empty text", got)
			}
		})
	}
}

// TestHandleHTTP_StrategyValueNeverEchoed is the regression-class
// lock for a real bug found during live verification: the original
// parseStrategy returned `fmt.Errorf("invalid strategy %q ...", s)`
// where `s` was caller-supplied. errorCategory strips only the
// request_id= prefix, so the entire "invalid strategy %q ..." text
// landed verbatim on the wire — including the caller's value.
//
// A canary in the strategy field MUST appear NOWHERE in the wire
// response (success or error path). The error envelope's category
// string is now the fixed-shape ErrInvalidStrategy sentinel; the
// caller's value goes only to the audit log (operator-side).
func TestHandleHTTP_StrategyValueNeverEchoed(t *testing.T) {
	const canary = "LEAK_CANARY_5500-1234-5678-9012_alice@example.com"

	reqBody, mErr := json.Marshal(Request{
		Text:     "x",
		Strategy: canary,
		Label:    "strategy-leak-test",
	})
	if mErr != nil {
		t.Fatalf("setup: json.Marshal: %v", mErr)
	}
	evt := events.APIGatewayV2HTTPRequest{
		Body: string(reqBody),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "leak-rid",
		},
	}

	resp, err := handleHTTP(context.Background(), evt)
	if err != nil {
		t.Fatalf("handleHTTP returned a Lambda invocation error: %v", err)
	}
	if resp.StatusCode != 400 {
		t.Errorf("StatusCode: got %d; want 400 for invalid strategy", resp.StatusCode)
	}
	if strings.Contains(resp.Body, canary) {
		t.Errorf("strategy value leaked into wire response body: %s", resp.Body)
	}

	// Verify the error envelope is the fixed-shape "invalid strategy"
	// category — operator-readable, but doesn't include caller input.
	var body errorBody
	if jerr := json.Unmarshal([]byte(resp.Body), &body); jerr != nil {
		t.Fatalf("response body not valid JSON: %v (%q)", jerr, resp.Body)
	}
	if !strings.HasPrefix(body.Error, "invalid strategy") {
		t.Errorf("Error category: got %q; want one starting with 'invalid strategy'", body.Error)
	}
	if strings.Contains(body.Error, canary) {
		t.Errorf("Error category leaked canary: %q", body.Error)
	}
	if body.GatewayRequestID != "leak-rid" {
		t.Errorf("GatewayRequestID: got %q; want 'leak-rid'", body.GatewayRequestID)
	}
}

// TestHandleHTTP_NonStringTextField pins the contract that a JSON
// body with a non-string `text` field (e.g. {"text": 123}) is a 400
// `invalid_json_body`, NOT a 500. The unmarshal error path is the
// only thing protecting the handler from type confusion when callers
// send unexpected payload shapes.
func TestHandleHTTP_NonStringTextField(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"text is a number", `{"text": 123}`},
		{"text is an object", `{"text": {"nested": "value"}}`},
		{"text is null", `{"text": null, "label": "x"}`}, // valid JSON, but text is required after unmarshal
		{"text is array", `{"text": ["a","b"]}`},
		{"completely malformed", `not json at all`},
		{"trailing garbage", `{"text":"hi"} extra`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			evt := events.APIGatewayV2HTTPRequest{
				Body: tc.body,
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					RequestID: "test-gw-rid",
				},
			}
			resp, err := handleHTTP(context.Background(), evt)
			if err != nil {
				t.Fatalf("handleHTTP returned a Lambda invocation error: %v", err)
			}
			if resp.StatusCode != 400 {
				t.Errorf("StatusCode: got %d; want 400 for %s", resp.StatusCode, tc.name)
			}

			var body errorBody
			if jerr := json.Unmarshal([]byte(resp.Body), &body); jerr != nil {
				t.Fatalf("response body not valid JSON: %v (%q)", jerr, resp.Body)
			}
			if body.GatewayRequestID != "test-gw-rid" {
				t.Errorf("gateway_request_id: got %q; want 'test-gw-rid'", body.GatewayRequestID)
			}
			// `null` text unmarshals successfully to "" — that path goes
			// through redactCore and surfaces as "text is required".
			// All other malformed cases go through invalid_json_body.
			if tc.name == "text is null" {
				if body.Error != "text is required" {
					t.Errorf("error category for null text: got %q; want 'text is required'", body.Error)
				}
			} else {
				if body.Error != "invalid_json_body" {
					t.Errorf("error category: got %q; want 'invalid_json_body' for %s", body.Error, tc.name)
				}
			}
		})
	}
}

// TestRedactCore_TextTooLarge confirms that input exceeding the
// 100 MB sentinel surfaces as a 400 (NOT 500). The engine returns
// redact.ErrTextTooLarge from input normalization; redactCore wraps
// it preserving the sentinel via errors.Is in errorStatus.
func TestRedactCore_TextTooLarge(t *testing.T) {
	// Allocate MaxInputBytes + 1 and pass it through. This is ~100 MB;
	// the test runs in a few seconds on a developer laptop. We use a
	// single-byte payload repeated rather than a more complex string
	// because we only care about the size-check path, not redaction.
	tooBig := strings.Repeat("a", redact.MaxInputBytes+1)
	_, err := redactCore(context.Background(), Request{Text: tooBig, Label: "size-test"}, "gw-rid")
	if err == nil {
		t.Fatalf("redactCore with %d-byte text should error, got nil", redact.MaxInputBytes+1)
	}
	if !strings.Contains(err.Error(), "text exceeds") {
		t.Errorf("expected 'text exceeds' in error, got: %v", err)
	}
	if got := errorStatus(err); got != 400 {
		t.Errorf("errorStatus = %d; want 400 for oversized text", got)
	}
}

// TestRedactCore_NULByteIsClientError confirms a NUL byte in the text
// field surfaces as a 400 (NOT a 500). The engine rejects NUL bytes
// in input normalization with a wrapped error containing "NUL bytes";
// redactCore string-matches this substring and produces a categorized
// 400 rather than the generic "redaction failed" 500.
//
// This matters because the natural rejection signals — engine produces
// a generic error, no public sentinel — would default to 500 without
// the explicit string match. A 500 for binary input is wrong: the
// caller sent invalid input, the gateway didn't fail.
func TestRedactCore_NULByteIsClientError(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"NUL at end", "hello world\x00"},
		{"NUL in middle", "hello\x00world"},
		{"NUL at start", "\x00hello"},
		{"only NUL", "\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := redactCore(context.Background(), Request{Text: tc.text, Label: "nul-test"}, "gw-rid")
			if err == nil {
				t.Fatalf("redactCore with NUL byte should error, got nil")
			}
			if !strings.Contains(err.Error(), "binary content") {
				t.Errorf("expected 'binary content' category, got: %v", err)
			}
			if got := errorStatus(err); got != 400 {
				t.Errorf("errorStatus = %d; want 400 for NUL-byte input", got)
			}
		})
	}
}

// TestHandleHTTP_PanicRecovery confirms the defense-in-depth
// `defer recover()` in handleHTTP catches engine panics and
// returns 500 with a sanitized envelope. We force a panic by
// swapping the package-level engine to nil — `nil.Redact()` is
// a runtime nil-pointer dereference, the canonical panic shape
// the recover guard exists to catch.
//
// The critical assertions:
//   - StatusCode is 500 (not a propagated panic).
//   - body.Error is "internal_error" (no leak of nil-deref details).
//   - body.GatewayRequestID is preserved (operators can correlate).
//   - The captured log buffer contains only "panic_recovered type=...
//     gateway_request_id=..." — never the panic value itself, which
//     can include input bytes for runtime panics.
func TestHandleHTTP_PanicRecovery(t *testing.T) {
	saved := engine
	engine = nil
	t.Cleanup(func() { engine = saved })

	// Capture log output to assert payload bytes don't leak via the
	// panic-recovered log line.
	var logBuf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	const sensitivePayload = "card 4532-0151-1283-0366"
	reqBody, mErr := json.Marshal(Request{Text: sensitivePayload, Label: "panic-test"})
	if mErr != nil {
		t.Fatalf("setup: json.Marshal: %v", mErr)
	}
	evt := events.APIGatewayV2HTTPRequest{
		Body: string(reqBody),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "panic-rid",
		},
	}

	resp, err := handleHTTP(context.Background(), evt)
	if err != nil {
		t.Fatalf("handleHTTP returned a Lambda invocation error after panic recovery: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Errorf("StatusCode: got %d; want 500 after panic recovery", resp.StatusCode)
	}

	var body errorBody
	if jerr := json.Unmarshal([]byte(resp.Body), &body); jerr != nil {
		t.Fatalf("response body not valid JSON: %v (%q)", jerr, resp.Body)
	}
	if body.Error != "internal_error" {
		t.Errorf("Error: got %q; want 'internal_error'", body.Error)
	}
	if body.GatewayRequestID != "panic-rid" {
		t.Errorf("GatewayRequestID: got %q; want 'panic-rid'", body.GatewayRequestID)
	}

	// The recovery log line must contain the panic TYPE and
	// gateway_request_id, but never the panic value itself or the
	// input payload.
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "panic_recovered") {
		t.Errorf("expected 'panic_recovered' in log output, got: %q", logOutput)
	}
	if !strings.Contains(logOutput, "gateway_request_id=panic-rid") {
		t.Errorf("expected gateway_request_id in log output, got: %q", logOutput)
	}
	if strings.Contains(logOutput, sensitivePayload) {
		t.Errorf("panic recovery leaked payload bytes into log: %q", logOutput)
	}
}

// TestNoInputBytesLeak is the property test the converged plan calls out
// as the most important: across a matrix of (sensitive payload) ×
// (request path), no payload bytes appear in either the returned error
// OR the captured log buffer.
//
// resp.Redacted is intentionally EXCLUDED from the assertion — the
// redacted output is supposed to contain bytes that survived
// redaction (e.g. surrounding context like "card " or "from "), so a
// blanket "payload bytes don't appear anywhere" check would fail the
// success path. The contract here is narrower: errors and logs must
// not echo the input.
//
// This catches the future-contributor failure mode: someone adds
// `log.Printf("processing input: %q", req.Text)` to a downstream
// helper. That contributor's change would NOT trip a smoke test (the
// audit log line still looks fine on the success path) but WOULD
// trip this test by leaking payload bytes through the captured log
// buffer on every path.
func TestNoInputBytesLeak(t *testing.T) {
	var logBuf bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldOutput) })

	// Each sensitive payload is a recognizable category (CC, SSN,
	// passport-shape) followed by an obvious literal. The literal
	// itself is what we assert doesn't leak.
	sensitive := []string{
		"card 4532-0151-1283-0366",
		"ssn 123-45-6789",
		"passport AB1234567",
	}

	// Three request shapes covering the three control-flow paths
	// through redactCore. Note: invalid_strategy uses a FIXED bogus
	// value rather than the payload-as-strategy, because the strategy
	// field's leak surface is covered by
	// TestHandleHTTP_StrategyValueNeverEchoed. This test focuses on
	// the text field's leak surface.
	paths := []struct {
		name   string
		mkReq  func(string) Request
		expErr bool
	}{
		{"invalid strategy → error", func(s string) Request {
			return Request{Text: s, Strategy: "bogus", Label: "leak-test"}
		}, true},
		{"success path", func(s string) Request {
			return Request{Text: s, Label: "leak-test"}
		}, false},
		{"NUL byte → error", func(s string) Request {
			return Request{Text: s + "\x00", Label: "leak-test"}
		}, true},
	}

	for _, payload := range sensitive {
		for _, p := range paths {
			t.Run(payload+"/"+p.name, func(t *testing.T) {
				logBuf.Reset()

				resp, err := redactCore(context.Background(), p.mkReq(payload), "gw-rid-leak")

				if p.expErr && err == nil {
					t.Fatalf("expected error for %s/%s, got nil", payload, p.name)
				}
				if !p.expErr && err != nil {
					t.Fatalf("expected success for %s/%s, got error: %v", payload, p.name, err)
				}

				assertNoLeak(t, payload, err, logBuf.String(), resp.Redacted)
			})
		}
	}
}

// assertNoLeak is the property check used by TestNoInputBytesLeak.
// Asserts the payload string does not appear in the returned error
// or in the captured log output. resp.Redacted is intentionally
// passed in but not checked: the success path retains some payload
// bytes by design (surrounding context, partial structure).
func assertNoLeak(t *testing.T, payload string, err error, logOutput, redacted string) {
	t.Helper()

	var errStr string
	if err != nil {
		errStr = err.Error()
	}
	if strings.Contains(errStr, payload) {
		t.Errorf("payload bytes leaked into error: error=%q contains %q", errStr, payload)
	}
	if strings.Contains(logOutput, payload) {
		t.Errorf("payload bytes leaked into log: log=%q contains %q", logOutput, payload)
	}

	// Sanity check: the payload itself must be non-empty, otherwise
	// the assertion above is vacuous (every string contains "").
	if payload == "" {
		t.Errorf("test bug: empty payload makes leak assertion vacuous")
	}

	// Document the deliberate exclusion: redacted is the output, not
	// part of the no-leak surface. The reference is unused by intent.
	_ = redacted
}

// ---------------------------------------------------------------------
// handleHTTP — full integration through the HTTP wrapper
// ---------------------------------------------------------------------

// TestHandleHTTP_SuccessRoundtrip exercises the full HTTP wrapper:
// JSON parse → redactCore → buildResponse → JSON marshal. Asserts
// the wire shape matches the documented Response struct (fields
// present, correct types, request_id preserved, gateway_request_id
// always set).
func TestHandleHTTP_SuccessRoundtrip(t *testing.T) {
	reqBody, mErr := json.Marshal(Request{
		Text:  "email alice@example.com",
		Label: "round-trip",
	})
	if mErr != nil {
		t.Fatalf("setup: json.Marshal: %v", mErr)
	}
	evt := events.APIGatewayV2HTTPRequest{
		Body: string(reqBody),
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			RequestID: "rt-gw-rid",
		},
	}

	resp, err := handleHTTP(context.Background(), evt)
	if err != nil {
		t.Fatalf("handleHTTP error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("StatusCode: got %d; want 200, body=%q", resp.StatusCode, resp.Body)
	}

	var body Response
	if jerr := json.Unmarshal([]byte(resp.Body), &body); jerr != nil {
		t.Fatalf("response body not valid JSON: %v (%q)", jerr, resp.Body)
	}
	if body.Redacted == "" {
		t.Errorf("Redacted field empty in success response: %q", resp.Body)
	}
	if body.RequestID != "round-trip" {
		t.Errorf("RequestID: got %q; want 'round-trip'", body.RequestID)
	}
	if body.GatewayRequestID != "rt-gw-rid" {
		t.Errorf("GatewayRequestID: got %q; want 'rt-gw-rid'", body.GatewayRequestID)
	}
	// findings_by_type / findings_count are gated by the package-level
	// includeFindingsInResponse, which defaults to false in tests
	// (the env var isn't set). Verify the side-channel guard holds.
	if strings.Contains(resp.Body, "findings_by_type") {
		t.Errorf("findings_by_type leaked in default test config: %q", resp.Body)
	}
	if strings.Contains(resp.Body, "findings_count") {
		t.Errorf("findings_count leaked in default test config: %q", resp.Body)
	}
}
