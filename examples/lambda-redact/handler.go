// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is a reference Lambda handler for a redaction gateway
// built on github.com/awslabs/ferret-scan/pkg/redact.
//
// This is its own Go module (see go.mod) so the AWS Lambda runtime
// dependency does not leak into the parent ferret-scan module. Build
// for arm64/al2023 with the project Makefile:
//
//	make -C examples/lambda-redact build
//
// See README.md for end-to-end deploy instructions and architecture
// notes. The companion terraform/ directory provisions the supporting
// infrastructure (API Gateway, IAM role, log group, etc.).
//
// Key design properties this example demonstrates:
//
//   - One redact.Engine per execution environment, constructed in init().
//     Per-request setup cost is zero. This is the entire point of the
//     Engine pattern.
//
//   - No payload logging. The handler logs only the audit record (counts,
//     byte sizes, duration) — never req.Text or res.Redacted. The
//     function's log stream stays free of input bytes by construction.
//
//   - Sanitized errors. The handler returns a request ID for correlation
//     but never the raw input or matched substring in error responses.
//
//   - Strategy validation. Unknown strategy strings produce a 400-style
//     error rather than silently falling through to the default.
//
//   - Side-channel guard. Per-type finding counts are omitted from the
//     response by default; flip FERRET_INCLUDE_FINDINGS=true to enable
//     them for single-tenant or debug deployments.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/awslabs/ferret-scan/pkg/redact"
)

// engine is constructed once per Lambda execution environment and
// reused for every invocation. With provisioned concurrency, the
// construction cost is paid during init phase, not on the user's
// critical path.
var engine *redact.Engine

// includeFindingsInResponse, when true, attaches FindingsByType to the
// JSON response body. Defaults to false because the per-type counts
// constitute a soft side-channel: a multi-tenant gateway that returns
// {"PASSPORT": 1} tells the caller they sent passport data, which can
// leak inferred user behavior even though no payload bytes are exposed.
//
// Flip via FERRET_INCLUDE_FINDINGS=true ONLY for single-tenant or
// debug deployments where the caller already knows what they sent.
// The audit log always carries the full counts regardless — operators
// can query the function's log stream for them without exposing them
// on the wire.
var includeFindingsInResponse bool

func init() {
	// Validators to run. Configure via env var so deployers can
	// restrict the validator surface without a code change.
	checks := []string{"all"}
	if v := os.Getenv("FERRET_CHECKS"); v != "" {
		checks = parseCSV(v)
	}

	// Default redaction strategy. Override per-request via Request.Strategy.
	strategy := redact.FormatPreserving
	if v := os.Getenv("FERRET_STRATEGY"); v != "" {
		s, err := parseStrategy(v)
		if err != nil {
			log.Fatalf("init: invalid FERRET_STRATEGY: %v", err)
		}
		strategy = s
	}

	// Side-channel control: response body keeps FindingsByType only
	// when explicitly opted in. Safe-by-default — the audit log still
	// has the full counts, so operators don't lose visibility.
	includeFindingsInResponse = os.Getenv("FERRET_INCLUDE_FINDINGS") == "true"

	// LogWriter is intentionally left nil — pkg/redact defaults to
	// io.Discard, which keeps the internal observer's output out of
	// the function's log stream entirely. The handler writes its own
	// structured audit record at the end of each invocation.
	e, err := redact.NewEngine(redact.EngineOptions{
		Checks:   checks,
		Strategy: strategy,
	})
	if err != nil {
		log.Fatalf("init: failed to construct redact.Engine: %v", err)
	}
	engine = e
}

// Request is the JSON body the handler accepts. Field names use
// snake_case to match common REST conventions; see README.md for
// example payloads.
type Request struct {
	Text     string `json:"text"`
	Strategy string `json:"strategy,omitempty"` // "simple" | "format_preserving" | "synthetic"
	Label    string `json:"label,omitempty"`
}

// Response is the JSON body the handler returns on success. Field
// presence is deliberate:
//
//   - `redacted` is always present.
//
//   - `request_id` echoes the caller's `Request.Label` when supplied,
//     and is OMITTED (omitempty) when the caller didn't supply a
//     label. We do NOT generate a server-side UUID to fill it in:
//     a server-supplied identifier the caller can't predict is worse
//     than a missing field — callers wouldn't know whether it's
//     stable across retries (it isn't), wouldn't know whether to log
//     it, and would have a third correlation key on top of
//     `gateway_request_id` and their own. Omission is correct here.
//
//   - `gateway_request_id` is the API Gateway request ID, always
//     present. This is the canonical correlation key for operators —
//     it's what shows up in CloudWatch and X-Ray.
//
//   - `duration_ms` is always present.
//
//   - `findings_count` and `findings_by_type` are BOTH gated by the
//     same FERRET_INCLUDE_FINDINGS toggle. They're a side-channel
//     even at single-integer resolution ("your input had 4 sensitive
//     items") in multi-tenant deployments. Single toggle, both
//     signals follow it.
//
// The matched substring is never on the wire. Callers that need the
// matched bytes must add a separate, authenticated endpoint that
// uses pkg/redact's FindingsWithMatchText and is gated by a
// stricter authorization layer than the redaction route itself.
type Response struct {
	Redacted         string         `json:"redacted"`
	RequestID        string         `json:"request_id,omitempty"`
	GatewayRequestID string         `json:"gateway_request_id"`
	DurationMS       int64          `json:"duration_ms"`
	FindingsCount    *int           `json:"findings_count,omitempty"`
	FindingsByType   map[string]int `json:"findings_by_type,omitempty"`
}

// ErrorResponse is returned for invalid input. It deliberately does NOT
// echo the request body — that's the input we're trying to protect.
type ErrorResponse struct {
	Error            string `json:"error"`
	RequestID        string `json:"request_id,omitempty"`
	GatewayRequestID string `json:"gateway_request_id"`
}

// buildResponse assembles the JSON response. Pulled out as a pure
// function so the side-channel guard (includeFindings=false elides
// FindingsCount AND FindingsByType) is unit-testable without spinning
// up the full handler or mutating package state.
//
// Security reviewers can verify the entire side-channel logic in
// isolation: when includeFindings is false, both FindingsCount (a
// pointer; nil triggers omitempty) and FindingsByType (a nil map;
// also triggers omitempty) are left at their zero value, and the
// json.Marshal on the Response struct will omit both fields.
//
// requestID is the caller's label or empty (omitted on the wire).
// gatewayRequestID is the API Gateway request ID and always emitted.
func buildResponse(
	redacted string,
	findingsByType map[string]int,
	durationMS int64,
	requestID string,
	gatewayRequestID string,
	includeFindings bool,
) Response {
	resp := Response{
		Redacted:         redacted,
		RequestID:        requestID,
		GatewayRequestID: gatewayRequestID,
		DurationMS:       durationMS,
	}
	if includeFindings {
		// Compute total count by summing per-type counts. Both
		// signals follow the same toggle; reporting one without the
		// other would either confuse callers (count without breakdown
		// = "we know there's data but won't tell you what kind") or
		// inflate side-channel risk (breakdown without count = same
		// signal in two places).
		total := 0
		for _, n := range findingsByType {
			total += n
		}
		resp.FindingsCount = &total
		resp.FindingsByType = findingsByType
	}
	return resp
}

// redactCore is the inner business-logic handler. It takes a parsed
// Request and a gateway-supplied request ID, and produces a Response
// (or an error). Pulled out from the HTTP-shaped entry point
// (handleHTTP, below) so the redaction logic stays runtime-agnostic
// and the HTTP framing — body parsing, status codes, error envelope,
// panic recovery — lives in one place.
//
// requestID is the caller's label or empty (no synthetic default). The
// audit log uses "<unset>" as a placeholder when label is empty for
// readability, but the wire response uses omitempty — see Response.
//
// gatewayRequestID is the API Gateway request ID, threaded through so
// audit records and error logs can correlate to CloudWatch / X-Ray
// without depending on the caller having supplied a label.
//
// Unit tests can target redactCore directly without spinning up an
// API Gateway event mock.
func redactCore(ctx context.Context, req Request, gatewayRequestID string) (Response, error) {
	requestID := req.Label

	// auditID is what shows up in audit log lines and error messages.
	// "<unset>" is a placeholder for human readability ONLY — the wire
	// response uses the real requestID (or omits the field) per the
	// Response struct's omitempty contract.
	auditID := requestID
	if auditID == "" {
		auditID = "<unset>"
	}

	if req.Text == "" {
		return Response{}, fmt.Errorf("request_id=%s: text is required", auditID)
	}

	strategy := redact.FormatPreserving
	overrideStrategy := false
	if req.Strategy != "" {
		s, err := parseStrategy(req.Strategy)
		if err != nil {
			// Operator-side log: capture the offending value with %q
			// so operators can see what the caller sent. The wire
			// response uses the fixed-shape ErrInvalidStrategy
			// sentinel — see parseStrategy and errorCategory. The
			// %q-quoted value lands in CloudWatch only, never on
			// the wire.
			//
			// SINGLE-TENANT ASSUMPTION: this log line is appropriate
			// only when the function log group is operator-only.
			// For a multi-tenant deployment where less-privileged
			// users have read access to the function log group,
			// callers could exfiltrate sensitive data by stuffing
			// it into the strategy field. In that model, drop the
			// `value=%q` field and rely on the access log's
			// requestId for correlation.
			log.Printf("invalid_strategy gateway_request_id=%s value=%q", gatewayRequestID, req.Strategy)
			return Response{}, fmt.Errorf("request_id=%s: %w", auditID, err)
		}
		strategy = s
		overrideStrategy = true
	}

	res, err := engine.Redact(ctx, redact.Request{
		Text:             req.Text,
		Label:            req.Label,
		Strategy:         strategy,
		OverrideStrategy: overrideStrategy,
		// AllowSuppressions intentionally empty: the public API's safe
		// default. A multi-tenant gateway should NEVER let a tenant
		// pass through suppressions without per-tenant isolation.
	})
	if err != nil {
		// Sanitize: never echo req.Text or anything the engine produced.
		switch {
		case errors.Is(err, redact.ErrEmptyText):
			return Response{}, fmt.Errorf("request_id=%s: text is required", auditID)
		case errors.Is(err, redact.ErrTextTooLarge):
			return Response{}, fmt.Errorf("request_id=%s: text exceeds %d-byte limit", auditID, redact.MaxInputBytes)
		case errors.Is(err, redact.ErrEngineClosed):
			return Response{}, fmt.Errorf("request_id=%s: gateway shutting down", auditID)
		default:
			// Generic message — don't leak internals to caller.
			// Specifically check for the NUL-byte rejection from
			// pkg/redact's input normalization. ErrEmptyText and
			// ErrTextTooLarge are sentinels; the NUL-byte rejection
			// is a wrapped error with a stable substring.
			if strings.Contains(err.Error(), "NUL bytes") {
				return Response{}, fmt.Errorf("request_id=%s: text contains binary content (NUL byte detected)", auditID)
			}
			return Response{}, fmt.Errorf("request_id=%s: redaction failed", auditID)
		}
	}

	// Log the audit record (no payload bytes). Format as JSON so log
	// aggregators can query it. Never log the input or the redacted
	// output — those are the bytes the gateway is supposed to protect.
	//
	// AuditRecord is a flat struct of primitives + small string-keyed
	// maps, so json.Marshal cannot realistically fail in practice. We
	// still check the error rather than discarding it because (a)
	// silently-dropped errors are an antipattern, especially in example
	// code that consumers will copy-paste, and (b) if a future change
	// adds a custom MarshalJSON to one of the embedded types, surfacing
	// the failure here lets the operator notice instead of silently
	// emitting unhelpful logs.
	audit := res.AuditRecord()
	auditJSON, err := json.Marshal(audit)
	if err != nil {
		// Don't leak the marshal target in the message — log the type
		// name and the error category only. The audit record contains
		// no PII even on success, but we hold the line on
		// "the only thing in the log is what we explicitly approve."
		log.Printf("audit_marshal_failed err=%q request_id=%s gateway_request_id=%s", err, auditID, gatewayRequestID)
	} else {
		log.Printf("audit gateway_request_id=%s %s", gatewayRequestID, auditJSON)
	}

	return buildResponse(
		res.Redacted,
		audit.FindingsByType,
		audit.Duration.Milliseconds(),
		requestID,
		gatewayRequestID,
		includeFindingsInResponse,
	), nil
}

// errorBody is the JSON shape for error responses. Contains a category
// string and the request_id (caller's label, omitted if unset) plus
// the gateway request ID. Deliberately omits any field that could
// carry the original input or the matched substring.
type errorBody struct {
	Error            string `json:"error"`
	RequestID        string `json:"request_id,omitempty"`
	GatewayRequestID string `json:"gateway_request_id"`
}

// handleHTTP is the actual Lambda entry point under API Gateway HTTP API
// (payload format version 2.0). It unwraps the event, parses the JSON
// body into a Request, calls redactCore, and translates the result into
// an APIGatewayV2HTTPResponse with the right HTTP status code.
//
// Defense in depth: a deferred recover() at the top sanitizes any
// panic from downstream code (engine internals, validators) into a
// 500 with a generic error string. Without this, aws-lambda-go's
// default panic behavior surfaces the panic value to the caller in
// the error response — and the panic value can include input bytes if
// the panic was a nil deref reading req.Text. The recover keeps the
// no-payload-bytes contract holding by construction.
//
// Status code mapping:
//
//   - 200: success
//   - 400: client error — empty text, oversized text, invalid strategy,
//     malformed JSON, or NUL-byte content. The error body's `error`
//     field carries a generic category string; the request_id is
//     preserved (caller's label) for correlation when present.
//   - 503: gateway shutting down (engine closed mid-request).
//   - 500: internal error (marshal failure on the response side, or
//     a recovered panic from downstream code). Generic message; no
//     internal state leaked to the caller.
func handleHTTP(ctx context.Context, evt events.APIGatewayV2HTTPRequest) (resp events.APIGatewayV2HTTPResponse, err error) {
	gatewayRequestID := evt.RequestContext.RequestID

	// Defense in depth: recover from any panic in the handler chain
	// (or the engine internals). Without this, aws-lambda-go's
	// default behavior is to return the panic value as the Lambda
	// invocation error, which API Gateway then surfaces in the
	// integration response. A nil-deref panic on req.Text would
	// echo the input bytes to the caller. Recover here flattens any
	// panic into a generic 500 with a sanitized error category.
	defer func() {
		if r := recover(); r != nil {
			// Log the panic type and gateway_request_id ONLY. Never
			// log the panic value itself (`r`) — a panic value can
			// contain input bytes, especially for runtime panics
			// like nil-deref where the runtime synthesizes a message
			// that may include surrounding context.
			log.Printf("panic_recovered type=%T gateway_request_id=%s", r, gatewayRequestID)
			resp = errorResponse(http.StatusInternalServerError, "internal_error", "", gatewayRequestID)
			err = nil
		}
	}()

	// Unwrap the body. HTTP API v2 sets isBase64Encoded when the
	// upstream client sent binary; for JSON requests it's normally
	// false but we handle it defensively.
	body := evt.Body
	if evt.IsBase64Encoded {
		decoded, decErr := base64.StdEncoding.DecodeString(body)
		if decErr != nil {
			return errorResponse(http.StatusBadRequest, "invalid_base64_body", "", gatewayRequestID), nil
		}
		body = string(decoded)
	}

	var req Request
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		// Don't echo the body — it might already contain sensitive
		// content that the caller intended us to redact.
		return errorResponse(http.StatusBadRequest, "invalid_json_body", "", gatewayRequestID), nil
	}

	result, redactErr := redactCore(ctx, req, gatewayRequestID)
	if redactErr != nil {
		// Map errors to HTTP status. The error message format
		// "request_id=<id>: <category>" is produced by redactCore;
		// we extract the category for the JSON body without echoing
		// internal details. The caller's request_id (req.Label) is
		// preserved on the wire (omitempty when unset).
		category := errorCategory(redactErr)
		status := errorStatus(redactErr)
		return errorResponse(status, category, req.Label, gatewayRequestID), nil
	}

	respBody, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		// Marshal of our own Response struct can't realistically fail,
		// but suppress-and-log is wrong here. Return a 500 with a
		// generic message.
		log.Printf("response_marshal_failed err=%q gateway_request_id=%s", marshalErr, gatewayRequestID)
		return errorResponse(http.StatusInternalServerError, "internal_error", req.Label, gatewayRequestID), nil
	}

	return events.APIGatewayV2HTTPResponse{
		StatusCode: http.StatusOK,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(respBody),
	}, nil
}

// errorResponse builds an APIGatewayV2HTTPResponse with a JSON body
// containing the error category, the caller's request_id (omitted if
// unset), and the gateway request ID. Centralized so every error path
// produces the same wire shape and we can't accidentally omit
// gateway_request_id.
func errorResponse(status int, category, requestID, gatewayRequestID string) events.APIGatewayV2HTTPResponse {
	body, err := json.Marshal(errorBody{
		Error:            category,
		RequestID:        requestID,
		GatewayRequestID: gatewayRequestID,
	})
	if err != nil {
		// Triple-impossible: marshaling a struct of three strings.
		// If it ever happens, return a hardcoded body so we don't
		// leak a panic up the stack.
		body = []byte(`{"error":"internal_error","gateway_request_id":""}`)
	}
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(body),
	}
}

// errorCategory pulls a stable short string out of redactCore's error.
// We don't echo redactCore's full message because it includes the
// request_id and a colon separator that we render separately.
func errorCategory(err error) string {
	msg := err.Error()
	// Format is "request_id=<id>: <category>". Strip the prefix.
	if idx := strings.Index(msg, ": "); idx >= 0 {
		return msg[idx+2:]
	}
	return msg
}

// errorStatus maps redactCore's known errors to HTTP status codes.
// Anything that didn't come from a known sentinel is treated as
// internal (500) rather than client (400) — failing closed.
func errorStatus(err error) int {
	switch {
	case errors.Is(err, redact.ErrEmptyText),
		errors.Is(err, redact.ErrTextTooLarge),
		errors.Is(err, ErrInvalidStrategy):
		return http.StatusBadRequest
	case errors.Is(err, redact.ErrEngineClosed):
		return http.StatusServiceUnavailable
	}
	// String-match the categories that redactCore produces but that
	// don't have public sentinels (text-required check before reaching
	// the engine, NUL-byte rejection from pkg/redact's input
	// normalization). All matched substrings are FIXED, never
	// derived from caller input — see parseStrategy and ErrInvalidStrategy
	// for the rationale.
	msg := err.Error()
	switch {
	case strings.Contains(msg, "text is required"),
		strings.Contains(msg, "text exceeds"),
		strings.Contains(msg, "binary content"):
		return http.StatusBadRequest
	case strings.Contains(msg, "gateway shutting down"):
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

// parseStrategy converts the wire-level strategy string to the public
// redact.Strategy enum. Unknown values produce a fixed-shape error
// (ErrInvalidStrategy) rather than echoing the caller's value: even
// for an enum check, putting `%q` of caller-supplied input in the
// error message means the input lands on the wire in the error
// envelope (errorCategory strips only the request_id= prefix). The
// fixed-shape error keeps the wire response payload-free; operators
// can still see the bad value in the audit log line, which is
// produced from req.Strategy directly rather than via this error.
//
// Silent fallback to a default would hide a typo'd client config and
// produce confusingly different redactions than the caller asked
// for, so we still return an error — just one that doesn't echo
// the input.
var ErrInvalidStrategy = errors.New("invalid strategy (want simple|format_preserving|synthetic)")

func parseStrategy(s string) (redact.Strategy, error) {
	switch s {
	case "simple":
		return redact.Simple, nil
	case "format_preserving", "":
		return redact.FormatPreserving, nil
	case "synthetic":
		return redact.Synthetic, nil
	default:
		return 0, ErrInvalidStrategy
	}
}

// parseCSV splits a comma-separated string and trims whitespace from
// each entry. Empty entries (trailing commas, double commas) are
// dropped. Used to parse FERRET_CHECKS at init time.
func parseCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// main wires up the Lambda runtime. For local testing without a
// Lambda runtime, set FERRET_LOCAL=1 and pass the input as argv[1]:
//
//	FERRET_LOCAL=1 ./bootstrap 'card 5500-0000-0000-0004 from alice@example.com'
//
// Otherwise lambda.Start blocks until the runtime delivers an
// invocation, which is the correct behavior under provided.al2023.
func main() {
	if os.Getenv("FERRET_LOCAL") == "1" {
		runLocal()
		return
	}
	lambda.Start(handleHTTP)
}

// runLocal drives a single invocation from argv for local testing.
// Bypasses the HTTP framing in handleHTTP and calls redactCore
// directly — useful for verifying the redaction logic without
// constructing an APIGatewayV2HTTPRequest by hand.
//
// Kept separate so the production path through lambda.Start is the
// last thing executed in main().
func runLocal() {
	if len(os.Args) < 2 {
		log.Println("usage: FERRET_LOCAL=1 ./bootstrap '<text to redact>'")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := redactCore(ctx, Request{Text: os.Args[1], Label: "local-test"}, "local-no-gateway")
	if err != nil {
		log.Fatalf("redactCore: %v", err)
	}
	out, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		// Same reasoning as the audit-log marshal: realistically
		// unreachable, but example code shouldn't model
		// `_ =`-style error suppression.
		log.Fatalf("marshal response: %v", err)
	}
	fmt.Println(string(out))
}
