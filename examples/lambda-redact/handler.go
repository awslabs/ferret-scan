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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

// Response is the JSON body the handler returns on success. Note the
// absence of `findings_with_match_text` or any field that could carry
// the matched substring — this is the safe default. Callers that need
// the matched bytes should add a separate, authenticated endpoint.
//
// FindingsByType is omitted by default; see includeFindingsInResponse
// for the side-channel rationale. The audit log always carries it
// regardless.
type Response struct {
	Redacted       string         `json:"redacted"`
	FindingsByType map[string]int `json:"findings_by_type,omitempty"`
	RequestID      string         `json:"request_id"`
	DurationMS     int64          `json:"duration_ms"`
}

// ErrorResponse is returned for invalid input. It deliberately does NOT
// echo the request body — that's the input we're trying to protect.
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}

// buildResponse assembles the JSON response. Pulled out as a pure
// function so the side-channel guard (includeFindings=false elides
// FindingsByType) is unit-testable without spinning up the full
// handler or mutating package state.
//
// Security reviewers can verify the entire side-channel logic in
// isolation: when includeFindings is false, FindingsByType is left at
// its zero value (nil) and the json.Marshal on the Response struct
// will omit the field due to the `omitempty` tag.
func buildResponse(
	redacted string,
	findingsByType map[string]int,
	durationMS int64,
	requestID string,
	includeFindings bool,
) Response {
	resp := Response{
		Redacted:   redacted,
		RequestID:  requestID,
		DurationMS: durationMS,
	}
	if includeFindings {
		resp.FindingsByType = findingsByType
	}
	return resp
}

// handle is the Lambda entry point. The wrapper is generic enough to
// adapt to any runtime: API Gateway HTTP API (the default), Function
// URLs, EventBridge, or direct invocation. For HTTP API integrations
// you typically wrap this with the events.APIGatewayV2HTTPRequest
// adapter; that adaptation lives in your deployment, not the handler.
func handle(ctx context.Context, req Request) (Response, error) {
	requestID := req.Label
	if requestID == "" {
		requestID = "<unset>"
	}

	if req.Text == "" {
		return Response{}, fmt.Errorf("request_id=%s: text is required", requestID)
	}

	strategy := redact.FormatPreserving
	overrideStrategy := false
	if req.Strategy != "" {
		s, err := parseStrategy(req.Strategy)
		if err != nil {
			return Response{}, fmt.Errorf("request_id=%s: %w", requestID, err)
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
			return Response{}, fmt.Errorf("request_id=%s: text is required", requestID)
		case errors.Is(err, redact.ErrTextTooLarge):
			return Response{}, fmt.Errorf("request_id=%s: text exceeds %d-byte limit", requestID, redact.MaxInputBytes)
		case errors.Is(err, redact.ErrEngineClosed):
			return Response{}, fmt.Errorf("request_id=%s: gateway shutting down", requestID)
		default:
			// Generic message — don't leak internals to caller.
			return Response{}, fmt.Errorf("request_id=%s: redaction failed", requestID)
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
		log.Printf("audit_marshal_failed err=%q request_id=%s", err, requestID)
	} else {
		log.Printf("audit %s", auditJSON)
	}

	return buildResponse(
		res.Redacted,
		audit.FindingsByType,
		audit.Duration.Milliseconds(),
		requestID,
		includeFindingsInResponse,
	), nil
}

// parseStrategy converts the wire-level strategy string to the public
// redact.Strategy enum. Unknown values produce an error rather than
// silently falling through to the default — silent fallback would
// hide a typo'd client config and produce confusingly different
// redactions than the caller asked for.
func parseStrategy(s string) (redact.Strategy, error) {
	switch s {
	case "simple":
		return redact.Simple, nil
	case "format_preserving", "":
		return redact.FormatPreserving, nil
	case "synthetic":
		return redact.Synthetic, nil
	default:
		return 0, fmt.Errorf("invalid strategy %q (want simple|format_preserving|synthetic)", s)
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
// Otherwise lambda.Start(handle) blocks until the runtime delivers an
// invocation, which is the correct behavior under provided.al2023.
func main() {
	if os.Getenv("FERRET_LOCAL") == "1" {
		runLocal()
		return
	}
	lambda.Start(handle)
}

// runLocal drives a single invocation from argv for local testing.
// Kept separate so the production path through lambda.Start is the
// last thing executed in main().
func runLocal() {
	if len(os.Args) < 2 {
		log.Println("usage: FERRET_LOCAL=1 ./handler '<text to redact>'")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := handle(ctx, Request{Text: os.Args[1], Label: "local-test"})
	if err != nil {
		log.Fatalf("handle: %v", err)
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
