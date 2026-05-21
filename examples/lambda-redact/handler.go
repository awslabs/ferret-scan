// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples_lambda
// +build examples_lambda

// Package main is a reference Lambda handler for a redaction gateway
// built on github.com/awslabs/ferret-scan/pkg/redact.
//
// See README.md in this directory for build / deploy instructions and
// architecture notes. The build tag prevents this file from being
// compiled as part of the main ferret-scan module — copy it into your
// own module to deploy.
//
// Key design properties this example demonstrates:
//
//   - One redact.Engine per execution environment, constructed in init().
//     Per-request setup cost is zero. This is the entire point of the
//     Engine pattern.
//
//   - No payload logging. The handler logs only the audit record (counts,
//     byte sizes, duration) — never req.Text or res.Redacted. CloudWatch
//     stays free of input bytes by construction.
//
//   - Sanitized errors. The handler returns a request ID for correlation
//     but never the raw input or matched substring in error responses.
//
//   - Strategy validation. Unknown strategy strings produce a 400-style
//     error rather than silently falling through to the default.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	// Uncomment when deploying to Lambda. Adding it here would force a
	// dependency on aws-lambda-go for the entire ferret-scan module,
	// which intentionally avoids AWS SDK imports in its core.
	//
	// "github.com/aws/aws-lambda-go/lambda"

	"github.com/awslabs/ferret-scan/pkg/redact"
)

// engine is constructed once per Lambda execution environment and
// reused for every invocation. With provisioned concurrency, the
// construction cost is paid during init phase, not on the user's
// critical path.
var engine *redact.Engine

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

	// LogWriter is intentionally left nil — pkg/redact defaults to
	// io.Discard, which keeps the internal observer's output out of
	// CloudWatch entirely. The handler writes its own structured
	// audit record at the end of each invocation.
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
type Response struct {
	Redacted       string         `json:"redacted"`
	FindingsByType map[string]int `json:"findings_by_type"`
	RequestID      string         `json:"request_id"`
	DurationMS     int64          `json:"duration_ms"`
}

// ErrorResponse is returned for invalid input. It deliberately does NOT
// echo the request body — that's the input we're trying to protect.
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}

// handle is the Lambda entry point. Replace with whatever your runtime
// needs (events.APIGatewayProxyRequest for API Gateway HTTP API,
// events.LambdaFunctionURLRequest for Function URLs, etc.).
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

	// Log the audit record (no payload bytes). Format as JSON so
	// CloudWatch Insights can query it. Per BSC4: never log PII.
	auditJSON, _ := json.Marshal(res.AuditRecord())
	log.Printf("audit %s", auditJSON)

	return Response{
		Redacted:       res.Redacted,
		FindingsByType: res.AuditRecord().FindingsByType,
		RequestID:      requestID,
		DurationMS:     res.AuditRecord().Duration.Milliseconds(),
	}, nil
}

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

func parseCSV(v string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(v); i++ {
		if i == len(v) || v[i] == ',' {
			s := v[start:i]
			// trim spaces
			for len(s) > 0 && s[0] == ' ' {
				s = s[1:]
			}
			for len(s) > 0 && s[len(s)-1] == ' ' {
				s = s[:len(s)-1]
			}
			if s != "" {
				out = append(out, s)
			}
			start = i + 1
		}
	}
	return out
}

// main is the program entry point. When deploying as a real Lambda,
// uncomment the lambda.Start line and remove the local-test fallback.
func main() {
	// In a real deployment:
	//
	// lambda.Start(handle)
	//
	// For local testing, run a single redaction against argv[1]:
	if len(os.Args) < 2 {
		log.Println("usage: handler '<text to redact>'")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := handle(ctx, Request{Text: os.Args[1], Label: "local-test"})
	if err != nil {
		log.Fatalf("handle: %v", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}
