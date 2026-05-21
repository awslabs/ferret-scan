// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package redact is the public, stable API for embedding ferret-scan as
// an in-process library — Lambda handlers, sidecars, gRPC servers, batch
// jobs, and any other Go code that wants to scan and redact text without
// shelling out to the CLI.
//
// # Design goals
//
//   - Reusable Engine. Validators, the enhanced manager, and dual-path
//     state are constructed once via NewEngine and reused for every
//     subsequent Redact call. Per-request setup cost is zero on warm
//     paths; constructing an Engine on every call (the way the CLI's
//     stdin path does today) is roughly an order of magnitude slower
//     than the actual scan on small payloads.
//
//   - Safe by default. The public API has no constructor that loads a
//     suppression file from disk. If a caller wants to suppress findings,
//     they pass an explicit []Rule on the per-request Options. This
//     forecloses the multi-tenant footgun where a misconfigured server
//     accidentally pulls a tenant-scoped suppression file and lets
//     suppressed (i.e. owner-approved) findings flow through unredacted.
//
//   - Minimal Result surface. Result.Findings exposes type, line number,
//     and confidence — not the matched substring or any free-form metadata.
//     Callers who want the matched bytes opt in via FindingsWithMatchText.
//     Result.AuditRecord returns a payload-free, BSC4-shaped structured
//     summary suitable for WORM-safe audit logging (no offsets, no
//     substrings, no PII positions).
//
//   - Configurable log writer. Engine and the underlying scanner write
//     no observability output by default; pass an io.Writer in
//     EngineOptions.LogWriter (typically os.Stderr in dev, io.Discard
//     in production) to capture progress lines. This keeps CloudWatch
//     and other log sinks free of payload bytes by construction.
//
// # Thread safety
//
// An Engine is safe for concurrent use by multiple goroutines. Validators
// are stateless after construction. Two pieces of shared internal state
// serialize across goroutines: the cross-validator signal processor and
// the confidence calibrator (see internal/validators/enhanced_integration.go
// where both take sync.Mutex.Lock on the validation hot path). Workloads
// with high request concurrency should pool engines (one per worker,
// sized to runtime.GOMAXPROCS()) rather than sharing a single engine
// across all goroutines. Lock-stripping that would unlock true parallelism
// is tracked as a future optimization.
//
// AWS Lambda receives at most one in-flight request per execution
// environment by default, so contention never materializes for that
// deployment shape — a single Engine constructed in init() and reused
// for every invocation is the recommended pattern.
//
// # Versioning
//
// This package is versioned with the ferret-scan module. Breaking changes
// will be reflected in a major version bump. Callers should always use
// `defer engine.Close()` even though v1 implementations are no-ops; future
// versions may run background goroutines for metric flushing or signal
// aggregation, and Close becomes mandatory at that point.
//
// # Example
//
//	package main
//
//	import (
//	    "context"
//	    "log"
//
//	    "github.com/awslabs/ferret-scan/pkg/redact"
//	)
//
//	func main() {
//	    engine, err := redact.NewEngine(redact.EngineOptions{
//	        Checks:   []string{"CREDIT_CARD", "EMAIL"},
//	        Strategy: redact.FormatPreserving,
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer engine.Close()
//
//	    result, err := engine.Redact(context.Background(), redact.Request{
//	        Text:  "card 5500-0000-0000-0004 from alice@example.com",
//	        Label: "req-abc-123",
//	    })
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//
//	    log.Println(result.Redacted)
//	    log.Printf("audit: %+v", result.AuditRecord())
//	}
package redact
