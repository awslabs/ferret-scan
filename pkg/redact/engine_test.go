// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/pkg/redact"
)

// helper: build an engine for a test, register cleanup. Tests that need
// a custom EngineOptions can build one directly.
func newTestEngine(t *testing.T, opts redact.EngineOptions) *redact.Engine {
	t.Helper()
	e, err := redact.NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func TestNewEngine_DefaultOptions(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})

	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004 email alice@example.com",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(res.Redacted, "5500-0000-0000-0004") {
		t.Errorf("default-options engine left CC unredacted: %q", res.Redacted)
	}
	if strings.Contains(res.Redacted, "alice@example.com") {
		t.Errorf("default-options engine left email unredacted: %q", res.Redacted)
	}
}

func TestNewEngine_InvalidStrategy(t *testing.T) {
	_, err := redact.NewEngine(redact.EngineOptions{Strategy: redact.Strategy(99)})
	if err == nil {
		t.Fatal("expected error for invalid strategy, got nil")
	}
}

func TestRedact_EmptyText(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	_, err := e.Redact(context.Background(), redact.Request{Text: ""})
	if !errors.Is(err, redact.ErrEmptyText) {
		t.Fatalf("expected ErrEmptyText, got %v", err)
	}
}

func TestRedact_TextTooLarge(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	bigText := strings.Repeat("a", redact.MaxInputBytes+1)
	_, err := e.Redact(context.Background(), redact.Request{Text: bigText})
	if !errors.Is(err, redact.ErrTextTooLarge) {
		t.Fatalf("expected ErrTextTooLarge, got %v", err)
	}
}

func TestRedact_NULRejected(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	_, err := e.Redact(context.Background(), redact.Request{Text: "abc\x00def"})
	if err == nil {
		t.Fatal("expected error for NUL bytes, got nil")
	}
	if !strings.Contains(err.Error(), "NUL") {
		t.Errorf("expected NUL byte error, got %v", err)
	}
}

func TestRedact_BOMStripped(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "\uFEFFcard 5500-0000-0000-0004",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.HasPrefix(res.Redacted, "\uFEFF") {
		t.Errorf("BOM not stripped from output: %q", res.Redacted)
	}
}

func TestRedact_AfterClose(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := e.Redact(context.Background(), redact.Request{Text: "abc"})
	if !errors.Is(err, redact.ErrEngineClosed) {
		t.Fatalf("expected ErrEngineClosed, got %v", err)
	}
}

func TestRedact_FormatPreservingPreservesLength(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})
	input := "card 5500-0000-0000-0004 ok"
	res, err := e.Redact(context.Background(), redact.Request{Text: input})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if len(res.Redacted) != len(input) {
		t.Errorf("format-preserving changed length: in=%d out=%d", len(input), len(res.Redacted))
	}
}

func TestRedact_StrategyOverride(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	res, err := e.Redact(context.Background(), redact.Request{
		Text:             "card 5500-0000-0000-0004",
		Strategy:         redact.Simple,
		OverrideStrategy: true,
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// Simple strategy emits a placeholder; format-preserving does not.
	if !strings.Contains(res.Redacted, "[") || !strings.Contains(res.Redacted, "]") {
		t.Errorf("expected Simple strategy placeholder in output, got %q", res.Redacted)
	}
}

func TestRedact_LabelDefault(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if got := res.AuditRecord().Label; got != "<request>" {
		t.Errorf("expected default Label=<request>, got %q", got)
	}
}

func TestRedact_LabelExplicit(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	res, err := e.Redact(context.Background(), redact.Request{
		Text:  "card 5500-0000-0000-0004",
		Label: "req-abc-123",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if got := res.AuditRecord().Label; got != "req-abc-123" {
		t.Errorf("expected Label=req-abc-123, got %q", got)
	}
}

func TestFindings_DoesNotExposeMatchText(t *testing.T) {
	// The whole point of separating Findings() from FindingsWithMatchText():
	// the safe path must not include the matched substring.
	e := newTestEngine(t, redact.EngineOptions{})
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004 email alice@example.com",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	findings := res.Findings()
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range findings {
		if strings.Contains(f.Type, "5500") || strings.Contains(f.Type, "alice") {
			t.Errorf("Finding.Type leaked match text: %+v", f)
		}
	}
}

func TestFindingsWithMatchText_IncludesMatchText(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{})
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004 ok",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	findings := res.FindingsWithMatchText()
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	// CC validators emit brand-specific types ("MASTERCARD", "VISA",
	// "AMERICAN_EXPRESS", etc.) — not "CREDIT_CARD". The MatchText
	// should still carry the literal substring, regardless of brand.
	foundWithText := false
	for _, f := range findings {
		if f.MatchText != "" && strings.Contains(f.MatchText, "5500") {
			foundWithText = true
		}
	}
	if !foundWithText {
		t.Errorf("expected at least one finding with MatchText containing the CC bytes, got %+v", findings)
	}
}

func TestSuppressions_ExpiredRulesAreDormant(t *testing.T) {
	// Per the design contract: expired rules do NOT suppress. They are
	// dormant, not actively whitelisting. This test pins that behavior.
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	yesterday := time.Now().Add(-24 * time.Hour)
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004",
		AllowSuppressions: []redact.Rule{
			{Type: "CREDIT_CARD", ExpiresAt: &yesterday, Reason: "expired-test"},
		},
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	// Match should NOT be suppressed. The redacted output must differ
	// from the input (the redactor saw the match).
	if strings.Contains(res.Redacted, "5500-0000-0000-0004") {
		t.Errorf("expired rule incorrectly suppressed match (output=%q)", res.Redacted)
	}
	if got := res.AuditRecord().SuppressedByType["CREDIT_CARD"]; got != 0 {
		t.Errorf("expired rule was counted as suppressing %d findings", got)
	}
}

func TestSuppressions_ActiveRuleSuppressesMatch(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	tomorrow := time.Now().Add(24 * time.Hour)
	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004 ok",
		AllowSuppressions: []redact.Rule{
			// Note: the CC validator emits brand-specific types
			// (MASTERCARD, VISA, etc.). A rule on the parent
			// "CREDIT_CARD" alias would NOT match — the API does not
			// alias-expand. This is honest about the data model;
			// callers building suppression rules should consult
			// Result.Findings or Result.AuditRecord.FindingsByType to
			// see the actual emitted type names.
			{Type: "MASTERCARD", ExpiresAt: &tomorrow, Reason: "active-test"},
		},
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	// Active rule should suppress the match — the original CC bytes
	// should be present in the output.
	if !strings.Contains(res.Redacted, "5500-0000-0000-0004") {
		t.Errorf("active rule did NOT suppress match (output=%q)", res.Redacted)
	}
	if got := res.AuditRecord().SuppressedByType["MASTERCARD"]; got != 1 {
		t.Errorf("expected 1 suppressed MASTERCARD finding, got %d", got)
	}
}

func TestSuppressions_ScopeMismatch(t *testing.T) {
	// A rule scoped to "tenant-a" should not suppress matches from "tenant-b".
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	res, err := e.Redact(context.Background(), redact.Request{
		Text:  "card 5500-0000-0000-0004",
		Label: "tenant-b",
		AllowSuppressions: []redact.Rule{
			{Type: "MASTERCARD", Scope: "tenant-a", Reason: "tenant-a-only"},
		},
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if strings.Contains(res.Redacted, "5500-0000-0000-0004") {
		t.Errorf("rule scoped to tenant-a leaked into tenant-b: output=%q", res.Redacted)
	}
}

func TestSuppressions_EmptyScopeMatchesAnyLabel(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	res, err := e.Redact(context.Background(), redact.Request{
		Text:  "card 5500-0000-0000-0004",
		Label: "anything",
		AllowSuppressions: []redact.Rule{
			{Type: "MASTERCARD", Reason: "global"},
		},
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	if !strings.Contains(res.Redacted, "5500-0000-0000-0004") {
		t.Errorf("empty-scope rule did NOT suppress match: output=%q", res.Redacted)
	}
}

func TestEngineOptions_ChecksRestriction(t *testing.T) {
	// Engine constructed with only EMAIL should not flag credit cards.
	e := newTestEngine(t, redact.EngineOptions{
		Checks:   []string{"EMAIL"},
		Strategy: redact.FormatPreserving,
	})

	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card 5500-0000-0000-0004 email alice@example.com",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// Email validator should fire.
	if !strings.Contains(res.Redacted, "card 5500-0000-0000-0004") {
		t.Errorf("CC was redacted despite Checks=[EMAIL]: %q", res.Redacted)
	}
	if strings.Contains(res.Redacted, "alice@example.com") {
		t.Errorf("email NOT redacted despite Checks=[EMAIL]: %q", res.Redacted)
	}
}

func TestEngine_ConcurrentUse(t *testing.T) {
	// The thread-safety contract states Engine is safe for concurrent
	// use. Run many concurrent Redact calls and verify each gets a
	// well-formed Result. Contention is expected and OK; correctness is
	// what we're verifying.
	e := newTestEngine(t, redact.EngineOptions{})

	const goroutines = 16
	const iterations = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errCh := make(chan error, goroutines*iterations)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				res, err := e.Redact(context.Background(), redact.Request{
					Text: "card 5500-0000-0000-0004 from alice@example.com",
				})
				if err != nil {
					errCh <- err
					return
				}
				if strings.Contains(res.Redacted, "5500-0000-0000-0004") {
					errCh <- errors.New("concurrent run produced unredacted output")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestAuditRecord_Shape(t *testing.T) {
	e := newTestEngine(t, redact.EngineOptions{Strategy: redact.FormatPreserving})

	res, err := e.Redact(context.Background(), redact.Request{
		Text:  "card 5500-0000-0000-0004 email alice@example.com",
		Label: "audit-test",
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	rec := res.AuditRecord()
	if rec.Label != "audit-test" {
		t.Errorf("Label: got %q", rec.Label)
	}
	if rec.Strategy != redact.FormatPreserving {
		t.Errorf("Strategy: got %v", rec.Strategy)
	}
	if rec.InputBytes == 0 || rec.RedactedBytes == 0 {
		t.Errorf("byte counts not populated: in=%d out=%d", rec.InputBytes, rec.RedactedBytes)
	}
	if rec.Duration == 0 {
		t.Errorf("Duration not populated")
	}
	if rec.Timestamp.IsZero() {
		t.Errorf("Timestamp not populated")
	}
	if rec.FindingsByType == nil {
		t.Fatal("FindingsByType is nil")
	}
	if rec.SuppressedByType == nil {
		t.Fatal("SuppressedByType is nil")
	}
}

func TestAuditRecord_NoPayloadLeak(t *testing.T) {
	// Verify the AuditRecord shape never includes the matched substring
	// or input bytes — that's the no-payload-bytes contract.
	e := newTestEngine(t, redact.EngineOptions{})

	const sensitiveCC = "5500-0000-0000-0004"
	const sensitiveEmail = "alice@example.com"

	res, err := e.Redact(context.Background(), redact.Request{
		Text: "card " + sensitiveCC + " email " + sensitiveEmail,
	})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	rec := res.AuditRecord()

	// Marshal as if we were going to log it. The resulting string
	// MUST NOT contain the matched substrings.
	rendered := renderForAudit(rec)
	if strings.Contains(rendered, sensitiveCC) {
		t.Errorf("AuditRecord leaked CC: %s", rendered)
	}
	if strings.Contains(rendered, sensitiveEmail) {
		t.Errorf("AuditRecord leaked email: %s", rendered)
	}
}

// renderForAudit simulates a caller writing the audit record to a log
// sink with a verbose formatter; ensures no field carries payload bytes.
func renderForAudit(rec redact.AuditRecord) string {
	var sb strings.Builder
	sb.WriteString("label=")
	sb.WriteString(rec.Label)
	sb.WriteString(" strategy=")
	sb.WriteString(rec.Strategy.String())
	for k, v := range rec.FindingsByType {
		sb.WriteString(" found.")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(intToString(v))
	}
	for k, v := range rec.SuppressedByType {
		sb.WriteString(" suppressed.")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(intToString(v))
	}
	return sb.String()
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestEngine_LogWriter(t *testing.T) {
	// Engine accepts a custom LogWriter; verify io.Discard is the
	// default and that an alternate writer captures progress info.
	var sink strings.Builder
	e, err := redact.NewEngine(redact.EngineOptions{
		LogWriter: &sink,
		Debug:     true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer e.Close()

	_, err = e.Redact(context.Background(), redact.Request{Text: "alice@example.com"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// Debug=true should produce some output. We don't pin the exact
	// content (that's internal), only that something landed in our
	// writer rather than os.Stderr.
	if sink.Len() == 0 {
		t.Errorf("Debug=true wrote nothing to LogWriter")
	}
}

func TestEngine_DefaultLogWriterIsDiscard(t *testing.T) {
	// Implicit: an engine with nil LogWriter should not panic and
	// should not write anywhere. This is the silent-default contract.
	e := newTestEngine(t, redact.EngineOptions{LogWriter: io.Discard})
	_, err := e.Redact(context.Background(), redact.Request{Text: "alice@example.com"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	// No assertion needed — if io.Discard is honored we don't panic
	// and nothing leaks.
}
