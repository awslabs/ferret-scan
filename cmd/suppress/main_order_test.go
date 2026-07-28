// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

const suppressionFixture = `version: "1.0"
rules:
  - id: SUP-00000001
    hash: abc123def456
    reason: known test fixture
    enabled: true
    created_at: 2026-01-01T00:00:00Z
    metadata:
      zone: payments
      validator: CREDIT_CARD
      file: fixtures/cards.txt
      line: "42"
      ticket: JIRA-1234
      owner: platform-team
`

// TestListSuppressionsMetadataIsSorted pins the metadata field order in
// `--action list`. It was printed by ranging rule.Metadata (a map), so listing
// the same unchanged suppression file twice produced different output and the
// two runs could not be diffed — which matters because operators diff this
// listing to see what changed in review.
func TestListSuppressionsMetadataIsSorted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sup.yaml")
	if err := os.WriteFile(path, []byte(suppressionFixture), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		manager := suppressions.NewSuppressionManager(path)
		out := captureStdout(t, func() { listSuppressions(manager) })
		seen[metadataBlock(t, out)]++
	}
	if len(seen) != 1 {
		t.Fatalf("metadata order varied across 100 runs: %d distinct orders %v", len(seen), seen)
	}
	const want = "file=fixtures/cards.txt,line=42,owner=platform-team,ticket=JIRA-1234,validator=CREDIT_CARD,zone=payments"
	if _, ok := seen[want]; !ok {
		t.Fatalf("metadata block = %v, want %q", seen, want)
	}
}

// metadataBlock extracts the "  key: value" lines that follow "Metadata:" and
// renders them as a single comparable string.
func metadataBlock(t *testing.T, out string) string {
	t.Helper()
	idx := strings.Index(out, "Metadata:")
	if idx < 0 {
		t.Fatalf("no Metadata: section in listing:\n%s", out)
	}
	var parts []string
	for _, line := range strings.Split(out[idx:], "\n")[1:] {
		if !strings.HasPrefix(line, "  ") {
			break
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), ": ")
		if !ok {
			break
		}
		parts = append(parts, k+"="+v)
	}
	if len(parts) == 0 {
		t.Fatalf("Metadata: section had no entries:\n%s", out)
	}
	return strings.Join(parts, ",")
}

// TestListSuppressionsWithoutMetadata covers the len == 0 branch: a rule with no
// metadata must not print an empty "Metadata:" header.
func TestListSuppressionsWithoutMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sup.yaml")
	const bare = `version: "1.0"
rules:
  - id: SUP-00000002
    hash: deadbeef
    reason: no metadata here
    enabled: true
    created_at: 2026-01-01T00:00:00Z
`
	if err := os.WriteFile(path, []byte(bare), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	manager := suppressions.NewSuppressionManager(path)
	out := captureStdout(t, func() { listSuppressions(manager) })
	if !strings.Contains(out, "SUP-00000002") {
		t.Fatalf("rule not listed:\n%s", out)
	}
	if strings.Contains(out, "Metadata:") {
		t.Fatalf("unexpected Metadata: header for a rule with no metadata:\n%s", out)
	}
}

// captureStdout redirects os.Stdout for the duration of fn. listSuppressions
// writes with fmt.Printf, so there is no injectable writer to use instead.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stdout = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}
	out := <-done
	if err := r.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}
	return out
}
