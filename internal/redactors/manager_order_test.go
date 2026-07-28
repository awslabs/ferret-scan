// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// stubRedactor is a Redactor that copies its input to the output path and
// reports one redaction, which is enough to exercise ProcessMatches end to end.
type stubRedactor struct {
	name  string
	types []string
}

func (s *stubRedactor) GetName() string             { return s.name }
func (s *stubRedactor) GetSupportedTypes() []string { return s.types }

func (s *stubRedactor) GetSupportedStrategies() []RedactionStrategy {
	return []RedactionStrategy{RedactionSimple, RedactionFormatPreserving, RedactionSynthetic}
}

func (s *stubRedactor) RedactDocument(originalPath, outputPath string, matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(outputPath, []byte("redacted"), 0o600); err != nil {
		return nil, err
	}
	mappings := make([]RedactionMapping, 0, len(matches))
	for _, m := range matches {
		mappings = append(mappings, RedactionMapping{
			RedactedText: "[REDACTED]",
			DataType:     m.Type,
			Strategy:     strategy,
			Confidence:   m.Confidence,
		})
	}
	return &RedactionResult{
		Success:          true,
		RedactedFilePath: outputPath,
		RedactionMap:     mappings,
	}, nil
}

func (s *stubRedactor) GetComponentName() string { return s.name }

// newTestManager builds a manager writing under dir, failing the test if the
// output manager cannot be constructed.
func newTestManager(t *testing.T, dir string) *RedactionManager {
	t.Helper()
	om, err := NewOutputStructureManager(dir, nil)
	if err != nil {
		t.Fatalf("NewOutputStructureManager(%s): %v", dir, err)
	}
	return NewRedactionManager(om, nil)
}

// TestGetRegisteredRedactors_StableOrder locks the per-redactor file type lists.
// They were appended while ranging the registration map, so the same manager
// reported its supported types in a different order on every call.
func TestGetRegisteredRedactors_StableOrder(t *testing.T) {
	// Registration lowercases each type and prefixes a dot, so the dotted and
	// undotted spellings below collapse to four keys. Supplied in neither the
	// expected order nor its reverse.
	want := []string{".docx", ".pptx", ".txt", ".xlsx"}

	for i := 0; i < auditIterations; i++ {
		rm := newTestManager(t, t.TempDir())
		if err := rm.RegisterRedactor(&stubRedactor{
			name:  "stub",
			types: []string{".xlsx", "txt", ".docx", "pptx", ".txt", "docx", ".pptx", "xlsx"},
		}); err != nil {
			t.Fatalf("RegisterRedactor: %v", err)
		}

		got := rm.GetRegisteredRedactors()["stub"]
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d types, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: type %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestProcessMatches_StableDocumentIDs is the important one in this file. Audit
// log document IDs are assigned from the file loop's position (doc_0, doc_1, …).
// The loop ranged a map keyed on file path, so the SAME file was recorded under a
// different document ID on every run, and so was the order of ProcessedFiles.
// An audit log is a compliance artifact — one that cannot be compared against a
// previous run of the same scan is close to useless.
func TestProcessMatches_StableDocumentIDs(t *testing.T) {
	// Five files supplied in neither the expected order nor its reverse.
	inputs := []string{"src/zeta.txt", "src/alpha.txt", "docs/readme.txt", "notes.txt", "src/mid.txt"}
	want := []string{"docs/readme.txt", "notes.txt", "src/alpha.txt", "src/mid.txt", "src/zeta.txt"}

	seenPairings := make(map[string]int)
	for i := 0; i < 40; i++ {
		root := t.TempDir()
		var matches []detector.Match
		for _, rel := range inputs {
			full := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(full, []byte("SSN: 449-87-4100\n"), 0o600); err != nil {
				t.Fatalf("write input: %v", err)
			}
			matches = append(matches, detector.Match{
				Text: "449-87-4100", LineNumber: 1, Type: "SSN",
				Confidence: 100, Filename: full, Validator: "ssn",
			})
		}

		rm := newTestManager(t, filepath.Join(root, "out"))
		if err := rm.RegisterRedactor(&stubRedactor{name: "stub", types: []string{".txt"}}); err != nil {
			t.Fatalf("RegisterRedactor: %v", err)
		}

		results, err := rm.ProcessMatches(matches, nil)
		if err != nil {
			t.Fatalf("iteration %d: ProcessMatches: %v", i, err)
		}
		if len(results.ProcessedFiles) != len(want) {
			t.Fatalf("iteration %d: got %d processed files, want %d",
				i, len(results.ProcessedFiles), len(want))
		}

		// ProcessedFiles order.
		for j := range want {
			got := results.ProcessedFiles[j].OriginalPath
			if !strings.HasSuffix(filepath.ToSlash(got), want[j]) {
				t.Fatalf("iteration %d: processed file %d = %q, want a path ending in %q",
					i, j, got, want[j])
			}
		}

		// Document ID assignment: doc_0 must always name the same file.
		var pairing []string
		for _, id := range rm.auditLogManager.ListAuditLogs() {
			log, ok := rm.auditLogManager.GetAuditLog(id)
			if !ok {
				t.Fatalf("iteration %d: audit log %s vanished", i, id)
			}
			rel, err := filepath.Rel(root, log.OriginalPath)
			if err != nil {
				t.Fatalf("iteration %d: relativize %s: %v", i, log.OriginalPath, err)
			}
			pairing = append(pairing, id+"="+filepath.ToSlash(rel))
		}
		seenPairings[strings.Join(pairing, ",")]++
	}

	if len(seenPairings) != 1 {
		t.Fatalf("audit log document IDs were assigned to files %d different ways across runs, want 1:\n%v",
			len(seenPairings), seenPairings)
	}
}
