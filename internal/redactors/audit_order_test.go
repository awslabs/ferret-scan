// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"encoding/json"
	"strings"
	"testing"
)

// auditIterations is high enough that a randomized Go map order over the entries
// below is overwhelmingly unlikely to produce the expected order every time.
const auditIterations = 200

// TestListAuditLogs_StableOrder locks the order of the ListAuditLogs listing.
// It was built by ranging the audit-log map, so the same manager returned its
// document IDs in a different sequence on every call.
func TestListAuditLogs_StableOrder(t *testing.T) {
	// Registered in neither the expected order nor its reverse.
	register := []string{"doc_c", "doc_a", "doc_e", "doc_b", "doc_d"}
	want := []string{"doc_a", "doc_b", "doc_c", "doc_d", "doc_e"}

	for i := 0; i < auditIterations; i++ {
		m := NewRedactionAuditLogManager("test", t.TempDir())
		for _, id := range register {
			if _, err := m.CreateAuditLog(id, "/in/"+id+".txt", "/out/"+id+".txt"); err != nil {
				t.Fatalf("CreateAuditLog(%s): %v", id, err)
			}
		}

		got := m.ListAuditLogs()
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d IDs, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: ID %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestExportAllAuditLogs_StableValidationError locks which document an export
// blames when more than one audit log is invalid. The validation loop ranged the
// map, so the same broken state produced a different error message on each run —
// an operator fixed whichever document happened to surface and then hit the next.
func TestExportAllAuditLogs_StableValidationError(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < auditIterations; i++ {
		m := NewRedactionAuditLogManager("test", t.TempDir())
		// Three logs, all invalid: clearing DocumentID fails Validate.
		for _, id := range []string{"doc_c", "doc_a", "doc_b"} {
			log, err := m.CreateAuditLog(id, "/in/"+id+".txt", "/out/"+id+".txt")
			if err != nil {
				t.Fatalf("CreateAuditLog(%s): %v", id, err)
			}
			log.DocumentID = ""
		}

		_, err := m.ExportAllAuditLogs()
		if err == nil {
			t.Fatalf("iteration %d: want a validation error, got nil", i)
		}
		seen[err.Error()]++
	}

	if len(seen) != 1 {
		t.Fatalf("the same invalid state produced %d distinct error messages, want 1: %v", len(seen), seen)
	}
	for msg := range seen {
		if !strings.Contains(msg, "doc_a") {
			t.Fatalf("want the lowest-sorting document reported, got %q", msg)
		}
	}
}

// TestValidateAllAuditLogs_StableError is the same guard for the standalone
// validation entry point.
func TestValidateAllAuditLogs_StableError(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < auditIterations; i++ {
		m := NewRedactionAuditLogManager("test", t.TempDir())
		for _, id := range []string{"doc_z", "doc_m", "doc_b"} {
			log, err := m.CreateAuditLog(id, "/in/"+id+".txt", "/out/"+id+".txt")
			if err != nil {
				t.Fatalf("CreateAuditLog(%s): %v", id, err)
			}
			log.DocumentID = ""
		}

		err := m.ValidateAllAuditLogs()
		if err == nil {
			t.Fatalf("iteration %d: want a validation error, got nil", i)
		}
		seen[err.Error()]++
	}

	if len(seen) != 1 {
		t.Fatalf("the same invalid state produced %d distinct error messages, want 1: %v", len(seen), seen)
	}
	for msg := range seen {
		if !strings.Contains(msg, "doc_b") {
			t.Fatalf("want the lowest-sorting document reported, got %q", msg)
		}
	}
}

// TestExportAllAuditLogs_StableJSON confirms the exported document is byte
// identical across runs. encoding/json already sorts map keys, so this held even
// before the ordering fix — it is here so a future change to the export shape
// (an array of logs, say, built by ranging the map) cannot quietly reintroduce
// per-run variance in a compliance artifact.
func TestExportAllAuditLogs_StableJSON(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < auditIterations; i++ {
		m := NewRedactionAuditLogManager("test", t.TempDir())
		for _, id := range []string{"doc_c", "doc_a", "doc_e", "doc_b", "doc_d"} {
			if _, err := m.CreateAuditLog(id, "/in/"+id+".txt", "/out/"+id+".txt"); err != nil {
				t.Fatalf("CreateAuditLog(%s): %v", id, err)
			}
		}

		data, err := m.ExportAllAuditLogs()
		if err != nil {
			t.Fatalf("iteration %d: ExportAllAuditLogs: %v", i, err)
		}

		// The export and each audit log stamp wall-clock timestamps, which are
		// legitimately variable — strip them before comparing. Everything else,
		// including the set and order of documents, must be identical.
		var doc interface{}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("iteration %d: unmarshal export: %v", i, err)
		}
		canonical, err := json.Marshal(stripTimestamps(doc))
		if err != nil {
			t.Fatalf("iteration %d: re-marshal: %v", i, err)
		}
		seen[string(canonical)]++
	}

	if len(seen) != 1 {
		t.Fatalf("exporting one unchanged manager produced %d distinct documents, want 1", len(seen))
	}
}

// stripTimestamps removes every key ending in "timestamp" from a decoded JSON
// document, recursively. Timestamps are environmental (a clock reading), unlike
// emit order, which is our own behavior and must not be normalized away.
func stripTimestamps(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			if strings.HasSuffix(k, "timestamp") {
				delete(t, k)
				continue
			}
			t[k] = stripTimestamps(child)
		}
		return t
	case []interface{}:
		for i, child := range t {
			t[i] = stripTimestamps(child)
		}
		return t
	default:
		return v
	}
}
