// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
)

// newDocIDTestManager builds a manager with an audit log manager wired up, which is
// the only part AddRedactionResult needs.
func newDocIDTestManager(t *testing.T) *RedactionManager {
	t.Helper()
	dir := t.TempDir()
	return &RedactionManager{
		redactors:       make(map[string]Redactor),
		auditLogManager: NewRedactionAuditLogManager("test", dir),
		config:          &RedactionManagerConfig{},
		stats:           &RedactionStats{},
	}
}

func oneRedaction() *RedactionResult {
	return &RedactionResult{
		RedactionMap: []RedactionMapping{{
			DataType:     "EMAIL",
			RedactedText: "[EMAIL-REDACTED]",
			Confidence:   95,
		}},
	}
}

// TestAddRedactionResult_NoDroppedAuditEntries is the regression test for document
// IDs taken from the clock. time.Now() resolves to a microsecond in practice, so
// files redacted in the same tick were assigned the same ID; CreateAuditLog rejects
// the duplicate and AddRedactionResult returned early, silently discarding that
// file's audit entry while leaving its redacted output on disk. The loss was
// intermittent — roughly half of a 200-file run — and named a different victim each
// time, which is exactly the failure mode a compliance artifact must not have.
//
// The bodies here do no I/O, so every call lands well inside one clock tick; with a
// clock-derived ID this fails on the first duplicate.
func TestAddRedactionResult_NoDroppedAuditEntries(t *testing.T) {
	const files = 500

	rm := newDocIDTestManager(t)
	for i := 0; i < files; i++ {
		in := filepath.Join("/in", fmt.Sprintf("f%d.txt", i))
		out := filepath.Join("/out", fmt.Sprintf("f%d.txt", i))
		rm.AddRedactionResult(in, out, oneRedaction())
	}

	if got := rm.auditLogManager.GetAuditLogCount(); got != files {
		t.Fatalf("audit log holds %d entries for %d redacted files — %d compliance records were dropped",
			got, files, files-got)
	}

	// Every input file must be accounted for by path, not just by count.
	for i := 0; i < files; i++ {
		in := filepath.Join("/in", fmt.Sprintf("f%d.txt", i))
		if _, ok := rm.auditLogManager.GetAuditLogByPath(in); !ok {
			t.Fatalf("no audit entry for %s, which was redacted", in)
		}
	}
}

// TestAddRedactionResult_ConcurrentNoDroppedEntries covers the real call shape: the
// worker pool calls AddRedactionResult from several goroutines
// (internal/parallel/worker_pool.go). Concurrency makes same-tick arrivals more
// likely, not less, so the ID source has to be safe under it. Run with -race.
func TestAddRedactionResult_ConcurrentNoDroppedEntries(t *testing.T) {
	const (
		workers     = 8
		perWorker   = 50
		wantEntries = workers * perWorker
	)

	rm := newDocIDTestManager(t)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				in := filepath.Join("/in", fmt.Sprintf("w%d_f%d.txt", w, i))
				out := filepath.Join("/out", fmt.Sprintf("w%d_f%d.txt", w, i))
				rm.AddRedactionResult(in, out, oneRedaction())
			}
		}(w)
	}
	wg.Wait()

	if got := rm.auditLogManager.GetAuditLogCount(); got != wantEntries {
		t.Fatalf("audit log holds %d entries for %d redacted files — %d compliance records were dropped",
			got, wantEntries, wantEntries-got)
	}
}

// TestAddRedactionResult_ReproducibleDocumentIDs locks the second half of the fix.
// Clock-derived IDs meant two audit logs of byte-identical input shared no document
// IDs at all, so they could not be diffed or key-matched — and because each
// redaction's own ID embeds the document ID ("doc_N_redaction_I"), every redaction
// ID moved too.
func TestAddRedactionResult_ReproducibleDocumentIDs(t *testing.T) {
	run := func() []string {
		rm := newDocIDTestManager(t)
		for i := 0; i < 20; i++ {
			in := filepath.Join("/in", fmt.Sprintf("f%d.txt", i))
			out := filepath.Join("/out", fmt.Sprintf("f%d.txt", i))
			rm.AddRedactionResult(in, out, oneRedaction())
		}

		ids := make([]string, 0, 20)
		for i := 0; i < 20; i++ {
			in := filepath.Join("/in", fmt.Sprintf("f%d.txt", i))
			log, ok := rm.auditLogManager.GetAuditLogByPath(in)
			if !ok {
				t.Fatalf("no audit entry for %s", in)
			}
			ids = append(ids, log.DocumentID)
		}
		return ids
	}

	first, second := run(), run()
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("document ID for file %d changed between two runs on identical input: %q then %q",
				i, first[i], second[i])
		}
	}

	// A file's redaction IDs derive from its document ID, so they must be stable too.
	rm := newDocIDTestManager(t)
	rm.AddRedactionResult("/in/a.txt", "/out/a.txt", oneRedaction())
	log, ok := rm.auditLogManager.GetAuditLogByPath("/in/a.txt")
	if !ok {
		t.Fatal("no audit entry for /in/a.txt")
	}
	if len(log.ContentRedactions) != 1 {
		t.Fatalf("got %d content redactions, want 1", len(log.ContentRedactions))
	}
	if want := "doc_1_redaction_0"; log.ContentRedactions[0].ID != want {
		t.Fatalf("redaction ID = %q, want %q", log.ContentRedactions[0].ID, want)
	}
}
