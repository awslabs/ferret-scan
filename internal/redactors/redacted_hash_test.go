// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestRedactedFileHashIsSetAndVerifiable is the recall case for #401.
//
// SetRedactedFileHash existed and had NO callers, so redacted_file_hash was empty in every audit log
// ever written, for every redactor and every file type. The log attested to the input and to a list
// of replacements, but nothing tied it to the bytes that were produced — which is the one artifact
// anyone downstream consumes.
//
// The digest is recomputed here with an independent sha256 over the whole file rather than compared
// against HashFile's own output: comparing HashFile to HashFile would pass even if it hashed the
// wrong path, which is the mistake worth catching, since CreateAuditLog is handed two paths.
func TestRedactedFileHashIsSetAndVerifiable(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	redacted := filepath.Join(dir, "redacted.txt")

	originalBody := []byte("contact jane.smith@corp.example\n")
	// Deliberately a DIFFERENT length and content, so hashing the wrong path is visible.
	redactedBody := []byte("contact [REDACTED-EMAIL]\n")

	if err := os.WriteFile(original, originalBody, 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}
	if err := os.WriteFile(redacted, redactedBody, 0o600); err != nil {
		t.Fatalf("write redacted: %v", err)
	}

	mgr := NewRedactionAuditLogManager("test", dir)
	log, err := mgr.CreateAuditLog("doc_1", original, redacted)
	if err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}

	wantRedacted := independentSHA256(t, redactedBody)
	wantOriginal := independentSHA256(t, originalBody)

	if log.RedactedFileHash == "" {
		t.Fatal("redacted_file_hash is empty — the audit log cannot attest to the artifact that " +
			"was actually written")
	}
	if log.RedactedFileHash != wantRedacted {
		t.Errorf("redacted_file_hash = %s, want %s (an independent sha256 of the redacted bytes)",
			log.RedactedFileHash, wantRedacted)
	}
	if log.OriginalFileHash != wantOriginal {
		t.Errorf("original_file_hash = %s, want %s", log.OriginalFileHash, wantOriginal)
	}

	// The two must differ, or the same path was hashed twice. This is the assertion that a
	// copy-paste of the original-hash line would fail.
	if log.RedactedFileHash == log.OriginalFileHash {
		t.Error("the two hashes are identical — one path was hashed twice")
	}
}

// TestRedactedFileHashAbsentWhenThereIsNoArtifact pins the other half of #401: a field that is
// declared and always empty is worse than an absent one, because a consumer cannot tell "not
// computed" from "computed as the empty string".
//
// A redactor declining to write is real, not hypothetical — the Office redactor refuses a partial
// redaction rather than emitting a leaky file. A sha256 is never legitimately empty, so `omitempty`
// makes absence mean exactly one thing.
func TestRedactedFileHashAbsentWhenThereIsNoArtifact(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	if err := os.WriteFile(original, []byte("body\n"), 0o600); err != nil {
		t.Fatalf("write original: %v", err)
	}

	mgr := NewRedactionAuditLogManager("test", dir)
	log, err := mgr.CreateAuditLog("doc_1", original, filepath.Join(dir, "never-written.txt"))
	if err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}

	if log.RedactedFileHash != "" {
		t.Errorf("redacted_file_hash = %q for a file that was never written", log.RedactedFileHash)
	}

	// The contract is about the SERIALIZED form, which is what a compliance reader sees, so assert on
	// the JSON rather than on the struct field.
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := round["redacted_file_hash"]; present {
		t.Errorf("redacted_file_hash is present in the JSON as %q; it must be OMITTED when there is "+
			"no artifact, so a reader can tell that apart from a computed-empty digest",
			round["redacted_file_hash"])
	}
	// The original's hash IS computable here, so it must still be present — this is what stops the
	// omitempty change from quietly dropping both.
	if _, present := round["original_file_hash"]; !present {
		t.Error("original_file_hash was omitted even though the original is readable")
	}
}

// independentSHA256 hashes in one shot, deliberately not via HashFile.
func independentSHA256(t *testing.T, body []byte) string {
	t.Helper()
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
