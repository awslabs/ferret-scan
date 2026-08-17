// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// TestWithinDirRejectsEscapes covers the containment predicate directly, including
// the case a naive prefix comparison gets wrong.
func TestWithinDirRejectsEscapes(t *testing.T) {
	dir := filepath.Clean("/tmp/ferret-embedded-1")

	inside := []string{
		dir,
		filepath.Join(dir, "embedded.docx"),
		filepath.Join(dir, "nested", "deeper.jpg"),
		// A traversal that resolves back inside is inside.
		filepath.Join(dir, "a", "..", "embedded.bin"),
	}
	for _, p := range inside {
		if !withinDir(dir, p) {
			t.Errorf("withinDir(%q, %q) = false, want true", dir, p)
		}
	}

	outside := []string{
		filepath.Clean("/tmp/ferret-embedded-1-evil/x.docx"), // sibling sharing the prefix
		filepath.Clean("/tmp/other/x.docx"),
		filepath.Join(dir, "..", "escape.docx"),
		filepath.Join(dir, "..", "..", "etc", "passwd"),
		filepath.Clean("/etc/passwd"),
	}
	for _, p := range outside {
		if withinDir(dir, p) {
			t.Errorf("withinDir(%q, %q) = true, want false", dir, p)
		}
	}
}

// TestHostilePartNamesStayInTheTempDir is the end-to-end statement of the property
// CodeQL's go/zipslip could not see: a producer-controlled archive entry name cannot
// steer a write out of the per-part temp directory.
//
// It asserts through RedactEmbedded rather than through SafeExt alone, so it covers
// the composition — allowlisted extension, hardcoded basename, containment check —
// rather than one link of it. Any escape would write a document's UNREDACTED bytes to
// an attacker-chosen path, which is strictly worse than the leak the redactor exists
// to prevent.
func TestHostilePartNamesStayInTheTempDir(t *testing.T) {
	rm := newTestManager(t)

	// A canary in every directory a traversal from os.TempDir() could plausibly
	// reach. Its content must be unchanged afterwards.
	tmp := os.TempDir()
	canaries := map[string][]byte{}
	for _, rel := range []string{"ferret-canary.txt", filepath.Join("..", "ferret-canary.txt")} {
		p := filepath.Clean(filepath.Join(tmp, rel))
		want := []byte("canary must not be overwritten\n")
		if err := os.WriteFile(p, want, 0o600); err != nil {
			continue // not writable here; skip this location rather than fail
		}
		canaries[p] = want
		defer func(target string) { _ = os.Remove(target) }(p)
	}

	hostile := []string{
		"../../../../tmp/ferret-canary.txt",
		"../ferret-canary.txt",
		"word/media/../../../../tmp/ferret-canary.txt",
		"/tmp/ferret-canary.txt",
		"C:\\Windows\\System32\\ferret-canary.txt",
		"..\\..\\ferret-canary.txt",
		"word/media/x.txt\x00../../ferret-canary.txt",
		strings.Repeat("../", 256) + "tmp/ferret-canary.txt",
		"....//....//ferret-canary.txt",
	}

	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			// The call is expected to succeed or fail; either is fine. What must not
			// happen is a write outside the temp directory.
			_, _ = rm.RedactEmbedded(EmbeddedRedactionRequest{
				ParentPath: filepath.Join(t.TempDir(), "outer.docx"),
				PartName:   name,
				Content:    []byte("ssn 796-58-4123\n"),
				Strategy:   RedactionFormatPreserving,
			})

			for p, want := range canaries {
				got, err := os.ReadFile(p) // #nosec G304 -- test-owned path
				if err != nil {
					t.Errorf("canary %s disappeared after part %q: %v", p, name, err)
					continue
				}
				if string(got) != string(want) {
					t.Errorf("canary %s was MODIFIED by part %q: a hostile archive entry "+
						"escaped its temp directory", p, name)
				}
			}
		})
	}
}

// TestSafeExtStillGuardsTheExtension pins that the containment check did not become
// the only defence. The allowlist is the primary control — it makes an escaping path
// unrepresentable — and the check exists for a future refactor, not instead of it.
func TestSafeExtStillGuardsTheExtension(t *testing.T) {
	for _, name := range []string{
		"../../../../etc/passwd",
		"word/media/../../../evil.jpg",
		"/etc/shadow.jpg",
		"x.jpg\x00.exe",
	} {
		ext, ok := embedded.SafeExt(name)
		if !ok {
			continue
		}
		if strings.ContainsAny(ext, `/\`+"\x00") || strings.Contains(ext, "..") {
			t.Errorf("SafeExt(%q) = %q, which can carry a path component", name, ext)
		}
	}
}
