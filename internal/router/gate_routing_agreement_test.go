// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGateAndRoutingAgree is the invariant whose violation produced this whole bug
// class, asserted directly rather than through any one extension.
//
// CanProcessFile is a PROMISE: the CLI, pkg/scan and the pre-commit hook all use it
// to decide whether a file is worth handing to the scanner. When it answers true and
// the routing then finds no capable preprocessor, the file is reported as scanned-and
// -clean while its contents were never read — "No matches found", exit 0, over a
// file holding credentials.
//
// It has broken twice in opposite directions. For .heic the gate claimed an
// extension no preprocessor handled (v2 gap 5.3, fixed by deriving the metadata
// branch of the gate from FileExtensionValidator). For .swift, .kt, .tf and
// .properties the gate sniffed the bytes, said "Text file", and the text
// preprocessor's extension allowlist then declined the file. Both are the same
// defect: two components answering "can this be processed" with different rules.
//
// So this test does not enumerate the extensions that happen to be broken today. It
// asserts the property.
func TestGateAndRoutingAgree(t *testing.T) {
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))

	textBody := []byte("let ssn = \"796-58-4123\"\nlet key = \"AKIAIOSFODNN7EXAMPLE\"\n")
	binaryBody := []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f}

	cases := []struct {
		name string
		body []byte
	}{
		// Listed text, unlisted text, and the mobile sources that surfaced this.
		{"a.txt", textBody},
		{"a.swift", textBody},
		{"a.kt", textBody},
		{"build.gradle.kts", textBody},
		{"vars.tf", textBody},
		{"app.properties", textBody},
		{"a.dart", textBody},
		{"Component.tsx", textBody},
		// No extension, and a name with no dot at all.
		{"noext", textBody},
		{"Makefile", textBody},
		// Extensions nothing claims by name.
		{"a.frobnicate", textBody},
		{"a.xyz", textBody},
		// Binary under assorted names, including a container name and an
		// extension the metadata validator does not recognize.
		{"b.xyz", binaryBody},
		{"b.docx", binaryBody},
		{"b.heic", binaryBody},
		{"b", binaryBody},
		// Text bytes wearing a container extension: the mislabelled-export case.
		{"mislabelled.docx", textBody},
	}

	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}

			admitted, reason := fr.CanProcessFile(path, true)
			if !admitted {
				// Declining is always allowed — the gate is permitted to be
				// conservative. It just has to give a reason.
				if strings.TrimSpace(reason) == "" {
					t.Errorf("gate declined %q with an empty reason", tc.name)
				}
				return
			}

			// Admitted: the routing must be able to act on that promise.
			_, err := fr.ProcessFile(path, nil)
			if err == nil {
				return
			}
			if strings.Contains(err.Error(), "no preprocessor can handle file") {
				t.Errorf("gate admitted %q as %q, but routing has no preprocessor for it.\n"+
					"A caller trusting the gate reports this file as scanned while its "+
					"contents were never read.\nerror: %v", tc.name, reason, err)
			}
			// Other errors are real processing failures (a truncated container, an
			// unreadable stream). Those are disclosed as incomplete coverage by the
			// callers and are not this invariant's concern.
		})
	}
}

// TestUnlistedTextExtensionScansLikeItsBytes is the end-to-end statement of the
// fix: routing a .swift file must produce the same extracted text as the identical
// bytes named .txt. Equality is the point — "some text came back" would pass while
// silently truncating.
func TestUnlistedTextExtensionScansLikeItsBytes(t *testing.T) {
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))

	body := []byte("let ssn = \"796-58-4123\"\nlet key = \"AKIAIOSFODNN7EXAMPLE\"\n")
	dir := t.TempDir()

	ref := filepath.Join(dir, "ref.txt")
	if err := os.WriteFile(ref, body, 0o600); err != nil {
		t.Fatal(err)
	}
	refContent, err := fr.ProcessFile(ref, nil)
	if err != nil {
		t.Fatalf("reference .txt failed to process: %v", err)
	}
	if !strings.Contains(refContent.Text, "796-58-4123") {
		t.Fatalf("reference .txt did not yield its own content; fixture is broken: %q", refContent.Text)
	}

	for _, name := range []string{"Creds.swift", "Creds.kt", "build.gradle.kts", "vars.tf", "app.properties"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, body, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := fr.ProcessFile(p, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got.Text != refContent.Text {
				t.Errorf("%s extracted text differs from the identical bytes named .txt\n got: %q\nwant: %q",
					name, got.Text, refContent.Text)
			}
		})
	}
}
