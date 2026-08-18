// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"os"
	"path/filepath"
	"testing"
)

// The scanner admits files by SNIFFING their bytes; redactor selection matched an
// eleven-extension allowlist. So a growing set of file types was scanned, reported findings,
// and could never produce a redacted copy — at exit 0.
//
// Measured on a file holding an AWS secret key, a database password, an SSN and an email:
//
//	.txt .json                                        3 findings, redacted copy written
//	.env .tfvars .tf .sql .py .sh .properties .toml
//	.pem Dockerfile Makefile                          3 findings, NO redacted copy, exit 0
//
// `.env` is the single likeliest file in a repository to hold a live credential. Same
// "reported but unredactable" shape as #306, and the general statement of it is #315.

const textualContent = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\npassword=hunter2\n"

// Any file whose BYTES are text must resolve to the text redactor, whatever it is named.
//
// Asserted over the names the allowlist missed, including two with NO extension at all —
// those failed even earlier, on an `ext == ""` guard that returned before any sniff.
func TestTextBytesResolveToTheTextRedactorWhateverTheExtension(t *testing.T) {
	rm := newTestManager(t)
	plain := &stubRedactor{exts: []string{".txt"}}
	if err := rm.RegisterRedactor(plain); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	for _, name := range []string{
		"secret.env", "secret.tfvars", "secret.tf", "secret.sql", "secret.py",
		"secret.sh", "secret.properties", "secret.toml", "secret.pem",
		"Dockerfile", "Makefile",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(textualContent), 0o600); err != nil {
				t.Fatal(err)
			}

			got, err := rm.GetRedactorForFile(p)
			if err != nil {
				t.Fatalf("no redactor for a text file named %q: %v\n"+
					"The scanner reads this file and reports its findings, so refusing to redact it "+
					"leaves the values in cleartext while the report says they were handled.", name, err)
			}
			if got != Redactor(plain) {
				t.Errorf("resolved to %q, want the text redactor", got.GetName())
			}
		})
	}
}

// Binary bytes with an unregistered extension must still be REFUSED.
//
// This is the guard that makes the fallback safe. Diverting a binary file to the text
// redactor would do byte-level string replacement on it and corrupt it, while reporting
// success — worse than the refusal it replaced. The refusal is disclosed by the caller
// through stats.UnredactedFiles.
func TestBinaryBytesWithUnknownExtensionAreStillRefused(t *testing.T) {
	rm := newTestManager(t)
	if err := rm.RegisterRedactor(&stubRedactor{exts: []string{".txt"}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cases := map[string][]byte{
		// A NUL early in the buffer is the classic binary tell.
		"blob.xyz": append([]byte{0x00, 0x01, 0x02}, []byte("some trailing text")...),
		// Byte soup across the whole range.
		"soup.dat": func() []byte {
			b := make([]byte, 512)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
	}

	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rm.GetRedactorForFile(p); err == nil {
				t.Error("a binary file was routed to the text redactor; byte-level replacement " +
					"would corrupt it while reporting success")
			}
		})
	}
}

// A registered redactor must keep its files. The fallback fires only when NOTHING is
// registered for the extension, so adding it must not divert formats that already have an
// owner — including a container file whose bytes happen to sniff as text, which the separate
// container-divert rule governs.
func TestRegisteredRedactorIsNotDivertedByTheFallback(t *testing.T) {
	rm := newTestManager(t)
	plain := &stubRedactor{exts: []string{".txt"}}
	jpeg := &stubRedactor{exts: []string{".jpg"}}
	if err := rm.RegisterRedactor(plain); err != nil {
		t.Fatal(err)
	}
	if err := rm.RegisterRedactor(jpeg); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "photo.jpg")
	// Deliberately TEXT bytes under a registered binary extension: the fallback must not
	// reach this file, because .jpg has an owner.
	if err := os.WriteFile(p, []byte(textualContent), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := rm.GetRedactorForFile(p)
	if err != nil {
		t.Fatalf("GetRedactorForFile: %v", err)
	}
	if got != Redactor(jpeg) {
		t.Error("a registered extension was diverted to the text redactor; the fallback must " +
			"only apply where nothing is registered")
	}
}

// An empty file must not be diverted.
//
// router.isTextFile deliberately calls a zero-byte file text, so it is not reported as
// unreadable. For redaction that reasoning does not carry: an empty file has no findings to
// remove, so there is nothing to route.
func TestEmptyFileIsNotDiverted(t *testing.T) {
	rm := newTestManager(t)
	if err := rm.RegisterRedactor(&stubRedactor{exts: []string{".txt"}}); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "empty.env")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rm.GetRedactorForFile(p); err == nil {
		t.Error("an empty file resolved to a redactor; it has no findings to remove")
	}
}

// The fallback needs the text redactor to be registered. With none, an unknown extension must
// report the original "no redactor registered" error rather than panic or resolve to nil.
func TestFallbackIsSkippedWhenNoTextRedactorIsRegistered(t *testing.T) {
	rm := newTestManager(t)
	if err := rm.RegisterRedactor(&stubRedactor{exts: []string{".jpg"}}); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(p, []byte(textualContent), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := rm.GetRedactorForFile(p)
	if err == nil {
		t.Errorf("resolved to %v with no text redactor registered", got)
	}
}

// looksLikeTextFile is the safety guard, so its contract is pinned directly — including the
// UTF-16 case, which a naive null-byte check would reject even though it is text.
func TestLooksLikeTextFile(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	utf16 := []byte{0xFF, 0xFE}
	for _, r := range "password=hunter2" {
		utf16 = append(utf16, byte(r), 0x00)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"ascii text", write("a.env", []byte(textualContent)), true},
		{"utf-16 text", write("b.env", utf16), true},
		{"leading NUL", write("c.env", append([]byte{0x00}, []byte("text after")...)), false},
		{"byte soup", write("d.env", func() []byte {
			b := make([]byte, 512)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()), false},
		{"empty", write("e.env", nil), false},
		{"missing", filepath.Join(dir, "nope.env"), false},
	}

	for _, tc := range cases {
		if got := looksLikeTextFile(tc.path); got != tc.want {
			t.Errorf("looksLikeTextFile(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
