// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rtf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

func newRedactor(t *testing.T) (*RTFRedactor, string) {
	t.Helper()
	dir := t.TempDir()
	om, err := redactors.NewOutputStructureManager(dir, nil)
	if err != nil {
		t.Fatalf("NewOutputStructureManager: %v", err)
	}
	return NewRTFRedactor(om, nil), dir
}

const ssn = "452-11-9384"

// verbatimRTF holds the value literally, so a byte substitution can remove it.
const verbatimRTF = "{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n" +
	"\\f0\\fs24 Employee SSN: 452-11-9384\\par\n}\n"

// splitRTF holds the value across a formatting run, the way macOS textutil writes a bolded
// fragment. The extractor reassembles it, so it is REPORTED, but it occurs nowhere literally.
const splitRTF = "{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n" +
	"\\f0\\fs24 Employee SSN: 452-11-\\f1\\b 9384\\b0\\par\n}\n"

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTheRedactedFileIsStillAnRTFDocument is the defect this package exists for.
//
// Routing .rtf to the plaintext redactor writes the EXTRACTED PROSE over the file, because the
// worker pool prefers RedactContent and RTF extraction is lossy by design. Measured before this
// package, the "redacted" output of a 115-byte RTF was two lines of text with no {\rtf header,
// no font table and no control words, and `textutil -convert txt` read 0 bytes back out of it.
func TestTheRedactedFileIsStillAnRTFDocument(t *testing.T) {
	r, dir := newRedactor(t)
	in := write(t, dir, "doc.rtf", verbatimRTF)
	out := filepath.Join(dir, "out", "doc.rtf")

	res, err := r.RedactDocument(in, out, []detector.Match{
		{Text: ssn, Type: "SSN", Confidence: 100, Validator: "ssn"},
	}, redactors.RedactionSimple)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	written := res.RedactedFilePath
	if written == "" {
		written = out
	}
	got, err := os.ReadFile(written) // #nosec G304 -- test-local path
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(string(got), `{\rtf`) {
		t.Errorf("output does not begin with the RTF signature, so it is not a document any reader "+
			"will open. First 60 bytes: %q", string(got[:min(60, len(got))]))
	}
	for _, want := range []string{`{\fonttbl`, `\f0\fs24`, `\par`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("RTF markup %q was lost — the extracted prose was written over the file", want)
		}
	}
	// And the value is actually gone. Both halves matter: markup preserved AND value removed.
	if strings.Contains(string(got), ssn) {
		t.Error("the reported value survives in the redacted file")
	}
}

// TestAValueSplitAcrossRunsIsRedacted is the RTF-specific hazard, now closed.
//
// The extractor reassembles `452-11-\f1\b 9384`, so the value is reported — but it occurs nowhere
// literally, so a byte substitution finds nothing. This test used to assert that the file was REFUSED
// for exactly that reason, which was the honest end state while the value could not be removed.
//
// It can now be removed: the extractor records a span map from its output back to the source bytes, so
// the redactor rewrites the bytes that PRODUCED the value. The assertions here are the three things
// that have to hold together, because getting any one of them alone is easy and useless:
//
//	the value is gone            — including the trailing fragment, not just the joined form
//	the document is still RTF    — header, font table and control words intact
//	the formatting run survives  — \f1\b is between the two halves and must not be eaten
func TestAValueSplitAcrossRunsIsRedacted(t *testing.T) {
	r, dir := newRedactor(t)
	in := write(t, dir, "split.rtf", splitRTF)
	out := filepath.Join(dir, "out", "split.rtf")

	res, err := r.RedactDocument(in, out, []detector.Match{
		{Text: ssn, Type: "SSN", Confidence: 100, Validator: "ssn"},
	}, redactors.RedactionSimple)
	if err != nil {
		t.Fatalf("a split value should now be redactable, not refused: %v", err)
	}
	written := res.RedactedFilePath
	if written == "" {
		written = out
	}
	got, err := os.ReadFile(written) // #nosec G304 -- test-local path
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)

	// The value must be gone in every spelling. "9384" matters on its own: the naive fix replaces the
	// first mapped range and forgets the rest, leaving the tail digits in the file.
	for _, leak := range []string{ssn, "452-11-", "9384"} {
		if strings.Contains(text, leak) {
			t.Errorf("%q survives in the redacted document:\n%s", leak, text)
		}
	}
	// Still a document.
	if !strings.HasPrefix(text, `{\rtf`) {
		t.Errorf("output no longer starts with the RTF signature:\n%s", text)
	}
	for _, want := range []string{`{\fonttbl`, `\par`} {
		if !strings.Contains(text, want) {
			t.Errorf("RTF markup %q was lost:\n%s", want, text)
		}
	}
	// And the formatting run BETWEEN the two halves of the value must survive. Collapsing the whole
	// span would delete it and change how the rest of the paragraph renders.
	if !strings.Contains(text, `\f1\b`) {
		t.Errorf("the formatting run between the split halves was eaten; only the value's bytes should "+
			"be rewritten:\n%s", text)
	}
}

// TestResidueCheckStillRefusesAValueItCannotRemove keeps the safety net pinned.
//
// The span map closes the common case, so the end-to-end refusal path is no longer easy to reach — and
// an unreachable guard is one nobody notices has broken. This exercises residueTypes directly: if a
// value is still present in the written bytes, by any spelling, the caller must refuse rather than
// leave a file an operator will read as redacted.
func TestResidueCheckStillRefusesAValueItCannotRemove(t *testing.T) {
	matches := []detector.Match{{Text: ssn, Type: "SSN"}}

	// Present verbatim.
	if got := residueTypes([]byte(verbatimRTF), matches); len(got) != 1 || got[0] != "SSN" {
		t.Errorf("residueTypes on bytes still holding the value = %v, want [SSN]", got)
	}
	// Present only in the DECODED rendering, split across a run. This is the spelling a raw-bytes-only
	// check misses, and it is why the check decodes.
	if got := residueTypes([]byte(splitRTF), matches); len(got) != 1 || got[0] != "SSN" {
		t.Errorf("residueTypes on a SPLIT value = %v, want [SSN] — a raw-bytes-only check cannot see "+
			"this, which is the leak the decoding exists to catch", got)
	}
	// Genuinely absent.
	clean := "{\\rtf1\\ansi\\deff0\\f0 Employee SSN: [SSN-REDACTED]\\par\n}\n"
	if got := residueTypes([]byte(clean), matches); len(got) != 0 {
		t.Errorf("residueTypes on redacted bytes = %v, want none — this would refuse every good file", got)
	}
}

// TestRedactContentIsNotOffered pins the mechanism, not just its symptom.
//
// The worker pool prefers RedactContent (the extracted text) over RedactDocument (the file)
// whenever a redactor offers it. This type must therefore NOT satisfy a RedactContent-bearing
// interface, or the prose-over-file defect returns however correct RedactDocument is.
func TestRedactContentIsNotOffered(t *testing.T) {
	r, _ := newRedactor(t)

	// The signature is copied from plaintext.PlainTextRedactor.RedactContent, which is what the
	// worker pool actually type-asserts for. Writing a DIFFERENT signature here is how this test
	// nearly shipped vacuous: a mutant that re-added RedactContent with the wrong argument list
	// satisfied the local interface and "failed" the test, while the real regression would have
	// slipped past. Pinned against the real one below so the two cannot drift.
	type contentRedactor interface {
		RedactContent(*preprocessors.ProcessedContent, string, []detector.Match,
			redactors.RedactionStrategy) (*redactors.RedactionResult, error)
	}
	if _, ok := any(r).(contentRedactor); ok {
		t.Error("RTFRedactor exposes RedactContent, so the worker pool will write the EXTRACTED PROSE " +
			"over the .rtf and destroy the document — that is the whole reason this package exists")
	}

	// NON-VACUITY: the interface above must be satisfiable by the type that DOES implement it,
	// or a typo in the signature would make the assertion above pass for any input.
	if _, ok := any(r.inner).(contentRedactor); !ok {
		t.Fatal("plaintext.PlainTextRedactor does not satisfy the local contentRedactor interface, so " +
			"its signature has drifted and the assertion above cannot detect the regression it exists for")
	}
}

// TestOnlyRTFIsClaimed. .rtfd is a BUNDLE (a directory holding TXT.rtf plus media), not a file, so
// claiming it would promise a redaction that cannot happen here.
func TestOnlyRTFIsClaimed(t *testing.T) {
	r, _ := newRedactor(t)
	got := r.GetSupportedTypes()
	if len(got) != 1 || got[0] != ".rtf" {
		t.Errorf("GetSupportedTypes() = %v, want exactly [.rtf]", got)
	}
	if n := len(r.GetSupportedStrategies()); n != 3 {
		t.Errorf("got %d strategies, want all 3 — the substitution is strategy-agnostic", n)
	}
}

// TestLooksLikeRTFAcceptsOnlyRTF pins the signature gate's helper directly.
//
// The gate itself cannot fire on any strategy shipped today — all three emit alphanumerics and
// brackets into a located span, which cannot remove the header — so a mutation deleting the gate
// survives every other test here. That makes it defence-in-depth for a future strategy, and the
// least this can do is guarantee the predicate is right.
func TestLooksLikeRTFAcceptsOnlyRTF(t *testing.T) {
	accept := [][]byte{
		[]byte(`{\rtf1\ansi\deff0 hi}`),
		append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{\rtf1}`)...), // BOM-prefixed, which producers emit
	}
	for _, in := range accept {
		if !looksLikeRTF(in) {
			t.Errorf("valid RTF rejected: %q", string(in))
		}
	}
	reject := [][]byte{
		nil,
		{},
		[]byte("Employee SSN: [SSN-REDACTED]\n"), // the prose-over-file regression, exactly
		[]byte(`{\rt`),
		[]byte("%PDF-1.4"),
		[]byte(` {\rtf1}`), // leading space: the signature must be at offset 0
	}
	for _, in := range reject {
		if looksLikeRTF(in) {
			t.Errorf("non-RTF accepted: %q", string(in))
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
