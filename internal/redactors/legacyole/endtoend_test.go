// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/richardlehane/mscfb"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// End-to-end redaction: a REAL OLE compound file goes in, and the assertions are
// on the bytes of the file that comes out.
//
// The unit tests next door cover overwriteAll, sameLengthReplacement and the
// content-range gate in isolation. None of them proves the sink: whether the value
// is actually gone from the OUTPUT FILE, and whether that file is still a
// container any reader will open. Both matter more than the pieces, because the
// two failure modes are opposite and each is worse than no redaction at all —
// reporting success while leaving cleartext, or producing a corrupt document that
// looks redacted.
//
// Every assertion here reads the output back THROUGH mscfb, stream by stream. A
// naive grep of the whole file would be weaker in both directions: it can match
// structural bytes that are not document content, and it cannot tell whether the
// stream a reader would actually see still holds the secret.

const (
	testSSN    = "449-87-4100"
	testCard   = "4532-0151-1283-0366"
	testAuthor = "Jane Analyst"
)

// docFixture builds a .doc containing an SSN and a card in the body stream, and an
// author name in the property stream.
func docFixture(t *testing.T) []byte {
	t.Helper()
	return buildCFB(t, []cfbStream{
		{name: "WordDocument", data: []byte(
			"Quarterly summary follows.\r" +
				"Employee SSN: " + testSSN + " on file.\r" +
				"Card " + testCard + " expires soon.\r")},
		{name: "\x05SummaryInformation", data: buildSummaryInformation(map[uint32]string{
			propAuthor:     testAuthor,
			propLastAuthor: "Ops Reviewer",
			propAppName:    "Microsoft Word 97",
		})},
	})
}

func writeFixture(t *testing.T, data []byte, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

// streamContents reads every stream of a compound file into a map, the way any
// reader (Word, textutil, this tool's own extractor) would see it.
func streamContents(t *testing.T, path string) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	doc, err := mscfb.New(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("output is no longer a readable compound file: %v — redaction that "+
			"corrupts the container trades a leak for an unopenable document", err)
	}
	out := map[string][]byte{}
	for entry, e := doc.Next(); e == nil; entry, e = doc.Next() {
		b, rerr := io.ReadAll(entry)
		if rerr != nil {
			t.Errorf("stream %q unreadable after redaction: %v", entry.Name, rerr)
			continue
		}
		out[entry.Name] = b
	}
	return out
}

func matchesFor(vals map[string]string) []detector.Match {
	out := make([]detector.Match, 0, len(vals))
	for text, typ := range vals {
		out = append(out, detector.Match{Text: text, Type: typ, Confidence: 95})
	}
	return out
}

// The headline sink assertion. Values in the body AND in the property stream must
// be gone from the streams a reader sees, and the container must still parse.
func TestRedaction_RemovesValuesFromEveryStream(t *testing.T) {
	src := writeFixture(t, docFixture(t), "report.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{
		testSSN:    "SSN",
		testCard:   "CREDIT_CARD",
		testAuthor: "AUTHOR_INFO",
	}), redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if !res.Success {
		t.Fatal("RedactDocument reported failure")
	}

	streams := streamContents(t, out)
	if len(streams) == 0 {
		t.Fatal("no streams in the output; the assertions below would be vacuous")
	}

	for name, content := range streams {
		for _, secret := range []string{testSSN, testCard, testAuthor} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("stream %q still contains %q in cleartext — this file was reported "+
					"as redacted", name, secret)
			}
			// The wide encoding is the same leak wearing a different hat: legacy
			// Word stores much of its text as UTF-16LE, so a value can survive as
			// interleaved zero bytes while an ASCII check reads clean.
			if wide := toUTF16LE(secret); wide != nil && bytes.Contains(content, wide) {
				t.Errorf("stream %q still contains %q as UTF-16LE — an ASCII-only "+
					"overwrite would report success here", name, secret)
			}
		}
	}

	// The property stream must have been reached specifically. If it were skipped,
	// the loop above would pass simply because the author name is not in the body.
	props, ok := streams["SummaryInformation"]
	if !ok {
		t.Fatal("no SummaryInformation stream in the output — the metadata half of this " +
			"test asserted nothing")
	}
	if !bytes.Contains(props, []byte("Microsoft Word 97")) {
		t.Error("the property stream lost an UNREPORTED value; redaction must overwrite " +
			"only what was reported, not damage neighbouring properties")
	}
}

// A same-length overwrite is the entire reason the container survives. If any
// stream changed size, every sector offset, FAT chain and length prefix behind it
// would be wrong — so this pins size equality stream by stream, not just for the
// file as a whole.
func TestRedaction_PreservesContainerStructure(t *testing.T) {
	fixture := docFixture(t)
	src := writeFixture(t, fixture, "report.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	if _, err := r.RedactDocument(src, out, matchesFor(map[string]string{
		testSSN:    "SSN",
		testAuthor: "AUTHOR_INFO",
	}), redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	redacted, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(redacted) != len(fixture) {
		t.Fatalf("output is %d bytes, input was %d — a size change means every offset "+
			"after the edit is wrong", len(redacted), len(fixture))
	}

	before := streamContents(t, src)
	after := streamContents(t, out)
	if len(before) != len(after) {
		t.Fatalf("stream count changed from %d to %d", len(before), len(after))
	}
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			t.Errorf("stream %q disappeared from the output", name)
			continue
		}
		if len(a) != len(b) {
			t.Errorf("stream %q changed size from %d to %d bytes; the same-length "+
				"invariant is what keeps the container valid", name, len(b), len(a))
		}
	}

	// The header, FAT and directory sectors must be untouched: only stream content
	// is eligible for overwriting.
	const headerBytes = 512
	if !bytes.Equal(fixture[:headerBytes], redacted[:headerBytes]) {
		t.Error("the 512-byte header was modified; a pattern coinciding with header " +
			"bytes must never be overwritten")
	}
}

// Redaction must not silently do nothing. A run that locates no occurrence of any
// match is indistinguishable, from the caller's side, from a successful one — and
// it ships a cleartext copy under a name that says "redacted".
func TestRedaction_ReportsWhatItActuallyChanged(t *testing.T) {
	src := writeFixture(t, docFixture(t), "report.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{
		testSSN:    "SSN",
		testAuthor: "AUTHOR_INFO",
	}), redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res.RedactionMap) != 2 {
		t.Errorf("RedactionMap has %d entries, want 2 (one per located match); a match "+
			"the redactor could not find must not be reported as redacted", len(res.RedactionMap))
	}

	// A value that is NOT in the document must not appear in the map.
	out2 := filepath.Join(t.TempDir(), "redacted2.doc")
	res2, err := r.RedactDocument(src, out2, matchesFor(map[string]string{
		"555-66-7777": "SSN", // absent from the fixture
	}), redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res2.RedactionMap) != 0 {
		t.Errorf("a value absent from the document produced %d mapping(s); claiming a "+
			"redaction that did not happen is how a leak gets reported as handled",
			len(res2.RedactionMap))
	}
}

// A value stored only as UTF-16LE is the realistic case for legacy Word body text,
// and it is invisible to a single-byte pass. If it survived, the tool would report
// the finding and ship the cleartext.
func TestRedaction_ReachesWideEncodedText(t *testing.T) {
	// Padded past the 4096-byte mini cutoff so the wide text lives in regular
	// sectors, which is where a real document's body text sits.
	body := make([]byte, 4608)
	copy(body, toUTF16LE("Employee SSN: "+testSSN+" on file."))
	src := writeFixture(t, buildCFB(t, []cfbStream{
		{name: "WordDocument", data: body},
	}), "wide.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{testSSN: "SSN"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res.RedactionMap) == 0 {
		t.Fatal("a UTF-16LE-encoded SSN was not located at all; the redactor searched " +
			"only for the ASCII form and the value stays in cleartext")
	}

	for name, content := range streamContents(t, out) {
		if wide := toUTF16LE(testSSN); bytes.Contains(content, wide) {
			t.Errorf("stream %q still contains the UTF-16LE SSN", name)
		}
	}
}

// Repeated occurrences must all go. Leaving the second copy of a value behind is a
// full leak of that value, and it is the classic replace-first-only bug.
func TestRedaction_RemovesEveryOccurrence(t *testing.T) {
	src := writeFixture(t, buildCFB(t, []cfbStream{
		{name: "WordDocument", data: []byte(
			"SSN " + testSSN + " appears here,\r" +
				"and again as " + testSSN + ",\r" +
				"and once more: " + testSSN + ".\r")},
	}), "repeat.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{testSSN: "SSN"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if n, _ := res.RedactionMap[0].Metadata["occurrences"].(int); n != 3 {
		t.Errorf("reported %d occurrences, want 3", n)
	}
	for name, content := range streamContents(t, out) {
		if c := bytes.Count(content, []byte(testSSN)); c != 0 {
			t.Errorf("stream %q still holds %d copies of the SSN", name, c)
		}
	}
}

// Both advertised strategies must actually redact. A strategy that is accepted but
// leaves the value in place is worse than one that is refused.
func TestRedaction_EveryAdvertisedStrategyRedacts(t *testing.T) {
	r := NewLegacyOLERedactor(nil, nil)
	strategies := r.GetSupportedStrategies()
	if len(strategies) == 0 {
		t.Fatal("no strategies advertised; this test would assert nothing")
	}

	for _, st := range strategies {
		t.Run(st.String(), func(t *testing.T) {
			src := writeFixture(t, docFixture(t), "report.doc")
			out := filepath.Join(t.TempDir(), "redacted.doc")

			if _, err := r.RedactDocument(src, out, matchesFor(map[string]string{
				testSSN:    "SSN",
				testAuthor: "AUTHOR_INFO",
			}), st); err != nil {
				t.Fatalf("RedactDocument(%s): %v", st, err)
			}
			for name, content := range streamContents(t, out) {
				for _, secret := range []string{testSSN, testAuthor} {
					if bytes.Contains(content, []byte(secret)) {
						t.Errorf("strategy %s left %q in stream %q", st, secret, name)
					}
				}
			}
		})
	}
}

// Redacting the same input twice must produce identical bytes. Nondeterministic
// redaction output has shipped in this repo before, and it makes the result depend
// on which run the user happened to get.
func TestRedaction_IsDeterministic(t *testing.T) {
	src := writeFixture(t, docFixture(t), "report.doc")
	dir := t.TempDir()
	r := NewLegacyOLERedactor(nil, nil)

	hashes := map[string]int{}
	const runs = 10
	for i := 0; i < runs; i++ {
		out := filepath.Join(dir, "redacted.doc")
		if _, err := r.RedactDocument(src, out, matchesFor(map[string]string{
			testSSN:    "SSN",
			testCard:   "CREDIT_CARD",
			testAuthor: "AUTHOR_INFO",
		}), redactors.RedactionFormatPreserving); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		hashes[hex.EncodeToString(sum[:])]++
		_ = os.Remove(out)
	}
	if len(hashes) != 1 {
		t.Fatalf("redacting one unchanged input %d times produced %d distinct outputs, "+
			"want 1: %v", runs, len(hashes), hashes)
	}
}

// A non-ASCII value cannot be encoded as UTF-16LE by toUTF16LE (it returns nil),
// so only the ASCII pass can reach it. That is fine for a value stored as
// single-byte text, but the redactor must not report success if it found nothing.
func TestRedaction_NonASCIIValue(t *testing.T) {
	const name = "José Güttierez-Ñuñez"
	src := writeFixture(t, buildCFB(t, []cfbStream{
		{name: "WordDocument", data: []byte("Author of record: " + name + " signed off.\r")},
		{name: "\x05SummaryInformation", data: buildSummaryInformation(map[uint32]string{
			propAuthor: name,
		})},
	}), "accents.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{name: "PERSON_NAME"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	streams := streamContents(t, out)
	stillPresent := false
	for _, content := range streams {
		if bytes.Contains(content, []byte(name)) {
			stillPresent = true
		}
	}

	// The contract: either the value is gone, or the redactor did not claim to have
	// removed it. Reporting a mapping while the value survives is the leak.
	if stillPresent && len(res.RedactionMap) > 0 {
		t.Error("a non-ASCII value survived redaction while being REPORTED as redacted; " +
			"a mapping the output does not honour is how cleartext gets shipped as handled")
	}
	if stillPresent {
		t.Errorf("the non-ASCII name %q survived in the output", name)
	}
}

// Refusing a file must leave no output behind. A caller that finds a file at the
// output path will treat it as a redacted copy, so writing one and then failing is
// worse than failing cleanly.
func TestRedaction_RefusalLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]byte{
		"plain.doc":     []byte("this is not a compound file, just text, with SSN " + testSSN),
		"zip.doc":       {0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0},
		"empty.doc":     {},
		"truncated.doc": {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1},
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			src := filepath.Join(dir, name)
			if err := os.WriteFile(src, content, 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out-"+name)

			r := NewLegacyOLERedactor(nil, nil)
			res, err := r.RedactDocument(src, out, matchesFor(map[string]string{testSSN: "SSN"}),
				redactors.RedactionFormatPreserving)
			if err == nil {
				t.Errorf("expected an error for %s; refusing is the only safe answer for "+
					"input that is not an OLE container (got result %+v)", name, res)
			}
			if _, statErr := os.Stat(out); statErr == nil {
				t.Errorf("%s: an output file exists despite the refusal; a caller would "+
					"treat it as a redacted copy", name)
			}
		})
	}
}

// A value that lives in the mini stream (any stream under 4096 bytes — which is
// where every real document's property stream sits) must be reachable. If
// contentRanges or the overwrite pass missed the mini stream, author and company
// names would be reported and never redacted.
func TestRedaction_ReachesMiniStreamContent(t *testing.T) {
	props := buildSummaryInformation(map[uint32]string{propAuthor: testAuthor})
	if len(props) >= cfbMiniCutoff {
		t.Fatalf("the property stream is %d bytes, at or over the %d-byte cutoff, so it "+
			"would NOT be in the mini stream and this test would assert nothing",
			len(props), cfbMiniCutoff)
	}

	src := writeFixture(t, buildCFB(t, []cfbStream{
		{name: "\x05SummaryInformation", data: props},
	}), "propsonly.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{testAuthor: "AUTHOR_INFO"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res.RedactionMap) == 0 {
		t.Fatal("the author name in the mini stream was not located; every real " +
			"document's properties live there, so this would be a blanket metadata leak")
	}
	for name, content := range streamContents(t, out) {
		if bytes.Contains(content, []byte(testAuthor)) {
			t.Errorf("stream %q still contains the author name", name)
		}
	}
}

// The replacement written into the file must be a mask, not the original value.
// sameLengthReplacement falls back to '*' repetition when a length-preserving
// replacement would return the input unchanged, and that fallback is what keeps a
// degenerate case from writing the secret straight back out.
func TestRedaction_WritesAMaskNotTheOriginal(t *testing.T) {
	// A single-character local part is the shape that once round-tripped unchanged
	// through format-preserving email redaction.
	const email = "a@b.co"
	src := writeFixture(t, buildCFB(t, []cfbStream{
		{name: "WordDocument", data: []byte("Contact address on file: " + email + " for records.\r")},
	}), "mail.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{email: "EMAIL"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res.RedactionMap) == 0 {
		t.Fatal("the address was not located")
	}
	if got := res.RedactionMap[0].RedactedText; got == email {
		t.Errorf("the replacement equals the original (%q); the redactor would write the "+
			"value back into the output and report it as redacted", got)
	}
	for name, content := range streamContents(t, out) {
		if bytes.Contains(content, []byte(email)) {
			t.Errorf("stream %q still contains %q", name, email)
		}
	}
}

// Guard on the redactor's declared surface: every type it claims must round-trip
// through an actual redaction. A type in the list that no code path handles reads
// as support and provides none.
func TestRedaction_EveryAdvertisedTypeIsHandled(t *testing.T) {
	r := NewLegacyOLERedactor(nil, nil)
	for _, tp := range r.GetSupportedTypes() {
		ext := tp
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		t.Run(ext, func(t *testing.T) {
			src := writeFixture(t, docFixture(t), "fixture"+ext)
			out := filepath.Join(t.TempDir(), "redacted"+ext)
			if _, err := r.RedactDocument(src, out, matchesFor(map[string]string{testSSN: "SSN"}),
				redactors.RedactionFormatPreserving); err != nil {
				t.Fatalf("advertised type %s failed to redact: %v", tp, err)
			}
			for name, content := range streamContents(t, out) {
				if bytes.Contains(content, []byte(testSSN)) {
					t.Errorf("advertised type %s: stream %q still contains the SSN", tp, name)
				}
			}
		})
	}
}
