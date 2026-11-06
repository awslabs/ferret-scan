// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The audit entries of the formats rewritten in place at a value's own byte length (#865), as the CLI
// writes them: the real audio and legacy Office redactors, AddRedactionResult and ExportAuditLog.
// Each entry carries the finding's line, and its redacted_text and strategy are what is in the file.
// Synthetic values: a reserved-domain address, a 555-01xx number, a sequential card serial.

// sameLengthEntry is one entry as asserted here: what the file must hold for it.
type sameLengthEntry struct {
	text, strategy, requested string
	line                      int
}

func checkSameLengthAudit(t *testing.T, what string, doc auditDoc, want map[string]sameLengthEntry, wide bool) {
	t.Helper()
	out, err := os.ReadFile(doc.RedactedPath)
	if err != nil {
		t.Fatalf("%s: reading the redacted file: %v", what, err)
	}
	if len(doc.ContentRedactions) != len(want) {
		t.Fatalf("%s: %d entries, want %d: %+v", what, len(doc.ContentRedactions), len(want), doc.ContentRedactions)
	}
	for _, e := range doc.ContentRedactions {
		w, ok := want[e.DataType]
		if !ok {
			t.Errorf("%s: unexpected entry %+v", what, e)
			continue
		}
		requested := ""
		if e.RequestedStrategy != nil {
			requested = *e.RequestedStrategy
		}
		if e.RedactedText != w.text || e.Strategy != w.strategy || requested != w.requested || e.Line != w.line {
			t.Errorf("%s %s: entry text %q strategy %q requested %q line %d; want %q %q %q %d",
				what, e.DataType, e.RedactedText, e.Strategy, requested, e.Line, w.text, w.strategy, w.requested, w.line)
		}
		form := []byte(e.RedactedText)
		if wide {
			form = utf16LE(e.RedactedText)
		}
		if !holdsWhole(out, form, wide) {
			t.Errorf("%s %s: redacted_text %q is not what the file holds", what, e.DataType, e.RedactedText)
		}
	}
}

// holdsWhole reports whether form occurs in buf other than inside a longer mask: a 20-byte mask is
// also "in" a file that holds only a 28-byte one.
func holdsWhole(buf, form []byte, wide bool) bool {
	star := []byte{'*'}
	if wide {
		star = []byte{'*', 0}
	}
	for off := 0; off+len(form) <= len(buf); {
		i := bytes.Index(buf[off:], form)
		if i < 0 {
			return false
		}
		at, end := off+i, off+i+len(form)
		if !bytes.HasSuffix(buf[:at], star) && !bytes.HasPrefix(buf[end:], star) {
			return true
		}
		off = at + 1
	}
	return false
}

func utf16LE(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// The issue's clip: one comment holding an email, reported as the address and as the whole field,
// merged into one span and written as one 28-byte mask. Its two entries used to say
// "j*******@example.com" and "c***************@example.com" beside format_preserving: 0 of 2 in the
// file. Under simple they said a 20-byte mask the file holds only inside the 28-byte one.
func TestAWAVsAuditIsWhatItsTagsHold(t *testing.T) {
	const field = "contact " + e2eEmail
	src := write(t, "merged.wav", wavWithLabelledValues(map[string]string{"ICMT": field, "IART": "Phone " + e2ePhone}))
	matches := []detector.Match{
		{Text: e2eEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 5, Filename: src},
		{Text: field, Type: "EMAIL", Confidence: 50, LineNumber: 5, Filename: src},
		{Text: e2ePhone, Type: "PHONE", Confidence: 100, LineNumber: 6, Filename: src},
	}
	mask := strings.Repeat("*", len(field))
	checkSameLengthAudit(t, "simple", redactAndAudit(t, src, matches, redactors.RedactionSimple), map[string]sameLengthEntry{
		"BUSINESS": {mask, "simple", "", 5},
		"EMAIL":    {mask, "simple", "", 5},
		"PHONE":    {strings.Repeat("*", len(e2ePhone)), "simple", "", 6},
	}, false)
	checkSameLengthAudit(t, "format_preserving", redactAndAudit(t, src, matches, redactors.RedactionFormatPreserving), map[string]sameLengthEntry{
		"BUSINESS": {mask, "mask", "format_preserving", 5},
		"EMAIL":    {mask, "mask", "format_preserving", 5},
		"PHONE":    {"(***) ***-0199", "format_preserving", "", 6},
	}, false)
}

// A legacy Office file's entries carry their lines, and a group masked whole under format_preserving
// says so. They recorded no line at all.
func TestALegacyDocumentsAuditIsWhatItsStreamsHold(t *testing.T) {
	// A card number running into an account number: two findings of different types sharing bytes,
	// written as one mask of their union.
	const account = "9012349876"
	union := e2eCard + "876"
	src := write(t, "w.doc", olefixture.LegacyDoc("Email "+e2eEmail+"\rRef "+union+"\r", nil))
	matches := []detector.Match{
		{Text: e2eEmail, Type: "BUSINESS", Validator: "email", Confidence: 90, LineNumber: 1, Filename: src},
		{Text: e2eCard, Type: "VISA", Validator: "creditcard", Confidence: 95, LineNumber: 2, Filename: src,
			Context: detector.ContextInfo{FullLine: "Ref " + union}},
		{Text: account, Type: "BANK_ACCOUNT", Validator: "bankaccount", Confidence: 60, LineNumber: 2, Filename: src,
			Context: detector.ContextInfo{FullLine: "Ref " + union}},
	}
	checkSameLengthAudit(t, "format_preserving", redactAndAudit(t, src, matches, redactors.RedactionFormatPreserving), map[string]sameLengthEntry{
		"BUSINESS": {"j*******@example.com", "format_preserving", "", 1},
		"VISA":     {strings.Repeat("*", len(union)), "mask", "format_preserving", 2},
	}, false)
}

// A value stored only as UTF-16 is overwritten at its UTF-16 width, so its entry records that text:
// "José Ramírez" is 14 bytes but 12 code units, and under simple the file holds a 12-unit mask, not
// the 14 '*' the entry used to record.
func TestALegacyUTF16ValueIsRecordedAtTheWidthWritten(t *testing.T) {
	const name = "José Ramírez"
	stream := append(utf16LE("Author "+name), 0, 0)
	src := write(t, "props.doc", olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamWordDocument, Data: stream}}))
	matches := []detector.Match{{Text: name, Type: "PERSON_NAME", Validator: "personname", Confidence: 80, LineNumber: 3, Filename: src}}
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		checkSameLengthAudit(t, st.String(), redactAndAudit(t, src, matches, st), map[string]sameLengthEntry{
			"PERSON_NAME": {strings.Repeat("*", len(utf16.Encode([]rune(name)))), st.String(), "", 3},
		}, true)
	}
}
