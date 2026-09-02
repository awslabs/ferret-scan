// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// A container that yields no document text must say so.
//
// Selecting the body part by name means an unrecognized name yields zero text, and
// zero text used to be indistinguishable from an empty document: Success=true,
// exit 0, no message. That made the failure the part-selection fix addresses silent
// by construction — a 40-page document could contribute nothing to a scan and the
// operator would have no signal.
//
// The subtle half is that the warning must survive an ERROR return. When the archive
// has no recognizable body part at all, the extractor both sets the warning and
// returns an error, and the file usually still has a successful metadata sibling — so
// any code path that only propagates warnings from non-error results drops the note
// exactly when it matters most.

// TestExtractionWarningSurvivesAnExtractorError is the regression. It routes a
// container in which one preprocessor errored while carrying a warning, and one
// succeeded, which is the real shape of a .docx with a missing body part.
func TestExtractionWarningSurvivesAnExtractorError(t *testing.T) {
	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		// Mirrors the text extractor: no body part found, so both an error and the
		// note that explains what the user lost.
		&stubPreprocessor{
			name:    "Text Extractor",
			warning: "no text extracted from .docx: no document body part was found in the archive",
			err:     errNoBodyPart,
		},
		// Mirrors office_metadata, which succeeds from docProps and would otherwise
		// make the whole file look fine.
		&stubPreprocessor{
			name: "office_metadata",
			text: "Author: Jane Analyst\n",
		},
	}

	got, err := fr.ProcessFileWithContext("report.docx", &ProcessingContext{FilePath: "report.docx"})
	if err != nil {
		t.Fatalf("routing failed outright: %v", err)
	}
	if got.ExtractionWarning == "" {
		t.Fatalf("no ExtractionWarning survived.\n"+
			"The extractor that found no body part returned an error alongside its warning, and "+
			"the successful metadata sibling made the file look healthy — so the scan would "+
			"report metadata-only findings at exit 0 with nothing said about the unread "+
			"document body.\n  ProcessorType=%q Text=%q", got.ProcessorType, got.Text)
	}
	if !strings.Contains(got.ExtractionWarning, "no document body part") {
		t.Errorf("ExtractionWarning = %q, want it to name the missing body part", got.ExtractionWarning)
	}
	if !strings.Contains(got.ExtractionWarning, "Text Extractor") {
		t.Errorf("ExtractionWarning = %q, want it to name which preprocessor reported it, since a "+
			"combined result has several", got.ExtractionWarning)
	}
}

// TestNoExtractionWarningOnAHealthyContainer is the non-vacuity floor. If the warning
// were emitted unconditionally the test above would pass while every ordinary scan
// gained a spurious message and, with --fail-on-incomplete, a spurious exit 3.
func TestNoExtractionWarningOnAHealthyContainer(t *testing.T) {
	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		&stubPreprocessor{name: "Text Extractor", text: "Employee SSN 449-87-4100 on file.\n"},
		&stubPreprocessor{name: "office_metadata", text: "Author: Jane Analyst\n"},
	}

	got, err := fr.ProcessFileWithContext("report.docx", &ProcessingContext{FilePath: "report.docx"})
	if err != nil {
		t.Fatalf("routing failed: %v", err)
	}
	if got.ExtractionWarning != "" {
		t.Errorf("ExtractionWarning = %q on a container that extracted normally; every ordinary "+
			"scan would carry this message", got.ExtractionWarning)
	}
}

// TestDocxWithNoBodyPartIsFlagged drives the real extractors rather than stubs, so the
// two halves (the extractor setting the note, the router carrying it) are proven to fit
// together. BOTH real producers are wired in, because the router-carrying half only
// exists on the success arm: with the text extractor alone, its body-part error makes
// the whole route fail, the stub test above is the only coverage the carry gets, and an
// earlier version of this test passed with noteEmptyExtraction deleted outright.
func TestDocxWithNoBodyPartIsFlagged(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "nobody.docx")
	if err := os.WriteFile(path, docxWithoutBodyPart(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	// Use the real preprocessors rather than the registry: NewFileRouter starts
	// with an empty preprocessor list and InitializePreprocessors registers only what
	// a caller has previously supplied a factory for, so relying on it would make this
	// test silently skip — which is how the gap being fixed stayed invisible. The
	// fixture provides docProps/core.xml, so the metadata producer succeeds.
	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		preprocessors.NewTextPreprocessor(),
		preprocessors.NewOfficeMetadataPreprocessor(),
	}

	got, err := fr.ProcessFileWithContext(path, &ProcessingContext{FilePath: path})
	if err != nil {
		t.Fatalf("routing failed outright (%v); the router-carrying half this test is "+
			"named for was never exercised", err)
	}
	if got == nil || got.ProcessorType == "" {
		t.Fatal("no successful producer, so the warning-carrying success arm is unreachable " +
			"and this test proves nothing")
	}
	if got.ExtractionWarning == "" {
		t.Fatalf("a .docx with no document body part produced no ExtractionWarning "+
			"(ProcessorType=%q, textLen=%d); the metadata sibling made the file look healthy, "+
			"so its unread body would be invisible to the operator", got.ProcessorType, len(got.Text))
	}
	if !strings.Contains(got.ExtractionWarning, "no document body part") {
		t.Errorf("ExtractionWarning = %q, want it to name the missing body part", got.ExtractionWarning)
	}
}

// --- helpers ---------------------------------------------------------------

var errNoBodyPart = io.ErrUnexpectedEOF // any non-nil error; the value is not asserted

type stubPreprocessor struct {
	name    string
	text    string
	warning string
	err     error
}

func (s *stubPreprocessor) GetName() string                    { return s.name }
func (s *stubPreprocessor) CanProcess(string) bool             { return true }
func (s *stubPreprocessor) GetSupportedExtensions() []string   { return []string{".docx"} }
func (s *stubPreprocessor) SetObserver(observability.Observer) {}

func (s *stubPreprocessor) Process(filePath string) (*preprocessors.ProcessedContent, error) {
	c := &preprocessors.ProcessedContent{
		OriginalPath:      filePath,
		Filename:          filepath.Base(filePath),
		Text:              s.text,
		ProcessorType:     s.name,
		Success:           s.err == nil,
		ExtractionWarning: s.warning,
	}
	return c, s.err
}

// docxWithoutBodyPart builds a .docx whose relationships name a document part that is
// not in the archive, while docProps/core.xml is present — so the metadata extractor
// succeeds and the text extractor cannot find a body.
func docxWithoutBodyPart() []byte {
	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
	parts := []struct{ name, body string }{
		{"[Content_Types].xml", decl +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
			`</Types>`},
		{"_rels/.rels", decl +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"docProps/core.xml", decl +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">` +
			`<dc:creator>Jane Analyst</dc:creator></cp:coreProperties>`},
		// word/document.xml is deliberately absent.
	}

	out := new(bytes.Buffer)
	zw := zip.NewWriter(out)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, p.body); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// A warning that already names its producer must not be prefixed with that name again.
//
// An embedded container routes back through this same combine step, and every level used to
// add its own copy, so a note from four levels down reached the operator as
//
//	office_metadata: office_metadata: office_metadata: office_metadata: embedded item …
//
// measured on a .docx nested six deep. The name is there to say which reader produced the
// note; repeating it says nothing more and pushes the part that matters off the line.
func TestAWarningIsNotPrefixedTwiceWithItsOwnProducer(t *testing.T) {
	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		// Exactly what a nested container hands back: the child's combine step already
		// prefixed the note, and the parent's is about to run over it.
		&stubPreprocessor{
			name:    "office_metadata",
			text:    "Author: Jane Analyst\n",
			warning: `office_metadata: embedded item "attachment.docx" was not examined: embedded container nesting limit reached`,
		},
	}

	got, err := fr.ProcessFileWithContext("outer.docx", &ProcessingContext{FilePath: "outer.docx"})
	if err != nil {
		t.Fatalf("routing failed: %v", err)
	}
	if n := strings.Count(got.ExtractionWarning, "office_metadata: "); n != 1 {
		t.Errorf("the producer name appears %d times, want 1:\n  %q", n, got.ExtractionWarning)
	}
	// Still prefixed once, because a combined result has several producers and the
	// operator needs to know which one is talking.
	if !strings.HasPrefix(got.ExtractionWarning, "office_metadata: ") {
		t.Errorf("ExtractionWarning = %q, want it to name the producer once", got.ExtractionWarning)
	}
	if !strings.Contains(got.ExtractionWarning, "attachment.docx") {
		t.Errorf("ExtractionWarning = %q, want the part it is about to survive the prefixing",
			got.ExtractionWarning)
	}
}

// The other direction: a note that does NOT already carry its producer's name still gets one.
// Dropping the prefix entirely would be the obvious wrong way to remove the duplication.
func TestAnUnprefixedWarningStillGetsItsProducer(t *testing.T) {
	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		&stubPreprocessor{
			name:    "audio_metadata",
			text:    "Artist: Jane Analyst\n",
			warning: "audio metadata may be incomplete: the WAV chunk layout could not be walked to the end",
		},
	}

	got, err := fr.ProcessFileWithContext("clip.wav", &ProcessingContext{FilePath: "clip.wav"})
	if err != nil {
		t.Fatalf("routing failed: %v", err)
	}
	if !strings.HasPrefix(got.ExtractionWarning, "audio_metadata: ") {
		t.Errorf("ExtractionWarning = %q, want the producing preprocessor named", got.ExtractionWarning)
	}
}
