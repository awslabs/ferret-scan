// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

func newTestManager(t *testing.T) *RedactionManager {
	t.Helper()
	// A real OutputStructureManager: NewRedactionManagerWithConfig dereferences it to
	// build the audit log manager, so nil panics.
	om, err := NewOutputStructureManager(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("building output manager: %v", err)
	}
	return NewRedactionManagerWithConfig(om, nil, nil)
}

func sampleMatches() []detector.Match {
	return []detector.Match{{Text: "452-11-9384", Type: "SSN", Confidence: 100}}
}

// TestRedactEmbeddedRefusesPastTheDepthBound.
//
// Without the bound, admitting embedded OOXML documents is unbounded recursion and a
// decompression-bomb amplifier: an embedded .docx dispatches to the Office redactor,
// which dispatches ITS embeddings, which dispatch back. Measured on the read side
// with a 7KB .docx embedding itself nine times, all nine levels were followed.
func TestRedactEmbeddedRefusesPastTheDepthBound(t *testing.T) {
	rm := newTestManager(t)

	// Stand the parent at the limit, so the child would be one level too deep.
	parent := filepath.Join(t.TempDir(), "parent.docx")
	rm.embeddedDepth.set(parent, embedded.MaxDepth)

	_, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
		ParentPath: parent,
		PartName:   "word/embeddings/tooDeep.docx",
		Content:    []byte("PK\x03\x04 pretend package"),
		Matches:    sampleMatches(),
		Strategy:   RedactionFormatPreserving,
	})
	if err == nil {
		t.Fatal("RedactEmbedded descended past the depth bound and returned no error")
	}
	if !errors.Is(err, embedded.ErrTooDeep) {
		t.Errorf("error %v does not match embedded.ErrTooDeep, so a caller cannot tell "+
			"\"coverage was cut short\" from \"this child failed to parse\" and the "+
			"disclosure is downgraded to a generic failure", err)
	}
	// The message has to be actionable: it must name the part and the limit.
	if !strings.Contains(err.Error(), "tooDeep.docx") {
		t.Errorf("error %q does not name the part", err.Error())
	}
}

// TestRedactEmbeddedAcceptsInsideTheBound is the recall half.
//
// A bound that refuses at a legitimate depth is worse than none: it stops redaction
// that would have removed a value, and the read side would have reported it.
func TestRedactEmbeddedAcceptsInsideTheBound(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	rm := newTestManager(t)
	// .jpg rather than .txt: the extension has to be one the shared admission table
	// accepts, or the request is refused before the depth check is reached.
	if err := rm.RegisterRedactor(&stubRedactor{exts: []string{".jpg"}}); err != nil {
		t.Fatal(err)
	}

	parent := filepath.Join(t.TempDir(), "parent.docx")
	// One below the limit, so the child sits exactly AT it and must be allowed.
	rm.embeddedDepth.set(parent, embedded.MaxDepth-1)

	res, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
		ParentPath: parent,
		PartName:   "word/media/atTheLimit.jpg",
		Content:    []byte("original bytes"),
		Matches:    sampleMatches(),
		Strategy:   RedactionFormatPreserving,
	})
	if err != nil {
		t.Fatalf("RedactEmbedded refused a part at depth %d, which is within the limit of "+
			"%d: %v", embedded.MaxDepth, embedded.MaxDepth, err)
	}
	if string(res.Content) != stubRedactedOutput {
		t.Errorf("returned content %q, want the redactor's output %q — the bytes actually "+
			"written by the child must be what comes back, not the input",
			res.Content, stubRedactedOutput)
	}
}

// TestRedactEmbeddedRejectsUnadmittedExtension.
//
// The extension chooses the redactor AND is concatenated into a temp path, so an
// unadmitted one must be refused rather than passed through.
func TestRedactEmbeddedRejectsUnadmittedExtension(t *testing.T) {
	rm := newTestManager(t)
	for _, part := range []string{
		"word/embeddings/payload.exe",
		"word/embeddings/payload",
		"word/embeddings/../../../etc/passwd",
	} {
		_, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
			ParentPath: "parent.docx",
			PartName:   part,
			Content:    []byte("x"),
			Matches:    sampleMatches(),
			Strategy:   RedactionFormatPreserving,
		})
		if err == nil {
			t.Errorf("RedactEmbedded(%q) returned no error for an unadmitted type", part)
			continue
		}
		if !errors.Is(err, ErrNoEmbeddedRedactor) {
			t.Errorf("RedactEmbedded(%q) error %v does not match ErrNoEmbeddedRedactor, so "+
				"the caller cannot tell a coverage gap from a transient failure", part, err)
		}
	}
}

// TestRedactEmbeddedReportsMissingRedactorAsACoverageGap.
//
// Audio is the live case: it is scanned, so a value in a tag is reported, and no
// redactor can remove it. That must surface as a coverage gap, never as success.
func TestRedactEmbeddedReportsMissingRedactorAsACoverageGap(t *testing.T) {
	rm := newTestManager(t) // nothing registered

	_, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
		ParentPath: "parent.docx",
		PartName:   "word/media/audio1.mp3",
		Content:    []byte("ID3 tag with a value"),
		Matches:    sampleMatches(),
		Strategy:   RedactionFormatPreserving,
	})
	if err == nil {
		t.Fatal("RedactEmbedded returned success for a type no redactor handles")
	}
	if !errors.Is(err, ErrNoEmbeddedRedactor) {
		t.Errorf("error %v does not match ErrNoEmbeddedRedactor", err)
	}
}

// TestRedactEmbeddedLeavesNoTemporaryFiles.
//
// The temp file holds the part's UNREDACTED bytes — precisely the values the run
// exists to remove. One left behind after a failure is a second disclosure, sitting
// in a world-listable directory for as long as the host lives.
func TestRedactEmbeddedLeavesNoTemporaryFiles(t *testing.T) {
	// Point TMPDIR at an empty directory so anything created is attributable.
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	rm := newTestManager(t)
	okRedactor := &stubRedactor{exts: []string{".jpg"}}
	if err := rm.RegisterRedactor(okRedactor); err != nil {
		t.Fatal(err)
	}
	failing := &stubRedactor{exts: []string{".png"}, fail: true}
	if err := rm.RegisterRedactor(failing); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		part string
	}{
		{"success path", "word/media/image1.jpg"},
		{"redactor error path", "word/media/image1.png"},
		{"no redactor path", "word/media/audio1.mp3"},
		{"unadmitted type path", "word/media/thing.exe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = rm.RedactEmbedded(EmbeddedRedactionRequest{
				ParentPath: "parent.docx",
				PartName:   tc.part,
				Content:    []byte("bytes holding 452-11-9384"),
				Matches:    sampleMatches(),
				Strategy:   RedactionFormatPreserving,
			})

			leftovers, err := os.ReadDir(tmp)
			if err != nil {
				t.Fatal(err)
			}
			if len(leftovers) != 0 {
				names := make([]string, 0, len(leftovers))
				for _, e := range leftovers {
					names = append(names, e.Name())
				}
				t.Errorf("%d temporary entr(ies) survived: %v\nThese hold the part's "+
					"UNREDACTED bytes.", len(leftovers), names)
			}
		})
	}
}

// TestRedactEmbeddedTempFileIsNotWorldReadable.
//
// A predictable or group-readable temp file publishes the cleartext values to any
// other account on the host for the duration of the scan.
func TestRedactEmbeddedTempFileIsNotWorldReadable(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	rm := newTestManager(t)
	spy := &modeSpyRedactor{t: t}
	if err := rm.RegisterRedactor(spy); err != nil {
		t.Fatal(err)
	}

	if _, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
		ParentPath: "parent.docx",
		PartName:   "word/media/image1.jpg",
		Content:    []byte("secret bytes"),
		Matches:    sampleMatches(),
		Strategy:   RedactionFormatPreserving,
	}); err != nil {
		t.Fatalf("RedactEmbedded: %v", err)
	}
	if !spy.observed {
		t.Fatal("the stub redactor was never called, so nothing was checked")
	}
	if spy.fileMode.Perm()&0o077 != 0 {
		t.Errorf("the temp file holding unredacted bytes has mode %v; it must not be "+
			"readable by group or other", spy.fileMode.Perm())
	}
	if spy.dirMode.Perm()&0o077 != 0 {
		t.Errorf("the temp directory has mode %v; it must not be readable by group or "+
			"other", spy.dirMode.Perm())
	}
}

// TestRedactEmbeddedPassesTheWholeMatchList.
//
// A finding from an embedded part carries no attribution to that part — every one
// reports the CONTAINER as its origin — so the child cannot be handed a subset. If
// it were, a value living only in the child would be filtered out before the child
// ever looked for it.
func TestRedactEmbeddedPassesTheWholeMatchList(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	rm := newTestManager(t)
	spy := &modeSpyRedactor{t: t}
	if err := rm.RegisterRedactor(spy); err != nil {
		t.Fatal(err)
	}

	want := []detector.Match{
		{Text: "452-11-9384", Type: "SSN"},
		{Text: "536-90-4271", Type: "SSN"},
		{Text: "4111111111111111", Type: "CREDIT_CARD"},
	}
	if _, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
		ParentPath: "parent.docx",
		PartName:   "word/media/image1.jpg",
		Content:    []byte("x"),
		Matches:    want,
		Strategy:   RedactionFormatPreserving,
	}); err != nil {
		t.Fatal(err)
	}
	if len(spy.gotMatches) != len(want) {
		t.Errorf("the child received %d matches, want all %d. A subset means a value that "+
			"lives only in the child is filtered out before the child looks for it.",
			len(spy.gotMatches), len(want))
	}
}

// TestDepthStateIsClearedSoItDoesNotGrow.
//
// Entries must be removed when a child finishes, or the map grows for the life of a
// directory scan — one entry per embedded part across every file.
func TestDepthStateIsClearedSoItDoesNotGrow(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	rm := newTestManager(t)
	if err := rm.RegisterRedactor(&stubRedactor{exts: []string{".jpg"}}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		if _, err := rm.RedactEmbedded(EmbeddedRedactionRequest{
			ParentPath: "parent.docx",
			PartName:   "word/media/image1.jpg",
			Content:    []byte("x"),
			Matches:    sampleMatches(),
			Strategy:   RedactionFormatPreserving,
		}); err != nil {
			t.Fatal(err)
		}
	}

	rm.embeddedDepth.mu.Lock()
	n := len(rm.embeddedDepth.depth)
	rm.embeddedDepth.mu.Unlock()
	if n != 0 {
		t.Errorf("depth map holds %d entries after 20 completed children; it must be "+
			"cleared so it does not grow across a directory scan", n)
	}
}

// ---------- stubs ----------

const stubRedactedOutput = "REDACTED-BY-STUB"

// stubRedactor stands in for a format redactor so these tests exercise the dispatch
// mechanism rather than any real format's parsing.
type stubRedactor struct {
	exts []string
	fail bool
}

func (s *stubRedactor) GetName() string { return "stub" }
func (s *stubRedactor) GetSupportedTypes() []string {
	return s.exts
}
func (s *stubRedactor) GetSupportedStrategies() []RedactionStrategy {
	return []RedactionStrategy{RedactionSimple, RedactionFormatPreserving, RedactionSynthetic}
}
func (s *stubRedactor) GetComponentName() string { return "stub" }

func (s *stubRedactor) RedactDocument(originalPath, outputPath string,
	matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error) {
	if s.fail {
		return nil, errors.New("stub failure")
	}
	if err := os.WriteFile(outputPath, []byte(stubRedactedOutput), 0o600); err != nil {
		return nil, err
	}
	return &RedactionResult{Success: true, RedactedFilePath: outputPath}, nil
}

// modeSpyRedactor records the permissions of the temp file and directory it is
// handed, and the matches it receives.
type modeSpyRedactor struct {
	t          *testing.T
	observed   bool
	fileMode   os.FileMode
	dirMode    os.FileMode
	gotMatches []detector.Match
}

func (m *modeSpyRedactor) GetName() string             { return "modespy" }
func (m *modeSpyRedactor) GetSupportedTypes() []string { return []string{".jpg"} }
func (m *modeSpyRedactor) GetSupportedStrategies() []RedactionStrategy {
	return []RedactionStrategy{RedactionFormatPreserving}
}
func (m *modeSpyRedactor) GetComponentName() string { return "modespy" }

func (m *modeSpyRedactor) RedactDocument(originalPath, outputPath string,
	matches []detector.Match, strategy RedactionStrategy) (*RedactionResult, error) {
	m.observed = true
	m.gotMatches = matches
	if fi, err := os.Stat(originalPath); err == nil {
		m.fileMode = fi.Mode()
	}
	if fi, err := os.Stat(filepath.Dir(originalPath)); err == nil {
		m.dirMode = fi.Mode()
	}
	if err := os.WriteFile(outputPath, []byte(stubRedactedOutput), 0o600); err != nil {
		return nil, err
	}
	return &RedactionResult{Success: true, RedactedFilePath: outputPath}, nil
}
