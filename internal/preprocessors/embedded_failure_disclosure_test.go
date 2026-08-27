// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// failingRouter fails ProcessEmbedded for parts whose name contains failOn, and succeeds otherwise.
//
// The error text deliberately carries a TEMP PATH with a random suffix, because that is what the
// production error actually looks like — "all preprocessors failed for file:
// /var/folders/.../office_embedded_4107861223.docx". A disclosure that interpolates it would leak a
// path into every output format and inject a fresh random value into stderr on every run.
type failingRouter struct {
	failOn string
}

func (r *failingRouter) ProcessFile(filePath string, _ interface{}) (*ProcessedContent, error) {
	return &ProcessedContent{
		OriginalPath: filePath, Filename: filePath, Text: "child text",
		Format: "text", ProcessorType: "image_metadata", Success: true,
	}, nil
}

func (r *failingRouter) ProcessEmbedded(childPath, _ string) (*ProcessedContent, error) {
	if r.failOn != "" && strings.Contains(childPath, r.failOn) {
		return nil, fmt.Errorf("all preprocessors failed for file: %s", childPath)
	}
	return r.ProcessFile(childPath, nil)
}

func (r *failingRouter) CanProcessFile(string, bool) (bool, string) { return true, "" }
func (r *failingRouter) EmbeddedBudget(string) *embedded.Budget     { return nil }
func (r *failingRouter) EmbeddedDepthOf(string) int                 { return 0 }

// tooDeepRouter returns the nesting sentinel, to keep the two disclosure arms distinguishable.
type tooDeepRouter struct{}

func (tooDeepRouter) ProcessFile(string, interface{}) (*ProcessedContent, error) { return nil, nil }
func (tooDeepRouter) ProcessEmbedded(childPath, _ string) (*ProcessedContent, error) {
	return nil, fmt.Errorf("%w: %s is nested 4 levels deep (limit 3)",
		ErrEmbeddedTooDeep, filepath.Base(childPath))
}
func (tooDeepRouter) CanProcessFile(string, bool) (bool, string) { return true, "" }
func (tooDeepRouter) EmbeddedBudget(string) *embedded.Budget     { return nil }
func (tooDeepRouter) EmbeddedDepthOf(string) int                 { return 0 }

// embeddedPart writes a real temp file so CanProcessFile and the router see something on disk.
func embeddedPart(t *testing.T, name string) EmbeddedMedia {
	t.Helper()
	dir := t.TempDir()
	// The temp name carries a random-looking suffix, like the production one.
	temp := filepath.Join(dir, "office_embedded_4107861223"+filepath.Ext(name))
	if err := os.WriteFile(temp, []byte("part bytes"), 0o600); err != nil {
		t.Fatalf("write part: %v", err)
	}
	return EmbeddedMedia{OriginalName: "word/embeddings/" + name, TempFilePath: temp, MediaType: "document"}
}

func newBMP(router RouterInterface) *BaseMetadataPreprocessor {
	bmp := NewBaseMetadataPreprocessor("test_metadata", "test_metadata")
	bmp.SetObserver(observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr))
	bmp.SetRouter(router)
	return bmp
}

// TestFailedEmbeddedPartIsDisclosed is the regression test for #404.
//
// An embedded part that reached the router and FAILED fell off the loop body with nothing appended
// to the warnings slice, because the success arm had no else. Measured on a real .docx carrying one
// corrupt embedded part: the document was indistinguishable from one carrying NO embedded part at
// all — same 38 findings, exit 0, exit 0 again under --fail-on-incomplete, and not one byte of
// disclosure — while the part survived into the "redacted" output with its cleartext intact.
func TestFailedEmbeddedPartIsDisclosed(t *testing.T) {
	bmp := newBMP(&failingRouter{failOn: ".docx"})
	_, _, warnings := bmp.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "attach.docx")})

	if len(warnings) == 0 {
		t.Fatal("a failed embedded part produced NO warning; the container is reported exactly as " +
			"one with no embedded part at all (#404)")
	}
	joined := strings.Join(warnings, " | ")
	if !strings.Contains(joined, "attach.docx") {
		t.Errorf("the disclosure does not name the part: %q", joined)
	}
	if !strings.Contains(joined, "not examined") {
		t.Errorf("the disclosure must say the part was NOT EXAMINED so #403's classifier files it "+
			"under coverage cut short: %q", joined)
	}
}

// TestDisclosureCarriesNoTempPath is the constraint that makes the fix shippable rather than a
// different bug.
//
// The production error's text is "all preprocessors failed for file:
// /var/folders/.../office_embedded_4107861223.docx". Interpolating it would put a temp path into
// stderr and into every machine format — breaking the payload-free rule this area holds to — and the
// random suffix changes every run, so it would inject nondeterminism into any golden file capturing
// it. The nesting arm above is safe only because its sentinel's own message is already base-named.
func TestDisclosureCarriesNoTempPath(t *testing.T) {
	bmp := newBMP(&failingRouter{failOn: ".docx"})
	_, _, warnings := bmp.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "attach.docx")})

	joined := strings.Join(warnings, " | ")
	for _, banned := range []string{"office_embedded_", "4107861223", os.TempDir(), "/var/folders"} {
		if banned == "" {
			continue
		}
		if strings.Contains(joined, banned) {
			t.Errorf("the disclosure leaks %q: %s", banned, joined)
		}
	}
	// The whole point of not interpolating: two runs must produce the same bytes.
	bmp2 := newBMP(&failingRouter{failOn: ".docx"})
	_, _, again := bmp2.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "attach.docx")})
	if strings.Join(again, " | ") != joined {
		t.Errorf("the disclosure differs between runs:\n  %q\n  %q", joined, strings.Join(again, " | "))
	}
}

// TestSuccessfulPartIsNotDisclosed keeps the new arm from becoming vacuous.
//
// A warning that fires for every part would raise --fail-on-incomplete to 3 on every document with
// an embedded image, which trains operators to ignore the flag — the failure mode the CanProcessFile
// and SkipTextPipeline silences above are deliberately shaped to avoid.
func TestSuccessfulPartIsNotDisclosed(t *testing.T) {
	bmp := newBMP(&failingRouter{}) // fails nothing
	text, _, warnings := bmp.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "attach.docx"), embeddedPart(t, "photo.jpg")})

	if len(warnings) != 0 {
		t.Errorf("successful parts produced %d warning(s): %v", len(warnings), warnings)
	}
	if !strings.Contains(text, "child text") {
		t.Error("the successful parts' text was not assembled, so this test is not exercising the " +
			"success path it claims to")
	}
}

// TestOnlyTheFailedPartIsDisclosed: one bad part must not suppress or implicate its siblings.
func TestOnlyTheFailedPartIsDisclosed(t *testing.T) {
	bmp := newBMP(&failingRouter{failOn: ".docx"})
	text, _, warnings := bmp.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "attach.docx"), embeddedPart(t, "photo.jpg")})

	joined := strings.Join(warnings, " | ")
	if strings.Contains(joined, "photo.jpg") {
		t.Errorf("the healthy sibling was disclosed as unexamined: %q", joined)
	}
	if !strings.Contains(joined, "attach.docx") {
		t.Errorf("the failed part was not disclosed: %q", joined)
	}
	if !strings.Contains(text, "child text") {
		t.Error("the healthy sibling's text was dropped; a failure must not cost its siblings' coverage")
	}
}

// TestNestingBoundStillUsesItsOwnDisclosure guards the ordering of the two arms.
//
// ErrEmbeddedTooDeep is a distinct cause with a distinct message, and it is checked first. If the
// new generic arm ran ahead of it, the specific "nesting limit reached" wording — which an operator
// can act on differently from "could not be processed" — would be replaced by the generic one.
func TestNestingBoundStillUsesItsOwnDisclosure(t *testing.T) {
	bmp := newBMP(tooDeepRouter{})
	_, _, warnings := bmp.ProcessEmbeddedMedia("container.docx",
		[]EmbeddedMedia{embeddedPart(t, "deep.docx")})

	if len(warnings) == 0 {
		t.Fatal("the nesting bound produced no disclosure")
	}
	joined := strings.Join(warnings, " | ")
	if !strings.Contains(joined, "nested") && !strings.Contains(joined, errors.Unwrap(fmt.Errorf("%w", ErrEmbeddedTooDeep)).Error()) {
		t.Errorf("the nesting bound lost its specific wording to the generic arm: %q", joined)
	}
}

// TestIdenticalWarningsAreCollapsed covers the output shape a whole-traversal budget creates.
//
// The extractor caps notes per container, which was enough while only one container could refuse. A
// traversal budget means sixty sibling containers each refuse one part and each contributes an
// identical line. Measured before collapsing, on a 2.4MB fan-out fixture: a single 12,000-character
// warning line, the same 200 characters sixty times over. Collapsed, it is 252 characters with the
// count that an operator actually acts on.
func TestIdenticalWarningsAreCollapsed(t *testing.T) {
	parts := make([]EmbeddedMedia, 0, 8)
	for i := 0; i < 8; i++ {
		parts = append(parts, embeddedPart(t, "attach.docx"))
	}
	bmp := newBMP(&failingRouter{failOn: ".docx"})
	_, _, warnings := bmp.ProcessEmbeddedMedia("container.docx", parts)

	if len(warnings) != 1 {
		t.Fatalf("8 identical failures produced %d warning lines, want 1 collapsed line: %v",
			len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "(x8)") {
		t.Errorf("the collapsed line must carry the COUNT — one refusal and sixty call for different "+
			"responses: %q", warnings[0])
	}
}

// TestCollapseKeepsDistinctWarningsAndFirstAppearanceOrder.
//
// Distinct causes must survive collapsing, and the order must be the order the parts were walked:
// this string reaches stderr, every machine format and any golden file, so regrouping it run to run
// would be nondeterminism in output.
func TestCollapseKeepsDistinctWarningsAndFirstAppearanceOrder(t *testing.T) {
	got := collapseDuplicateWarnings([]string{"beta", "alpha", "beta", "gamma", "alpha", "beta"})
	want := []string{"beta (x3)", "alpha (x2)", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("collapseDuplicateWarnings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q (first-appearance order)", i, got[i], want[i])
		}
	}
}

// atDepthRouter reports a fixed depth, so the pre-materialisation guard can be driven directly.
type atDepthRouter struct{ depth int }

func (r *atDepthRouter) ProcessFile(filePath string, _ interface{}) (*ProcessedContent, error) {
	return &ProcessedContent{
		OriginalPath: filePath, Filename: filePath, Text: "child text",
		Format: "text", ProcessorType: "image_metadata", Success: true,
	}, nil
}
func (r *atDepthRouter) ProcessEmbedded(childPath, _ string) (*ProcessedContent, error) {
	return r.ProcessFile(childPath, nil)
}
func (r *atDepthRouter) CanProcessFile(string, bool) (bool, string) { return true, "" }
func (r *atDepthRouter) EmbeddedBudget(string) *embedded.Budget     { return embedded.NewBudget() }
func (r *atDepthRouter) EmbeddedDepthOf(string) int                 { return r.depth }

// TestAtTheDepthBoundNothingIsMaterialised covers the cheap half of #474.
//
// MaxEmbeddedDepth is enforced in ProcessEmbedded, which runs only AFTER each part has been inflated
// and written to a temp file — so at the bound the deepest level's bytes were written and then thrown
// away. On the 4-level bomb fixture that was the single largest contributor to the 180MB of temp a
// 198KB document produced; consulting the depth first took it to 135MB.
//
// Asserted on processEmbeddedMedia rather than end to end, because the property is "this function
// does no extraction at the bound", and its return values are exactly that.
func TestAtTheDepthBoundNothingIsMaterialised(t *testing.T) {
	// A real .docx with an embedded part, so reaching extraction would genuinely produce something.
	path := buildOfficeFixtureWithPart(t)

	omp := NewOfficeMetadataPreprocessor()
	omp.SetObserver(observability.NewStandardObserver(observability.ObservabilityMetrics, os.Stderr))

	// Below the bound: extraction happens, so the fixture and the assertion are both live.
	omp.SetRouter(&atDepthRouter{depth: 0})
	text, sections, warnings := omp.processEmbeddedMedia(path)
	if text == "" && len(sections) == 0 {
		t.Fatalf("below the bound nothing was extracted either, so this test cannot show the guard "+
			"doing anything (warnings=%v)", warnings)
	}

	// At the bound: no extraction, and the reason is stated.
	omp.SetRouter(&atDepthRouter{depth: embedded.MaxDepth})
	text, sections, warnings = omp.processEmbeddedMedia(path)

	if text != "" || len(sections) != 0 {
		t.Errorf("at the depth bound the parts were still extracted (%d bytes of text, %d sections); "+
			"their bytes are written and then discarded", len(text), len(sections))
	}
	if len(warnings) == 0 {
		t.Fatal("skipping extraction at the bound was SILENT; refusing to descend is incomplete " +
			"coverage and has to be disclosed, or it reads as a clean result")
	}
	joined := strings.Join(warnings, " | ")
	if !strings.Contains(joined, "nesting limit") {
		t.Errorf("the note must name the cause so it is distinguishable from a part that failed: %q", joined)
	}
}

// buildOfficeFixtureWithPart writes a minimal .docx carrying one embedded part.
func buildOfficeFixtureWithPart(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "container.docx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	z := zip.NewWriter(f)
	for name, body := range map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`,
		"_rels/.rels":         `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml":   `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>body</w:t></w:r></w:p></w:body></w:document>`,
		// A PNG signature so the part is admitted rather than skipped for its shape.
		"word/media/image0.png": "\x89PNG\r\n\x1a\n" + strings.Repeat("padding", 64),
	} {
		w, werr := z.Create(name)
		if werr != nil {
			t.Fatalf("create %s: %v", name, werr)
		}
		if _, werr = w.Write([]byte(body)); werr != nil {
			t.Fatalf("write %s: %v", name, werr)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

// TestCollapseBoundsDistinctWarnings: a document with thousands of DIFFERENT failures must not
// produce thousands of lines, and the overflow has to be stated rather than dropped.
func TestCollapseBoundsDistinctWarnings(t *testing.T) {
	in := make([]string, 0, maxDistinctEmbeddedWarnings+30)
	for i := 0; i < maxDistinctEmbeddedWarnings+30; i++ {
		in = append(in, fmt.Sprintf("distinct cause %d", i))
	}
	got := collapseDuplicateWarnings(in)
	if len(got) != maxDistinctEmbeddedWarnings+1 {
		t.Fatalf("got %d lines, want %d plus one overflow note",
			len(got), maxDistinctEmbeddedWarnings)
	}
	last := got[len(got)-1]
	if !strings.Contains(last, "30") || !strings.Contains(last, "further") {
		t.Errorf("the overflow note must say how many were not shown, got %q", last)
	}
}
