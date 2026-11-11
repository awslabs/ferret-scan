// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// The re-scan sink for #915, through the whole pipeline: scan a .doc, redact it, and scan the copy
// with the same code. A value the first scan reported and the second reports again is a silent
// survivor, whatever a byte grep of the copy says; for a typed property the grep says nothing at
// all, because the digits exist only after decoding.
//
// On the parent commit the re-scan reports the VT_I4 custom property's CUSTOM_PROPERTY finding again,
// byte for byte, under both strategies, and the run calls the file redacted. It also reports one
// finding per masked metadata field (AUTHOR_INFO "************" and the like): a field name with no
// value, which the extractor now leaves out.
func TestRescanOfARedactedLegacyDocReportsNoneOfItsFindings(t *testing.T) {
	const reviewCycle = "1928374650"
	doc := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: []byte("Quarterly review notes for the planning group.\r")},
		{Name: olefixture.StreamSummaryInformation, Data: olefixture.SummaryInformation(map[uint32]string{
			olefixture.PropAuthor:     "Jane Analyst",
			olefixture.PropLastAuthor: "Ops Reviewer",
		})},
		{Name: olefixture.StreamDocSummaryInformation, Data: olefixture.DocSummaryInformationWithCustom(
			map[uint32]string{olefixture.PropCompany: "Fairbanks Holdings"},
			map[string]string{"_AuthorEmail": "jane.analyst@example.com"},
			map[string]olefixture.TypedValue{"_AdHocReviewCycleID": olefixture.Int32(1928374650)},
		)},
	})
	dir := t.TempDir()
	src := filepath.Join(dir, "review.doc")
	if err := os.WriteFile(src, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.LoadConfigOrDefault("")

	for _, strategy := range []string{"simple", "format_preserving"} {
		t.Run(strategy, func(t *testing.T) {
			res, err := core.RedactFile(core.RedactConfig{
				FilePath:  src,
				OutputDir: filepath.Join(dir, "out-"+strategy),
				Strategy:  strategy,
				Config:    cfg,
				LogWriter: io.Discard,
			})
			if err != nil {
				t.Fatalf("RedactFile: %v", err)
			}
			type key struct{ typ, text string }
			before := map[key]bool{}
			for _, m := range res.Matches {
				before[key{m.Type, m.Text}] = true
			}
			if !before[key{"CUSTOM_PROPERTY", reviewCycle}] {
				t.Fatalf("the fixture's numeric custom property is not reported (%d findings); the re-scan "+
					"below would prove nothing about it", len(res.Matches))
			}
			if res.RedactedFilePath == "" {
				t.Fatal("no redacted copy was written")
			}

			again, err := core.ScanFile(core.ScanConfig{
				FilePath:            res.RedactedFilePath,
				EnablePreprocessors: true,
				Config:              cfg,
				LogWriter:           io.Discard,
			})
			if err != nil {
				t.Fatalf("re-scan: %v", err)
			}
			for _, m := range again.Matches {
				if before[key{m.Type, m.Text}] {
					t.Errorf("silent survivor: the redacted copy is reported again for %s (%d bytes), "+
						"exactly as before redaction", m.Type, len(m.Text))
				} else {
					t.Errorf("the redacted copy yields a %s finding of %d bytes (all mask: %v)",
						m.Type, len(m.Text), isAllMask(m.Text))
				}
			}
		})
	}
}

func isAllMask(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '*' {
			return false
		}
	}
	return true
}

// A legacy part embedded in a .docx is handed EVERY match the container found (office/embedded.go),
// so the body's values are in none of the part's streams. The "not found in any stream" refusal must
// not fire for them, or every .docx whose body and embedded .doc hold different values would be
// refused whole. The decoy: a body SSN and an embedded .doc carrying an email; both strategies write
// the container, and neither value is in the copy. On main this passes (main never refused a value it
// could not find); a version of this change without the provenance check refused the .docx.
func TestAContainersBodyValuesDoNotRefuseItsEmbeddedLegacyPart(t *testing.T) {
	const (
		ssn   = "449-87-4100"
		email = "jane.analyst@example.com"
	)
	doc := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: []byte("Contact " + email + " for the review.\r")},
	})
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, part := range []struct {
		name string
		data []byte
	}{
		{"[Content_Types].xml", []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="doc" ContentType="application/msword"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`)},
		{"_rels/.rels", []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`)},
		{"word/document.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Employee SSN ` + ssn + ` on file.</w:t></w:r></w:p></w:body></w:document>`)},
		{"word/embeddings/legacy.doc", doc},
	} {
		w, err := zw.Create(part.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(part.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "notes.docx")
	if err := os.WriteFile(src, zb.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, strategy := range []string{"simple", "format_preserving"} {
		t.Run(strategy, func(t *testing.T) {
			res, err := core.RedactFile(core.RedactConfig{
				FilePath:  src,
				OutputDir: filepath.Join(dir, "out-"+strategy),
				Strategy:  strategy,
				Checks:    []string{"SSN", "EMAIL"},
				Config:    config.LoadConfigOrDefault(""),
				LogWriter: io.Discard,
			})
			if err != nil {
				t.Fatalf("the container was refused: %v", err)
			}
			if res.RedactedFilePath == "" {
				t.Fatal("no redacted copy was written")
			}
			z, err := zip.OpenReader(res.RedactedFilePath)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			for _, f := range z.File {
				rc, err := f.Open()
				if err != nil {
					t.Fatal(err)
				}
				b, err := io.ReadAll(rc)
				_ = rc.Close()
				if err != nil {
					t.Fatal(err)
				}
				for _, v := range []string{ssn, email} {
					if bytes.Contains(b, []byte(v)) {
						t.Errorf("part %s of the copy still holds a reported value (%d bytes)", f.Name, len(v))
					}
				}
			}
		})
	}
}
