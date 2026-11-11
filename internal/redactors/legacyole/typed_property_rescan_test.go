// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole_test

import (
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
