// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// residueFloor is the shortest surviving run of a labelled value that is worth
// counting. Below 4 bytes a "surviving run" is noise: a two-digit fragment of an
// SSN appears in ordinary text by chance.
const residueFloor = 4

// SinkOutcome measures what survives redaction.
//
// This is the metric a detection-only score cannot provide. Measured: reverting
// PR #250 (the Office redactor no-op) leaves the detection scorecard bit-for-bit
// identical while a labelled SSN survives verbatim inside word/document.xml.
// Detection said PASS on a shipped cleartext leak.
type SinkOutcome struct {
	// WholeLeak counts labels whose full value survives in the redacted artifact.
	// This is the hard-gated number: it is a cleartext leak, full stop.
	WholeLeak int
	// Residue4 sums the longest surviving contiguous run of each label's own bytes
	// (>= residueFloor). It is deliberately nonzero for format_preserving, which
	// keeps the last four digits by design (***-**-5728).
	//
	// It exists because "the byte is redacted either way" is measurably false when
	// two validators claim one span: the same NPI is masked to ********** under
	// MEDICAL_ID but only ******7893 under PHONE, the shipped default. Mask DEPTH
	// is a real product property and this is the only number that tracks it.
	Residue4 int
	// Labels is how many labels were actually exercised.
	Labels int
	// Skipped names cases with no registered redactor for their file type.
	Skipped []string
}

// longestResidue measures how much of a labelled value survives redaction, by
// comparing the redacted document against the ORIGINAL rather than scanning it in
// isolation.
//
// Scanning the output alone does not work, and the corpus proved it: for the email
// "alice.morgan@northwind-labs.com" in a CSV whose neighbouring column holds the
// name "A Morgan", a perfectly redacted document reported 5 bytes of residue — the
// substring "organ", from the name, which was never part of the value's cell and was
// never supposed to be redacted. Any substring of any value can occur innocently
// somewhere in a document, so an isolated scan measures coincidence, not leakage.
//
// The honest question is narrower: of the byte runs that DISAPPEARED from the
// original, how much of the value is still present at a position the original did
// not already have it? Implemented as a count comparison per candidate substring —
// a run only counts as surviving if it appears at least as often in the redacted
// output as it did outside the value's own occurrence in the original.
func longestResidue(value, original, out string) int {
	// Widest first: the first surviving width found is the longest.
	for n := len(value); n >= residueFloor; n-- {
		for i := 0; i+n <= len(value); i++ {
			sub := value[i : i+n]

			// How often does this run appear in the original OUTSIDE the value
			// itself? Those occurrences are innocent bystanders (a name in the next
			// column, a repeated word) and must not be counted as residue.
			innocent := strings.Count(strings.ReplaceAll(original, value, ""), sub)

			if strings.Count(out, sub) > innocent {
				return n
			}
		}
	}
	return 0
}

// longestResidueRaw is the naive isolated scan, retained ONLY so a test can prove
// the coincidence-filtering above actually changes the answer. Never use it for
// scoring.
func longestResidueRaw(value, out string) int {
	// Widest first, so the first hit found IS the longest surviving run and the
	// search can stop immediately.
	for n := len(value); n >= residueFloor; n-- {
		for i := 0; i+n <= len(value); i++ {
			if strings.Contains(out, value[i:i+n]) {
				return n
			}
		}
	}
	return 0
}

// sinkExtension picks the on-disk extension for a case.
//
// The FileRouter dispatches on extension, so a case harvested from a .csv must be
// written back as .csv or it takes a different code path than the one it is meant
// to cover.
func sinkExtension(name string) string {
	switch {
	case strings.Contains(name, "_tsv"):
		return ".tsv"
	case strings.Contains(name, "_html"):
		return ".html"
	case strings.Contains(name, "_sql"):
		return ".sql"
	case strings.Contains(name, "_json"):
		return ".json"
	case strings.Contains(name, "_yaml"):
		return ".yaml"
	case strings.Contains(name, "_xml"):
		return ".xml"
	case strings.Contains(name, "_md") || strings.Contains(name, "markdown"):
		return ".md"
	case strings.Contains(name, "_ini"):
		return ".ini"
	case strings.HasPrefix(name, "c") || strings.HasPrefix(name, "fp__") || strings.HasPrefix(name, "tp__"):
		return ".csv"
	default:
		return ".txt"
	}
}

// ScoreSink drives core.RedactFile for one strategy over every redactable
// labelled case and reports what survived.
//
// core.RedactFile is the file/container-aware entry point. pkg/redact is NOT used
// and must not be: it is in-memory single-content, so it cannot reach the
// container parts where the PR #250 class of leak lives. Measured: the same
// mutation leaks through core.RedactFile and is invisible through pkg/redact.
func ScoreSink(strategy string, dir string) (*SinkOutcome, error) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("load pure default config: %w", err)
	}

	out := &SinkOutcome{}

	for _, c := range GatedCases() {
		if len(c.Labels) == 0 {
			continue
		}
		if !c.Redactable {
			out.Skipped = append(out.Skipped, c.Name)
			continue
		}

		src := filepath.Join(dir, c.Name+sinkExtension(c.Name))
		if err := os.WriteFile(src, []byte(c.Input), 0o600); err != nil {
			return nil, fmt.Errorf("%s: write fixture: %w", c.Name, err)
		}

		outDir := filepath.Join(dir, "out", strategy, c.Name)
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			return nil, fmt.Errorf("%s: mkdir: %w", c.Name, err)
		}

		res, err := core.RedactFile(core.RedactConfig{
			FilePath:  src,
			OutputDir: outDir,
			Strategy:  strategy,
			Checks:    c.Checks,
			Config:    cfg,
			LogWriter: io.Discard,
		})
		if err != nil {
			return nil, fmt.Errorf("%s: redact: %w", c.Name, err)
		}

		body, err := os.ReadFile(res.RedactedFilePath) //nolint:gosec // path from RedactFile
		if err != nil {
			return nil, fmt.Errorf("%s: read redacted: %w", c.Name, err)
		}
		text := string(body)

		for _, lb := range c.Labels {
			out.Labels++
			if strings.Contains(text, lb.Value) {
				// The whole value survived. This is the leak, and it is what the
				// gate refuses outright.
				out.WholeLeak++
				continue
			}
			out.Residue4 += longestResidue(lb.Value, c.Input, text)
		}
	}

	sort.Strings(out.Skipped)
	return out, nil
}
