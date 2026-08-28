// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// Band names a confidence tier. The thresholds are not redefined here: band()
// delegates to shared.GetConfidenceLevel so the gate cannot silently disagree
// with the product after a threshold change (TestBandsMatchShared pins this at
// the 60 and 90 boundaries).
type Band string

const (
	BandLow    Band = "LOW"
	BandMedium Band = "MEDIUM"
	BandHigh   Band = "HIGH"
)

// minLabelBytes is the floor on how short a reported value may be and still
// count as covering a label.
//
// TP matching is substring-based in both directions, because a validator may
// legitimately report a wider or narrower span than the label (a trailing period,
// a surrounding quote). Unbounded, that rule is exploitable: a validator reporting
// the single byte "-" would "cover" every hyphenated SSN and score a perfect
// recall. The shortest label in the corpus is 9 bytes, so a floor of 8 costs
// nothing — measured, strict-only matching and bidirectional matching both yield
// 111 TP — while making the degenerate case impossible.
const minLabelBytes = 8

// Label is one thing that must be found, keyed by (line, value, occurrence).
//
// There is deliberately no byte span, because detector.Match has no offset field
// at all — only LineNumber. Span-keyed truth would therefore have to be
// reconstructed by re-searching the line, which is ambiguous exactly when it
// matters (a value repeated on one line). TestValueOccursOnce asserts the
// corpus-wide invariant that makes the line+value key sufficient, and fails loudly
// the day a case violates it rather than silently mis-attributing a finding.
type Label struct {
	// Line is 1-based and compared against detector.Match.LineNumber.
	Line int
	// Value is the exact bytes planted in Input at Line. Ground truth comes from
	// the fixture's own content, never from what the scanner currently reports.
	Value string
	// Occurrence is the 1-based nth occurrence on that line; 0 means 1.
	Occurrence int
	// Types is the set of acceptable detector.Match.Type values (sub-types, e.g.
	// VISA vs CREDIT_CARD). Membership, not equality, so a validator may refine
	// its classification without breaking the corpus.
	Types []string
	// MinBand is the weakest acceptable band. BandLow means "must be reported at
	// all" — the redaction floor, since redaction ignores confidence.
	MinBand Band
}

func (l Label) occurrence() int {
	if l.Occurrence <= 0 {
		return 1
	}
	return 1
}

// Case is one labelled in-memory document.
type Case struct {
	// Name is the subtest name and the fixture stem it was harvested from.
	Name string
	// Origin records provenance so a suspect label can be traced.
	Origin string
	// Rationale says WHY this shape must behave this way, in user terms. A label
	// with no stated reason is unreviewable.
	Rationale string
	// Checks is validated against core.CheckNames(); never empty, never "all".
	// An unknown name fails OPEN in the scanner (measured: err=nil, 0 matches),
	// which would score precision 1.000 over an empty numerator.
	Checks []string
	// Input is the exact document bytes.
	Input string
	// Labels is what must be found. Empty plus Negative means every finding here
	// is a false positive.
	Labels []Label
	// Negative marks a case where nothing should be reported.
	Negative bool
	// Redactable is false for a file type with no registered redactor, so the sink metric
	// skips it rather than recording a fake leak.
	//
	// NO CASE SETS THIS FALSE TODAY, and the doc used to name .tsv, .html and .sql as though
	// they were permanently unredactable. They are not: PR #359 (2a0e96c) made
	// GetRedactorForFile fall back to the same preprocessors.LooksLikeText sniff the router
	// uses to admit a file, so scan admission and redact admission agree by construction and
	// any file whose bytes are text gets a redactor. The four cases carrying this flag were
	// therefore excluded from the sink gate for a reason that had stopped being true (#315).
	//
	// The field is kept rather than deleted because the capability boundary is real — .odt /
	// .ods / .odp still have no redactor (#514), and a PDF fixture would need this too. It is
	// no longer allowed to be silently true-by-accident:
	// TestTheSinkGateCoversEveryLabelledCase asserts the skip list is empty, so marking a case
	// unredactable is a deliberate act that has to be justified rather than a default that
	// quietly removes it from the leak gate.
	Redactable bool
}

// Outcome is the scorecard for one check.
type Outcome struct {
	TP       int // labels satisfied at or above MinBand
	TPBanded int // labels satisfied at >= MEDIUM (the pre-commit surface)
	FNMissed int // labels with no finding at all: a cleartext leak
	FNBand   int // labels found, but below MinBand
	FPHigh   int // unlabelled findings at >= MEDIUM
	FPLow    int // unlabelled findings below MEDIUM
	Extra    int // additional findings on an already-satisfied label (unscored)
}

// Scorecard is the whole run.
type Scorecard struct {
	ByCheck map[string]*Outcome
	Total   Outcome

	Undecided struct {
		Cases, Findings int
	}

	Cases  int
	Labels int

	// Misses and BandDrops name the failing labels, payload-free.
	Misses    []string
	BandDrops []string
}

func band(confidence float64) Band {
	return Band(strings.ToUpper(shared.GetConfidenceLevel(confidence)))
}

// atLeast reports whether got is no weaker than want.
func atLeast(got, want Band) bool {
	rank := map[Band]int{BandLow: 1, BandMedium: 2, BandHigh: 3}
	return rank[got] >= rank[want]
}

// covers reports whether a reported value can be credited to a label.
//
// Either direction is accepted (the validator may include a trailing period, or
// stop short of a surrounding quote), subject to minLabelBytes so a degenerate
// one-byte report cannot claim a TP.
func covers(reported, label string) bool {
	if len(reported) < minLabelBytes {
		return false
	}
	return strings.Contains(reported, label) || strings.Contains(label, reported)
}

func typeAllowed(got string, allowed []string) bool {
	for _, a := range allowed {
		if got == a {
			return true
		}
	}
	return false
}

// scanConfig builds the scan configuration.
//
// Config is config.LoadConfig(""), the PURE default — deliberately not
// LoadConfigOrDefault(""), which discovers ~/.ferret-scan/config.yaml and made
// the enabled-validator count depend on the developer's home directory (measured:
// 2 validators vs 0). SuppressionManager is nil for the same reason:
// NewSuppressionManager("") reads the user's suppression file, so a local
// suppression could silently delete a labelled finding and read as a regression.
// ValidatorBudgets is nil because a budget makes results partial and flaky.
// VirtualPath deliberately carries the fixture's EXTENSION, because the extension
// is itself a scoring input: context/analyzer.go classifies a document type from
// the filename, and a CSV classification is worth a confidence boost. Measured on
// byte-identical content, changing only the virtual path:
//
//	c13_two_field_only        -> 55 / 60      c13_two_field_only.csv        -> 75 / 80
//	c37_excel_semicolon_crlf  -> 70 (MEDIUM)  c37_excel_semicolon_crlf.csv  -> 90 (HIGH)
//
// An extensionless path therefore scores a .csv fixture two bands low and the
// corpus would have recorded a band drop that no user ever sees. Using the real
// extension keeps this harness on the same code path as the CLI (verified: the
// labels' bands now match `ferret-scan --file <fixture>` exactly).
func scanConfig(c Case, cfg *config.Config) core.ContentScanConfig {
	return core.ContentScanConfig{
		VirtualPath:        c.Name + sinkExtension(c.Name),
		Checks:             c.Checks,
		Config:             cfg,
		LogWriter:          io.Discard,
		SuppressionManager: nil,
		ValidatorBudgets:   nil,
	}
}

// canonical orders matches deterministically.
//
// This is scorecorpus's own copy rather than goldencorpus.CanonicalSort, so this
// package imports nothing from goldencorpus: a rename there cannot produce a
// merge that is textually clean and does not compile.
func canonical(in []detector.Match) []detector.Match {
	out := make([]detector.Match, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Text != b.Text {
			return a.Text < b.Text
		}
		return a.Confidence > b.Confidence
	})
	return out
}

// ScoreCase scores one case.
func ScoreCase(c Case, cfg *config.Config) (*Outcome, []string, []string, error) {
	res, err := core.ScanContent(c.Input, scanConfig(c, cfg))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: scan: %w", c.Name, err)
	}
	if res.Incomplete {
		// "Did not finish scanning" must never be scored as "scanned clean".
		return nil, nil, nil, fmt.Errorf("%s: scan incomplete: %s", c.Name, res.IncompleteReason)
	}

	matches := canonical(res.Matches)
	out := &Outcome{}
	var misses, drops []string

	// consumed[i] marks match i as already credited to a label, so one finding
	// can never satisfy two labels and a second finding on a satisfied label is
	// counted as Extra rather than as an FP.
	consumed := make([]bool, len(matches))

	for _, lb := range c.Labels {
		best := -1
		for i, m := range matches {
			if consumed[i] || m.LineNumber != lb.Line {
				continue
			}
			if !covers(m.Text, lb.Value) || !typeAllowed(m.Type, lb.Types) {
				continue
			}
			// Prefer the strongest band so a label is not failed by a weak
			// duplicate when a strong finding is also present.
			if best < 0 || matches[i].Confidence > matches[best].Confidence {
				best = i
			}
		}

		if best < 0 {
			out.FNMissed++
			misses = append(misses,
				fmt.Sprintf("%s line %d %s expected >=%s, got NONE",
					c.Name, lb.Line, strings.Join(lb.Types, "|"), lb.MinBand))
			continue
		}

		consumed[best] = true
		got := band(matches[best].Confidence)

		if !atLeast(got, lb.MinBand) {
			out.FNBand++
			drops = append(drops,
				fmt.Sprintf("%s line %d %s expected >=%s, got %s",
					c.Name, lb.Line, strings.Join(lb.Types, "|"), lb.MinBand, got))
		} else {
			out.TP++
		}
		if atLeast(got, BandMedium) {
			out.TPBanded++
		}
	}

	// Everything not credited to a label is either a false positive or an extra
	// claim on a line that already has one.
	for i, m := range matches {
		if consumed[i] {
			continue
		}
		if labelOnLine(c, m) {
			out.Extra++
			continue
		}
		if atLeast(band(m.Confidence), BandMedium) {
			out.FPHigh++
		} else {
			out.FPLow++
		}
	}

	return out, misses, drops, nil
}

// labelOnLine reports whether a match lands on a line that carries a label whose
// value it overlaps — i.e. a second claim on the same value rather than a new FP.
//
// Same-span duplicates are counted separately and not scored, because there is no
// arbitration layer to prefer one validator over another. The tempting
// justification "redaction covers the byte anyway" is measurably FALSE: the same
// NPI redacts to ********** under MEDICAL_ID but ******7893 under PHONE, the
// shipped default. Residue4 is what makes that consequence visible.
func labelOnLine(c Case, m detector.Match) bool {
	for _, lb := range c.Labels {
		if lb.Line == m.LineNumber && covers(m.Text, lb.Value) {
			return true
		}
	}
	return false
}

// Score runs the whole corpus.
func Score() (*Scorecard, error) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("load pure default config: %w", err)
	}

	sc := &Scorecard{ByCheck: map[string]*Outcome{}}

	for _, c := range GatedCases() {
		out, misses, drops, err := ScoreCase(c, cfg)
		if err != nil {
			return nil, err
		}
		sc.Cases++
		sc.Labels += len(c.Labels)
		sc.Misses = append(sc.Misses, misses...)
		sc.BandDrops = append(sc.BandDrops, drops...)

		for _, ck := range c.Checks {
			agg, ok := sc.ByCheck[ck]
			if !ok {
				agg = &Outcome{}
				sc.ByCheck[ck] = agg
			}
			agg.TP += out.TP
			agg.TPBanded += out.TPBanded
			agg.FNMissed += out.FNMissed
			agg.FNBand += out.FNBand
			agg.FPHigh += out.FPHigh
			agg.FPLow += out.FPLow
			agg.Extra += out.Extra
		}
	}

	for _, o := range sc.ByCheck {
		sc.Total.TP += o.TP
		sc.Total.TPBanded += o.TPBanded
		sc.Total.FNMissed += o.FNMissed
		sc.Total.FNBand += o.FNBand
		sc.Total.FPHigh += o.FPHigh
		sc.Total.FPLow += o.FPLow
		sc.Total.Extra += o.Extra
	}

	// The quarantined cases are counted but never scored: their polarity is a
	// product decision (is a Canadian SIN under an honest "sin" header a hit for
	// a US-SSN validator?). Counting them keeps the hatch from becoming a silent
	// laundering channel — moving a case in or out changes a baselined integer.
	for _, c := range QuarantinedCases() {
		res, err := core.ScanContent(c.Input, scanConfig(c, cfg))
		if err != nil {
			return nil, fmt.Errorf("%s (undecided): %w", c.Name, err)
		}
		sc.Undecided.Cases++
		sc.Undecided.Findings += len(res.Matches)
	}

	return sc, nil
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1
	}
	return float64(num) / float64(den)
}

// RecallAll is the redaction surface: every band counts.
func (o Outcome) RecallAll() float64 { return ratio(o.TP+o.FNBand, o.TP+o.FNBand+o.FNMissed) }

// RecallHM is the pre-commit exit-code surface: >= MEDIUM only.
func (o Outcome) RecallHM() float64 { return ratio(o.TPBanded, o.TP+o.FNBand+o.FNMissed) }

// PrecisionHM is precision over findings that reach the default review surface.
func (o Outcome) PrecisionHM() float64 { return ratio(o.TPBanded, o.TPBanded+o.FPHigh) }

// Render writes the human-readable scorecard.
func (s *Scorecard) Render(w io.Writer) {
	fmt.Fprintf(w, "scorecorpus  %d cases, %d gated labels, %d check(s)\n\n", s.Cases, s.Labels, len(s.ByCheck))
	fmt.Fprintf(w, "%-8s %4s %9s %9s %8s %8s %11s %10s %8s\n",
		"check", "TP", "FN(miss)", "FN(band)", "FP(H+M)", "FP(low)", "recall_all", "recall_hm", "prec_hm")

	names := make([]string, 0, len(s.ByCheck))
	for k := range s.ByCheck {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, n := range names {
		o := s.ByCheck[n]
		fmt.Fprintf(w, "%-8s %4d %9d %9d %8d %8d %11.4f %10.4f %8.4f\n",
			n, o.TP, o.FNMissed, o.FNBand, o.FPHigh, o.FPLow,
			o.RecallAll(), o.RecallHM(), o.PrecisionHM())
	}

	t := s.Total
	fmt.Fprintf(w, "%-8s %4d %9d %9d %8d %8d %11.4f %10.4f %8.4f\n",
		"TOTAL", t.TP, t.FNMissed, t.FNBand, t.FPHigh, t.FPLow,
		t.RecallAll(), t.RecallHM(), t.PrecisionHM())

	fmt.Fprintf(w, "\nnot gated, baselined:  extra_same_span %d   undecided %d cases / %d findings\n",
		t.Extra, s.Undecided.Cases, s.Undecided.Findings)
}
