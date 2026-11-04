// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package video

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// What each strategy writes into a video file (#863), asserted on the bytes of the output.
//
// These replace TestSyntheticStrategyIsNotAdvertised, which read GetSupportedStrategies and nothing
// else. The list left synthetic out and the test passed, while synthetic was written as a mask and
// simple as format_preserving, byte-identical to it, on every extension.

// Synthetic values: a reserved-domain address, an unassignable NANP number (exchange 010) and a
// sequential card serial with its Luhn digit.
const (
	strategyEmail = "jane.doe@example.com"
	strategyPhone = "(555) 010-0199"
	strategyCard  = "4123456789012349"
)

func strategyMatches() []detector.Match {
	return []detector.Match{
		{Text: strategyEmail, Type: "EMAIL", Validator: "email", Confidence: 90},
		{Text: strategyPhone, Type: "PHONE", Validator: "phone", Confidence: 90},
		{Text: strategyCard, Type: "VISA", Validator: "creditcard", Confidence: 90},
	}
}

// strategyFixtures builds the three labelled values in udta>meta>ilst, once per claimed extension.
func strategyFixtures(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	out := map[string]string{}
	for _, ext := range []string{".mp4", ".m4v", ".mov", ".3gp", ".3g2"} {
		out[ext] = mp4With(t, dir, "labelled"+ext,
			atom("meta", []byte{0, 0, 0, 0}, atom("ilst",
				itunesTag("\xa9cmt", "Email "+strategyEmail),
				itunesTag("\xa9ART", "Phone "+strategyPhone),
				itunesTag("\xa9nam", "Card "+strategyCard))))
	}
	return out
}

func redactUnder(t *testing.T, src string, matches []detector.Match, st redactors.RedactionStrategy) ([]byte, *redactors.RedactionResult, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "redacted"+filepath.Ext(src))
	res, err := NewVideoRedactor(nil, nil).RedactDocument(src, out, matches, st)
	if err != nil {
		return nil, nil, out, err
	}
	return mustRead(t, out), res, out, nil
}

// TestSimpleWritesAFullMaskOfEveryValue is the headline: simple keeps nothing of the value.
func TestSimpleWritesAFullMaskOfEveryValue(t *testing.T) {
	for ext, src := range strategyFixtures(t) {
		t.Run(ext, func(t *testing.T) {
			after, res, _, err := redactUnder(t, src, strategyMatches(), redactors.RedactionSimple)
			if err != nil {
				t.Fatalf("simple: %v", err)
			}
			if len(after) != len(mustRead(t, src)) {
				t.Fatal("size changed")
			}
			for label, v := range map[string]string{"Email ": strategyEmail, "Phone ": strategyPhone, "Card ": strategyCard} {
				if !bytes.Contains(after, []byte(label+strings.Repeat("*", len(v)))) {
					t.Errorf("simple: %q is not followed by a %d-byte mask", label, len(v))
				}
			}
			for _, kept := range []string{"2349", "@example.com", "0199"} {
				if bytes.Contains(after, []byte(kept)) {
					t.Errorf("simple: %q survives; simple promises nothing of the value is kept", kept)
				}
			}
			if len(res.RedactionMap) != 3 {
				t.Fatalf("RedactionMap has %d entries, want 3", len(res.RedactionMap))
			}
			for _, m := range res.RedactionMap {
				if strings.Trim(m.RedactedText, "*") != "" {
					t.Errorf("simple: mapping for %s records %q, which is not the mask that was written",
						m.DataType, m.RedactedText)
				}
			}
		})
	}
}

// TestFormatPreservingIsUnchanged pins the default's bytes: the fix moves simple and synthetic only.
func TestFormatPreservingIsUnchanged(t *testing.T) {
	for ext, src := range strategyFixtures(t) {
		t.Run(ext, func(t *testing.T) {
			after, _, _, err := redactUnder(t, src, strategyMatches(), redactors.RedactionFormatPreserving)
			if err != nil {
				t.Fatalf("format_preserving: %v", err)
			}
			for _, want := range []string{"Email j*******@example.com", "Phone (***) ***-0199", "Card ************2349"} {
				if !bytes.Contains(after, []byte(want)) {
					t.Errorf("format_preserving: %q not written", want)
				}
			}
		})
	}
}

// TestSyntheticIsRefusedAndWritesNothing: the declaration is enforced, so the run can disclose the
// file instead of writing a mask under the name synthetic.
func TestSyntheticIsRefusedAndWritesNothing(t *testing.T) {
	for ext, src := range strategyFixtures(t) {
		t.Run(ext, func(t *testing.T) {
			_, res, out, err := redactUnder(t, src, strategyMatches(), redactors.RedactionSynthetic)
			if !errors.Is(err, redactors.ErrStrategyNotSupported) {
				t.Fatalf("synthetic: err = %v, want ErrStrategyNotSupported", err)
			}
			if res != nil {
				t.Errorf("synthetic: a result was returned beside the refusal: %+v", res)
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Errorf("synthetic: an output file exists after the refusal (stat: %v)", statErr)
			}
			for _, want := range []string{"synthetic", "simple and format_preserving"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("synthetic: refusal %q does not name %q", err, want)
				}
			}
		})
	}
}

// TestSyntheticWithNothingToRedactIsNotRefused: the gate fires only on a dispatch that carries a
// match, so a clean or fully suppressed file is never reported as unredacted.
func TestSyntheticWithNothingToRedactIsNotRefused(t *testing.T) {
	src := mp4With(t, t.TempDir(), "clean.mp4", atom("meta", []byte{0, 0, 0, 0}, atom("ilst",
		itunesTag("\xa9nam", "Synthetic Recording"))))
	if _, _, _, err := redactUnder(t, src, nil, redactors.RedactionSynthetic); err != nil {
		t.Fatalf("a dispatch with no matches was refused: %v", err)
	}
}
