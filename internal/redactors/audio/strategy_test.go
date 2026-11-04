// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// What each strategy writes into an audio file (#863), asserted on the bytes of the output.
//
// These replace TestSyntheticStrategyIsDeclined, which read GetSupportedStrategies and nothing else.
// The list left synthetic out and the test passed, while synthetic was written as a mask and simple
// as format_preserving, byte-identical to it, in all four containers.

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

// m4aWithThreeTags writes ftyp + moov>udta>meta>ilst holding the three labelled values.
func m4aWithThreeTags(t *testing.T, dir string) string {
	t.Helper()
	atom := func(name string, payload []byte) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(8+len(payload)))
		out = append(out, []byte(name)...)
		return append(out, payload...)
	}
	tag := func(name, value string) []byte {
		return atom(name, atom("data", append([]byte{0, 0, 0, 1, 0, 0, 0, 0}, []byte(value)...)))
	}
	ilst := atom("ilst", bytes.Join([][]byte{
		tag("\xa9cmt", "Email "+strategyEmail),
		tag("\xa9ART", "Phone "+strategyPhone),
		tag("\xa9nam", "Card "+strategyCard),
	}, nil))
	moov := atom("moov", atom("udta", atom("meta", append([]byte{0, 0, 0, 0}, ilst...))))
	return writeFixture(t, dir, "labelled.m4a", append(atom("ftyp", []byte("M4A isom")), moov...))
}

// strategyFixtures builds the same three labelled values in each of the four containers.
func strategyFixtures(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	return map[string]string{
		"wav": buildWAV(t, dir, map[string]string{
			"ICMT": "Email " + strategyEmail, "IART": "Phone " + strategyPhone, "INAM": "Card " + strategyCard}),
		"mp3": buildMP3(t, dir, map[string]string{
			"COMM": "Email " + strategyEmail, "TPE1": "Phone " + strategyPhone, "TIT2": "Card " + strategyCard}),
		"flac": buildFLAC(t, dir, []string{
			"COMMENT=Email " + strategyEmail, "ARTIST=Phone " + strategyPhone, "TITLE=Card " + strategyCard}),
		"m4a": m4aWithThreeTags(t, dir),
	}
}

func redactUnder(t *testing.T, src string, matches []detector.Match, st redactors.RedactionStrategy) ([]byte, *redactors.RedactionResult, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "redacted"+filepath.Ext(src))
	res, err := NewAudioRedactor(nil, nil).RedactDocument(src, out, matches, st)
	if err != nil {
		return nil, nil, out, err
	}
	b, rerr := os.ReadFile(out) // #nosec G304 -- test temp dir
	if rerr != nil {
		t.Fatal(rerr)
	}
	return b, res, out, nil
}

// TestSimpleWritesAFullMaskOfEveryValue is the headline: simple keeps nothing of the value.
func TestSimpleWritesAFullMaskOfEveryValue(t *testing.T) {
	for name, src := range strategyFixtures(t) {
		t.Run(name, func(t *testing.T) {
			before, err := os.ReadFile(src) // #nosec G304 -- test temp dir
			if err != nil {
				t.Fatal(err)
			}
			after, res, _, err := redactUnder(t, src, strategyMatches(), redactors.RedactionSimple)
			if err != nil {
				t.Fatalf("simple: %v", err)
			}
			if len(after) != len(before) {
				t.Fatalf("size changed from %d to %d", len(before), len(after))
			}
			for label, v := range map[string]string{"Email ": strategyEmail, "Phone ": strategyPhone, "Card ": strategyCard} {
				if !bytes.Contains(after, []byte(label+strings.Repeat("*", len(v)))) {
					t.Errorf("simple: %q is not followed by a %d-byte mask", label, len(v))
				}
			}
			// The partials format_preserving keeps. Any one of them under simple is the defect.
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
	for name, src := range strategyFixtures(t) {
		t.Run(name, func(t *testing.T) {
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
	for name, src := range strategyFixtures(t) {
		t.Run(name, func(t *testing.T) {
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
	src := buildWAV(t, t.TempDir(), map[string]string{"INAM": "Synthetic Recording"})
	if _, _, _, err := redactUnder(t, src, nil, redactors.RedactionSynthetic); err != nil {
		t.Fatalf("a dispatch with no matches was refused: %v", err)
	}
}
