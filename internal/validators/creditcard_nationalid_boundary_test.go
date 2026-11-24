// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/nationalid"
)

// The creditcard / NATIONAL_ID boundary contract (#905 box 8).
//
// creditcard reports 13-19 digit Luhn-valid runs; nationalid reports a CPF (11 digits), CUIL (11), SIN
// (9) and others only BESIDE their own label. A digit run can be shaped for both, and nothing arbitrates
// between two validators that claim the same bytes at report time, so the split has to be a property of
// the two validators that a change to either cannot move silently. The contract:
//
//  1. A card-shaped run (15/16 digits, Luhn-valid) under a CPF, CUIL or SIN label belongs to creditcard.
//     The label does not turn it into a national ID: the national-ID shapes are 9 or 11 digits, and a
//     match glued to further digits is not a token (nationalid.standsAlone), including when the card
//     starts with a value that passes the CPF or SIN check.
//  2. A CPF, CUIL or SIN printed digit-only beside a CARD label belongs to nobody: nationalid needs its
//     OWN label, and creditcard needs 13-19 digits. When both labels are present each validator reports
//     its own span and the spans are disjoint.
//  3. The four track frames (Track 1, Track 2, URL-encoded Track 2, EMV tag 57) are the cited exceptions:
//     creditcard owns the whole frame as CARD_TRACK_DATA at 100 and reports the PAN inside it as a brand
//     finding at 75 (#905 box 2: accepted at 75, the frame carries the redaction at 100). Those two
//     findings share bytes by design and both come from creditcard. A national-ID label in front of the
//     frame does not produce a NATIONAL_ID.
//
// It drives the real document bridge with the two real validators, so what is asserted is what a scan
// reports. internal/core cannot be imported here (it imports this package); the two constructors are the
// ones core's validatorConstructors holds for CREDIT_CARD and NATIONAL_ID.

// The validator names a finding carries in Match.Validator (not the check names).
const (
	vCard = "creditcard"
	vNID  = "nationalid"
)

// Fixture values. Every one passes its own check; none is a published test card.
const (
	bndVisa16   = "4532061358952548"
	bndAmex15   = "375597297926224"
	bndCPF      = "52998224725"
	bndCUIL     = "20123456786"
	bndSIN      = "490810033"
	bndVisaSIN  = "4908100339345145" // Luhn-valid Visa whose first nine digits are a valid SIN
	bndMCCPF    = "5299822472583679" // Luhn-valid Mastercard whose first eleven digits are a valid CPF
	bndCUILCard = "2012345678690075" // Luhn-valid 16 digits whose first eleven digits are a valid CUIL
	bndTrailer  = "25121010000000000000"
)

// bndFinding is one expected finding: the validator that reported it, its type, the exact text and the
// 1-based line. Conf is pinned only where the contract is about the score (the frames); 0 means unpinned.
type bndFinding struct {
	validator string
	typ       string
	text      string
	line      int
	conf      float64
	frame     string
}

type bndRow struct {
	name string
	text string
	want []bndFinding
	// frameRow marks a track frame, the one place two findings may share bytes (both creditcard's).
	frameRow bool
}

func card(typ, text string, line int) bndFinding {
	return bndFinding{validator: vCard, typ: typ, text: text, line: line}
}
func nid(typ, text string, line int) bndFinding {
	return bndFinding{validator: vNID, typ: typ, text: text, line: line}
}

// frameWant builds the two creditcard findings a track frame gives: the frame at 100 and the PAN at 75.
func frameWant(frameText, frame string) []bndFinding {
	return []bndFinding{
		{validator: vCard, typ: "CARD_TRACK_DATA", text: frameText, line: 1, conf: 100, frame: frame},
		{validator: vCard, typ: "VISA", text: bndVisa16, line: 1, conf: 75},
	}
}

func boundaryRows() []bndRow {
	spaced := bndVisa16[:4] + " " + bndVisa16[4:8] + " " + bndVisa16[8:12] + " " + bndVisa16[12:]
	dashed := strings.ReplaceAll(spaced, " ", "-")
	track1 := "%B" + bndVisa16 + "^PUBLIC/JOHN Q^" + bndTrailer + "?"
	track2 := ";" + bndVisa16 + "=" + bndTrailer + "?"
	urlTrack2 := "%3B" + bndVisa16 + "%3D" + bndTrailer + "%3F"
	emvLine := "9F1F14 5710" + bndVisa16 + "D" + bndTrailer + "F"
	emvFrame := bndVisa16 + "D" + bndTrailer[:15]

	return []bndRow{
		// 1. A card under a national-ID label: creditcard only.
		{name: "card16 under CPF", text: "CPF: " + bndVisa16, want: []bndFinding{card("VISA", bndVisa16, 1)}},
		{name: "card16 under CPF with ordinal", text: "CPF nº " + bndVisa16, want: []bndFinding{card("VISA", bndVisa16, 1)}},
		{name: "card16 under CUIL", text: "CUIL: " + bndVisa16, want: []bndFinding{card("VISA", bndVisa16, 1)}},
		{name: "card16 under CUIT", text: "CUIT: " + bndVisa16, want: []bndFinding{card("VISA", bndVisa16, 1)}},
		{name: "card15 under SIN", text: "SIN: " + bndAmex15, want: []bndFinding{card("AMERICAN_EXPRESS", bndAmex15, 1)}},
		{name: "card15 under CPF", text: "CPF: " + bndAmex15, want: []bndFinding{card("AMERICAN_EXPRESS", bndAmex15, 1)}},
		{name: "card15 under long-form SIN label", text: "Social Insurance Number: " + bndAmex15, want: []bndFinding{card("AMERICAN_EXPRESS", bndAmex15, 1)}},
		{name: "card16 under long-form CPF label", text: "Cadastro de Pessoas Físicas: " + bndVisa16, want: []bndFinding{card("VISA", bndVisa16, 1)}},
		{name: "card16 spaced under SIN", text: "SIN " + spaced, want: []bndFinding{card("VISA", spaced, 1)}},
		{name: "card16 dashed under SIN", text: "SIN: " + dashed, want: []bndFinding{card("VISA", dashed, 1)}},
		// 1b. A card whose leading digits pass a national-ID check: the glued digits keep it a card.
		{name: "card whose first 9 digits are a valid SIN, under SIN", text: "SIN: " + bndVisaSIN, want: []bndFinding{card("VISA", bndVisaSIN, 1)}},
		{name: "card whose first 11 digits are a valid CPF, under CPF", text: "CPF: " + bndMCCPF, want: []bndFinding{card("MASTERCARD", bndMCCPF, 1)}},
		{name: "16 digits whose first 11 are a valid CUIL, under CUIL", text: "CUIL: " + bndCUILCard, want: []bndFinding{card("CREDIT_CARD", bndCUILCard, 1)}},

		// 2. A national ID digit-only beside a card label: nobody reports it.
		{name: "CPF digits under a card label", text: "Card: " + bndCPF, want: nil},
		{name: "CUIL digits under a credit card label", text: "Credit card number: " + bndCUIL, want: nil},
		{name: "SIN digits under a card label", text: "Card number: " + bndSIN, want: nil},
		{name: "SIN dashed under a card label", text: "Card: " + bndSIN[:3] + "-" + bndSIN[3:6] + "-" + bndSIN[6:], want: nil},
		{name: "CPF dotted under a card label", text: "Card: " + bndCPF[:3] + "." + bndCPF[3:6] + "." + bndCPF[6:9] + "-" + bndCPF[9:], want: nil},
		{name: "CPF digits beside a brand word", text: "Visa " + bndCPF, want: nil},

		// 2b. Both labels on one line or in one file: each validator reports its own span, disjoint.
		{name: "card then CPF, one line", text: "Card " + bndVisa16 + " CPF " + bndCPF,
			want: []bndFinding{card("VISA", bndVisa16, 1), nid("BR_CPF", bndCPF, 1)}},
		{name: "CPF then card, one line", text: "CPF " + bndCPF + " card " + bndVisa16,
			want: []bndFinding{card("VISA", bndVisa16, 1), nid("BR_CPF", bndCPF, 1)}},
		{name: "CPF line then card line", text: "CPF: " + bndCPF + "\nCard: " + bndVisa16,
			want: []bndFinding{nid("BR_CPF", bndCPF, 1), card("VISA", bndVisa16, 2)}},
		{name: "CUIL then card, dashed CUIL", text: "CUIL 20-12345678-6 card " + bndVisa16,
			want: []bndFinding{card("VISA", bndVisa16, 1), nid("AR_CUIL", "20-12345678-6", 1)}},
		{name: "SIN then card, SIN not Luhn-claimed by the card", text: "SIN " + bndSIN + " Visa " + bndAmex15,
			want: []bndFinding{nid("CA_SIN", bndSIN, 1), card("AMERICAN_EXPRESS", bndAmex15, 1)}},
		{name: "labelled CPF alone is the national ID's", text: "CPF: " + bndCPF, want: []bndFinding{nid("BR_CPF", bndCPF, 1)}},
		{name: "labelled CUIL alone is the national ID's", text: "CUIL: " + bndCUIL, want: []bndFinding{nid("AR_CUIL", bndCUIL, 1)}},
		{name: "labelled SIN alone is the national ID's", text: "SIN: " + bndSIN, want: []bndFinding{nid("CA_SIN", bndSIN, 1)}},

		// 3. The four track frames: creditcard owns the frame (CARD_TRACK_DATA 100) and the PAN (75).
		{name: "frame Track 1", text: track1, want: frameWant(track1, "track1"), frameRow: true},
		{name: "frame Track 2", text: track2, want: frameWant(track2, "track2"), frameRow: true},
		{name: "frame Track 2 URL-encoded", text: urlTrack2, want: frameWant(urlTrack2, "track2"), frameRow: true},
		{name: "frame EMV tag 57", text: emvLine, want: frameWant(emvFrame, "emv57"), frameRow: true},
		// 3b. A national-ID label in front of a frame does not make it a NATIONAL_ID.
		{name: "frame Track 1 under CPF", text: "CPF: " + track1, want: frameWant(track1, "track1"), frameRow: true},
		{name: "frame Track 2 under CUIL", text: "CUIL: " + track2, want: frameWant(track2, "track2"), frameRow: true},
		{name: "frame URL-encoded Track 2 under SIN", text: "SIN: " + urlTrack2, want: frameWant(urlTrack2, "track2"), frameRow: true},
		{name: "frame EMV tag 57 under CPF", text: "CPF: " + emvLine, want: frameWant(emvFrame, "emv57"), frameRow: true},
	}
}

// boundaryDetector is the real facade with the two real validators registered the way a scan does.
func boundaryDetector(t *testing.T) *Detector {
	t.Helper()
	d := NewDetector(nil)
	if err := d.SetupValidators(map[string]detector.Validator{
		vCard: creditcard.NewValidator(),
		vNID:  nationalid.NewValidator(),
	}); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}
	return d
}

func bndKey(f bndFinding) string {
	return fmt.Sprintf("L%d %s/%s %q", f.line, f.validator, f.typ, f.text)
}

func bndSorted(in []bndFinding) []bndFinding {
	out := append([]bndFinding(nil), in...)
	sort.Slice(out, func(i, j int) bool { return bndKey(out[i]) < bndKey(out[j]) })
	return out
}

// bndSpan is the byte span of a finding's text inside its line.
func bndSpan(text string, f bndFinding) (start, end int, ok bool) {
	lines := strings.Split(text, "\n")
	if f.line < 1 || f.line > len(lines) {
		return 0, 0, false
	}
	i := strings.Index(lines[f.line-1], f.text)
	if i < 0 {
		return 0, 0, false
	}
	return i, i + len(f.text), true
}

func TestCreditCardNationalIDBoundary(t *testing.T) {
	d := boundaryDetector(t)
	for _, row := range boundaryRows() {
		t.Run(row.name, func(t *testing.T) {
			matches, err := d.ValidateContent(row.text, "boundary.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			got := make([]bndFinding, 0, len(matches))
			for _, m := range matches {
				frame, _ := m.Metadata["card_frame"].(string)
				got = append(got, bndFinding{validator: m.Validator, typ: m.Type, text: m.Text, line: m.LineNumber, conf: m.Confidence, frame: frame})
			}
			got, want := bndSorted(got), bndSorted(row.want)

			var gk, wk []string
			for _, f := range got {
				gk = append(gk, bndKey(f))
			}
			for _, f := range want {
				wk = append(wk, bndKey(f))
			}
			if strings.Join(gk, "\n") != strings.Join(wk, "\n") {
				t.Fatalf("input %q\nreported:\n  %s\nwant:\n  %s", row.text, strings.Join(gk, "\n  "), strings.Join(wk, "\n  "))
			}
			// The score and the frame kind are pinned where the contract is about them.
			for i := range want {
				if want[i].conf != 0 && got[i].conf != want[i].conf {
					t.Errorf("%s: confidence %v, want %v", bndKey(got[i]), got[i].conf, want[i].conf)
				}
				if want[i].frame != "" && got[i].frame != want[i].frame {
					t.Errorf("%s: card_frame %q, want %q", bndKey(got[i]), got[i].frame, want[i].frame)
				}
			}

			// Neither validator double-reports a span. Two findings may share bytes only when both are
			// creditcard's and the row is a track frame: the frame and the PAN inside it.
			for i := range got {
				for j := i + 1; j < len(got); j++ {
					if got[i].line != got[j].line {
						continue
					}
					si, ei, ok1 := bndSpan(row.text, got[i])
					sj, ej, ok2 := bndSpan(row.text, got[j])
					if !ok1 || !ok2 || ei <= sj || ej <= si {
						continue
					}
					if row.frameRow && got[i].validator == vCard && got[j].validator == vCard {
						continue
					}
					t.Errorf("double report: %s and %s share bytes %d-%d / %d-%d", bndKey(got[i]), bndKey(got[j]), si, ei, sj, ej)
				}
			}
			if row.frameRow {
				for _, f := range got {
					if f.validator == vNID {
						t.Errorf("a track frame produced %s; creditcard owns the frame", bndKey(f))
					}
				}
			}
		})
	}
}

// TestCreditCardNationalIDBoundaryCitesAllFourFrames keeps the exception list honest: the four frames
// #905 names (Track 1, Track 2, URL-encoded Track 2, EMV tag 57) are each a row, bare and under a
// national-ID label, and the three card_frame kinds they produce are each seen.
func TestCreditCardNationalIDBoundaryCitesAllFourFrames(t *testing.T) {
	d := boundaryDetector(t)
	rows, kinds := 0, map[string]int{}
	for _, row := range boundaryRows() {
		if !row.frameRow {
			continue
		}
		rows++
		matches, err := d.ValidateContent(row.text, "boundary.txt")
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		for _, m := range matches {
			if k, _ := m.Metadata["card_frame"].(string); k != "" {
				kinds[k]++
			}
		}
	}
	if rows != 8 {
		t.Errorf("%d frame rows, want 8 (four frames, each bare and under a national-ID label)", rows)
	}
	// Track 1 twice, Track 2 four times (plain and URL-encoded, bare and labelled), EMV twice.
	want := map[string]int{"track1": 2, "track2": 4, "emv57": 2}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("card_frame %q seen %d times, want %d (all kinds seen: %v)", k, kinds[k], n, kinds)
		}
	}
}
