// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #905: a labelled card security code was only a keyword, so no shape of it was reported. It is now
// a CREDIT_CARD finding with Metadata["card_frame"] = "security_code" whose Text runs from the label
// to the value's last digit. Like frames_test.go, this file uses only what main also has, so it
// compiles against main and fails there by assertion.

// control is the issue's control card, on a line of its own.
const control = "Card number: 2221001234567896"

// codesOf returns the security-code findings.
func codesOf(ms []detector.Match) []detector.Match {
	var out []detector.Match
	for _, m := range ms {
		if m.Metadata["card_frame"] == "security_code" {
			out = append(out, m)
		}
	}
	return out
}

// oneCode scans content and returns its only security-code finding.
func oneCode(t *testing.T, content string) detector.Match {
	t.Helper()
	codes := codesOf(scan(t, content))
	if len(codes) != 1 {
		t.Fatalf("%q: want exactly one security code, got %+v", content, codes)
	}
	return codes[0]
}

// TestTheIssuesCodeShapes is the acceptance criterion over the issue's 13 code files and its
// `Valid thru` file, each followed by the control card on the next line.
func TestTheIssuesCodeShapes(t *testing.T) {
	for _, tc := range []struct {
		name, content, text string // text "" = no code finding
	}{
		{"cvv_inline", "Card: 4000 0012 3456 7899 Exp: 12/28 CVV: 123", "CVV: 123"},
		{"cvv_kv", "card=" + visa16 + " exp=1228 cvv=123", "cvv=123"},
		{"cvv_json", `{"card_number": "` + visa16 + `", "exp_month": "12", "exp_year": "2028", "cvv": "123"}`, `cvv": "123`},
		{"cvv_form_multiline", "Card number: 4000 0012 3456 7899\nExpiry: 12/28\nCVV: 123", "CVV: 123"},
		{"cvv_amex_cid", "Amex 3700 001234 56784 exp 12/28 CID 1234", "CID 1234"},
		{"cvv_before_pan", "CVV 123 for card " + visa16, "CVV 123"},
		{"cvv_seccode_with_card", "Visa " + visa16 + " expiration 12/2028 security code 123", "security code 123"},
		{"code_alone_cvv2", "CVV2: 123", "CVV2: 123"},
		{"code_alone_cvc", "cvc 123", "cvc 123"},
		{"code_alone_seccode", "Security code: 1234", "Security code: 1234"},
		{"code_alone_cvv_kv", "CVV=123", "CVV=123"},
		{"cvv_csv_header_only", "name,card,exp,cvv\nJOHN Q PUBLIC," + visa16 + ",12/28,123", ""},
		{"cvv_pipe_unlabelled", visa16 + "|12/28|123", ""},
		{"exp_alone_validthru", "Valid thru 12/28", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.content + "\n" + control + "\n"
			codes := codesOf(scan(t, content))
			if tc.text == "" {
				if len(codes) != 0 {
					t.Fatalf("want no code finding, got %+v", codes)
				}
				return
			}
			if len(codes) != 1 || codes[0].Text != tc.text || codes[0].Type != "CREDIT_CARD" || codes[0].Confidence != 100 {
				t.Fatalf("want one CREDIT_CARD %q at 100, got %+v", tc.text, codes)
			}
		})
	}
}

// TestACodeWithNoCardInReach: without the control, the unambiguous labels score
// unpairedCodeConfidence and publish it as their ceiling; "security code" alone, a context-only
// label, is not reported.
func TestACodeWithNoCardInReach(t *testing.T) {
	for _, line := range []string{"CVV2: 123", "cvc 123", "CVV=123"} {
		m := oneCode(t, line)
		if m.Confidence != 40 || m.Metadata["paired"] != false {
			t.Errorf("%q: %.1f paired=%v, want 40 unpaired", line, m.Confidence, m.Metadata["paired"])
		}
		if c, _ := m.Metadata["confidence_ceiling"].(float64); c != 40 {
			t.Errorf("%q: ceiling %v, want 40 so a document boost cannot promote it", line, m.Metadata["confidence_ceiling"])
		}
	}
	if codes := codesOf(scan(t, "Security code: 1234")); len(codes) != 0 {
		t.Errorf("a context-only label with no card must not be reported, got %+v", codes)
	}
}

// TestEveryLabelInEveryValueShape: each label, in each separator shape the grammar accepts, beside
// a card on the same line.
func TestEveryLabelInEveryValueShape(t *testing.T) {
	labels := []string{
		"cvv", "CVV2", "cvc", "CVC2", "ccv", "cav2", "card security code", "Card_Verification_Value",
		"card-verification-code", "cardverificationnumber", "cid", "CSC", "cvn", "cvn2", "security code",
		"Security_Code",
	}
	shapes := []struct{ value, tail string }{
		{": 123", ""}, {"=123", ""}, {" 123", ""}, {" : 1234", ""}, {"#123", ""},
		{`": "123`, `"`}, {`':'123`, `'`}, {"=123", "&exp=1228"}, {": 123", "."}, {"=123", ";"},
		{"=123", ")"}, {"=123", "|x"}, {"=123", "<br>"}, {"=123", "]"}, {"=123", "}"}, {"=123", ","},
	}
	for _, l := range labels {
		for _, s := range shapes {
			text := l + s.value
			for _, prefix := range []string{"", "Card " + visa16 + " ", `{"`} {
				line := prefix + text + s.tail
				if prefix == "" {
					line += " " + visa16
				}
				if prefix == `{"` {
					line += `, "card": "` + visa16 + `"}`
				}
				m := oneCode(t, line)
				if m.Text != text {
					t.Errorf("%q: Text %q, want %q", line, m.Text, text)
				}
				if m.Metadata["paired"] != true || m.Metadata["paired_card_type"] != "VISA" || m.Metadata["paired_card_line"] != 1 {
					t.Errorf("%q: metadata %v, want paired with the VISA on line 1", line, m.Metadata)
				}
			}
		}
	}
}

// TestCanonicalLabels: the label metadata names the label, not its spelling.
func TestCanonicalLabels(t *testing.T) {
	for in, want := range map[string]string{
		"CVV2": "cvv2", "Card_Verification_Value": "card verification value", "cardverificationnumber": "card verification number",
		"card-verification-code": "card verification code", "Card Security Code": "card security code", "SecurityCode": "security code",
	} {
		if got := oneCode(t, in+": 123 "+visa16).Metadata["label"]; got != want {
			t.Errorf("%q: label %v, want %q", in, got, want)
		}
	}
}

// TestPairingReachesThreeLines: a card three lines away pairs, four lines away does not; the card may
// be before or after the code.
func TestPairingReachesThreeLines(t *testing.T) {
	gap := func(n int) string { return strings.Repeat("filler\n", n) }
	for _, tc := range []struct {
		name, content string
		paired        bool
	}{
		{"card 3 before", control + "\n" + gap(2) + "CID 1234\n", true},
		{"card 4 before", control + "\n" + gap(3) + "CID 1234\n", false},
		{"card 3 after", "CID 1234\n" + gap(2) + control + "\n", true},
		{"card 4 after", "CID 1234\n" + gap(3) + control + "\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// cid is context-only: it is reported only when paired.
			if got := len(codesOf(scan(t, tc.content))) == 1; got != tc.paired {
				t.Errorf("CID reported %v, want %v", got, tc.paired)
			}
			// cvv is unambiguous: reported either way, at the card's 100 only when paired.
			want := 40.0
			if tc.paired {
				want = 100
			}
			if m := oneCode(t, strings.Replace(tc.content, "CID 1234", "CVV 123", 1)); m.Confidence != want {
				t.Errorf("CVV %.1f, want %.1f", m.Confidence, want)
			}
		})
	}
}

// TestThePairedScoreIsTheBestCardInReach: the highest card wins, its line and type are recorded.
func TestThePairedScoreIsTheBestCardInReach(t *testing.T) {
	content := "md5 " + visa16 + "\n" + // floored at 15 by the hard negative
		"CVV: 123\n" +
		control + "\n"
	m := oneCode(t, content)
	if m.Confidence != 100 || m.Metadata["paired_card_line"] != 3 || m.Metadata["paired_card_type"] != "MASTERCARD" {
		t.Errorf("want the control's 100 on line 3, got %.1f %v", m.Confidence, m.Metadata)
	}
	// Only the floored card in reach: the code takes its 15.
	if m := oneCode(t, "md5 "+visa16+"\nCVV: 123\n"); m.Confidence != intrinsicValueFloor {
		t.Errorf("paired with a 15: got %.1f", m.Confidence)
	}
}

// TestAHardNegativeOnTheCodesLine holds the code at the floor, as the same word holds a card.
func TestAHardNegativeOnTheCodesLine(t *testing.T) {
	for _, content := range []string{"test CVV: 123\n" + control, "CVV: 123 (sample)", "example cvc=123 " + visa16} {
		m := oneCode(t, content)
		if m.Confidence != intrinsicValueFloor {
			t.Errorf("%q: %.1f, want %.1f", content, m.Confidence, intrinsicValueFloor)
		}
		if _, ok := m.Metadata["confidence_ceiling"]; ok {
			t.Errorf("%q: the keyword floor publishes no ceiling, got %v", content, m.Metadata["confidence_ceiling"])
		}
	}
}

// TestCodeDecoys are the issue's decoys and the grammar's edges: none reports a code, and a card on
// the line is reported as a card only. The lines without a card are the golden corpus's
// creditcard_track_and_code_decoys case.
func TestCodeDecoys(t *testing.T) {
	for _, line := range []string{
		"CID 1234 called at 09:14",
		"Content-ID: <cid:1234@mail.invalid>",
		"CSC 2024 annual report",
		"// csc : 2014-09-25 Registry Services",
		"if exp < 100 { return }",
		`<input name="cvv" maxlength="4">`,
		"cvc_check: pass",
		"cvn := 123",
		"Security code: 1234",
		"CVN 789",
		"CVV: 12",
		"CVV: 12345",
		"CVV: ***",
		"cvv123",
		"CVV: 123.45",
		"xcvv=123",
		"cvv=123abc",
		"CVV2 2024-11-07",
		"cvv: 1234@host",
	} {
		if codes := codesOf(scan(t, line)); len(codes) != 0 {
			t.Errorf("%q: want no code, got %+v", line, codes)
		}
	}
	// With a card: the card only (the R1 decoys the issue measured).
	for _, line := range []string{
		visa16 + " AUTH 123456 TERM 0042 BATCH 117 MCC 5411",
		"Order 5678 paid with card " + visa16 + " total 123.45",
		"ref 1234 for card " + visa16,
		"store 0042 lane 3 card " + visa16,
	} {
		ms := scan(t, line)
		if len(codesOf(ms)) != 0 || len(ms) != 1 || ms[0].Text != visa16 {
			t.Errorf("%q: want the card only, got %+v", line, ms)
		}
	}
}

// TestTwoCodesOnOneLine: the scan resumes after a value, so the byte that ends one value is the
// next label's left edge.
func TestTwoCodesOnOneLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"cvv=123,cvc=456 " + visa16, []string{"cvv=123", "cvc=456"}},
		{"cvv=1234 card " + visa16 + " cvv=123", []string{"cvv=1234", "cvv=123"}},
	} {
		codes := codesOf(scan(t, tc.line))
		if len(codes) != len(tc.want) {
			t.Fatalf("%q: want %v, got %+v", tc.line, tc.want, codes)
		}
		for i, w := range tc.want {
			if codes[i].Text != w {
				t.Errorf("%q: code %d is %q, want %q", tc.line, i, codes[i].Text, w)
			}
		}
	}
}

// TestCodeMetadataCarriesNoDigits: no PAN digit and no code digit reaches metadata.
func TestCodeMetadataCarriesNoDigits(t *testing.T) {
	m := oneCode(t, "card="+visa16+" exp=1228 cvv=123")
	for k, val := range m.Metadata {
		s, ok := val.(string)
		if ok && (strings.Contains(s, "123") || strings.Contains(s, visa16[:6])) {
			t.Errorf("metadata %q = %q carries a value's digits", k, s)
		}
	}
}

// TestACancelledScanKeepsItsCodes: codes found before a cancellation are returned with the partial
// matches, paired with the cards seen so far.
func TestACancelledScanKeepsItsCodes(t *testing.T) {
	var b strings.Builder
	b.WriteString("CVV2: 123\n")
	for b.Len() < 1<<16 {
		b.WriteString("filler line\n")
	}
	ms, err := NewValidator().ValidateContentCtx(&cancelledAfterFirstPoll{Context: context.Background()}, b.String(), "cancel.txt")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want the scan cancelled at its second poll, got %v", err)
	}
	if codes := codesOf(ms); len(codes) != 1 || codes[0].Text != "CVV2: 123" {
		t.Errorf("want the one code found before the cancellation, got %+v", ms)
	}
}

// cancelledAfterFirstPoll is a context that is live when first asked and cancelled every time
// after, so a scan processes its first stride of lines and stops at the next poll.
type cancelledAfterFirstPoll struct {
	context.Context
	polls int
}

func (c *cancelledAfterFirstPoll) Err() error {
	c.polls++
	if c.polls == 1 {
		return nil
	}
	return context.Canceled
}

// TestCodesStayLinear: codes packed on one line, 4 then 32 KiB. The scan resumes after each value
// and asks the line's hard-negative question once, so it never rereads the line (see growthLimit
// for the readings, with that question asked once per code instead). Smaller than
// TestFramesStayLinear's sizes because the regressed run is far slower per byte and must fail on
// its ratio rather than time out. The pairing is linear by construction: one forward pass over
// cands and cards.
func TestCodesStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping complexity test in -short mode")
	}
	tr, br, small, big := growth(t, "cvv 123 ", 4<<10, func(ms []detector.Match) int { return len(codesOf(ms)) })
	if tr > growthLimit || br > growthLimit {
		t.Errorf("%dx the line (%d to %d codes) took %.1fx the time and %.1fx the bytes (limit %.0fx): "+
			"work on the whole line per code?", growthFactor, small, big, tr, br, growthLimit)
	}
	t.Logf("%d to %d codes, time x%.2f, bytes x%.2f", small, big, tr, br)
}
