// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// An external test package: pkg/redact builds the scanner, which imports this package, so only a
// _test package outside it can drive the whole detect-and-redact path.
package creditcard_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// #905's headline: on main every Track 1, tag 57 and URL-encoded Track 2 in the issue's files was
// written back unchanged by --enable-redaction, a Track 2's expiry, service code and discretionary
// data survived after its masked PAN, and every labelled code survived. Through the public
// redaction API, none of those bytes may survive simple or format_preserving.
//
// What format_preserving still keeps is pinned in TestFormatPreservingKeepsWhatTheCardMaskKeeps.

const (
	pan    = "4000001234567899"
	expSvc = "2812101" // expiry 2812, service code 101
	disc   = "4321098765"
)

var frameLines = []string{
	"%B" + pan + "^PUBLIC/JOHN Q^" + expSvc + disc + "?",
	";" + pan + "=" + expSvc + disc + "?",
	"track2=%3B" + pan + "%3D" + expSvc + disc + "%3F",
	"tag57=" + pan + "D" + expSvc + disc + "F",
	"5713" + pan + "D" + expSvc + disc + "123F", // 38 nibbles, 0x13 bytes
	"%B" + pan + "^PUBLIC/JOHN Q^" + expSvc + disc + "?;" + pan + "=" + expSvc + disc + "?",
}

var codeLines = []string{
	"card=" + pan + " exp=1228 cvv=987",
	`{"card_number": "` + pan + `", "cvv": "987"}`,
	"Card: 4000 0012 3456 7899 Exp: 12/28 CVV: 987",
	"CVV2: 987\nCard number: 2221001234567896",
}

// codeTexts is each codeLines entry's code finding, label through value. Under synthetic a card's
// random digits may hold "987" by chance, so there the labelled value is what must not survive.
var codeTexts = []string{"cvv=987", `cvv": "987`, "CVV: 987", "CVV2: 987"}

func redactWith(t *testing.T, s redact.Strategy, text string) string {
	t.Helper()
	eng, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"CREDIT_CARD"}, Strategy: s})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eng.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := eng.Redact(ctx, redact.Request{Text: text})
	if err != nil {
		t.Fatalf("Redact(%q, %s): %v", text, s, err)
	}
	return res.Redacted
}

func TestNoTrackOrCodeValueSurvivesRedaction(t *testing.T) {
	for _, s := range []redact.Strategy{redact.Simple, redact.FormatPreserving, redact.Synthetic} {
		for _, line := range frameLines {
			out := redactWith(t, s, line)
			values := []string{pan, expSvc, disc[:4], "0012345"}
			if s == redact.Synthetic {
				// Random digits hold a given four-digit run about one draw in 300; the whole
				// discretionary field cannot recur by chance.
				values[2] = disc
			}
			for _, v := range values {
				if strings.Contains(out, v) {
					t.Errorf("%s: %q survives in %q (from %q)", s, v, out, line)
				}
			}
			// Before CARD_TRACK_DATA had its own type, format_preserving and synthetic used the
			// card mask, which writes back every non-digit byte: the name survived (#905).
			if strings.Contains(out, "JOHN") || strings.Contains(out, "PUBLIC") {
				t.Errorf("%s: the Track 1 name survives in %q", s, out)
			}
		}
		for i, line := range codeLines {
			out := redactWith(t, s, line)
			if strings.Contains(out, codeTexts[i]) || (s != redact.Synthetic && strings.Contains(out, "987")) {
				t.Errorf("%s: the code survives in %q (from %q)", s, out, line)
			}
			// format_preserving keeps a plain PAN's last four by design; simple keeps nothing.
			if s == redact.Simple && strings.Contains(out, "7899") {
				t.Errorf("simple: a card digit survives in %q (from %q)", out, line)
			}
		}
	}
}

// TestFrameAndCodeRenderings pins what each strategy writes for the two types. Neither is in the
// redactors' creditCardTypes, so simple writes the type's own placeholder and format_preserving
// masks every byte, the Track 1 name and the code's label included (on main the card mask kept the
// name and the frame's last four digits). Synthetic writes a frame of the same shape whose PAN keeps
// its issuer prefix and fails Luhn, and nothing of the name.
func TestFrameAndCodeRenderings(t *testing.T) {
	track1 := frameLines[0]
	if got, want := redactWith(t, redact.FormatPreserving, track1), strings.Repeat("*", len(track1)); got != want {
		t.Errorf("format_preserving Track 1:\n got %q\nwant %q", got, want)
	}
	if got := redactWith(t, redact.Simple, track1); got != "[CARD_TRACK_DATA-REDACTED]" {
		t.Errorf("simple Track 1: got %q", got)
	}
	code := "CVV2: 987"
	if got := redactWith(t, redact.FormatPreserving, code); got != strings.Repeat("*", len(code)) {
		t.Errorf("format_preserving code: got %q", got)
	}
	if got := redactWith(t, redact.Simple, code); got != "[CARD_SECURITY_CODE-REDACTED]" {
		t.Errorf("simple code: got %q", got)
	}

	got := redactWith(t, redact.Synthetic, track1)
	if len(got) != len(track1) || !strings.HasPrefix(got, "%B4000") || strings.Count(got, "^") != 2 || !strings.HasSuffix(got, "?") {
		t.Fatalf("synthetic Track 1 lost its shape: %q (from %q)", got, track1)
	}
	if synthPAN := got[2:18]; luhnValid(synthPAN) {
		t.Errorf("synthetic Track 1 PAN %q passes Luhn", synthPAN)
	}
}

// TestASyntheticFrameIsNotACard is the re-scan for #905's P1: on main the synthetic copy of a frame
// carried a PAN that passed Luhn one time in ten, because the card generator wrote one Luhn-invalid
// number over ALL the frame's digits, so the check digit it broke was the frame's last, not the
// PAN's. A re-scan of the issue's synthetic copies reported 6 VISA findings. Every draw must fail
// Luhn: 40 draws per frame give a valid PAN on main with probability 1 - 0.9^40, about 98.5 %.
func TestASyntheticFrameIsNotACard(t *testing.T) {
	scanner, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"CREDIT_CARD"}, Strategy: redact.Simple})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scanner.Close() }()
	for _, line := range frameLines {
		for i := 0; i < 40; i++ {
			out := redactWith(t, redact.Synthetic, line)
			res, err := scanner.Redact(context.Background(), redact.Request{Text: out})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range res.Findings() {
				t.Fatalf("draw %d: re-scan of the synthetic copy %q (from %q) found %s", i, out, line, f.Type)
			}
		}
	}
}

func luhnValid(s string) bool {
	sum := 0
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if (len(s)-1-i)%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// TestARedactedFrameIsNotReportedAgain: re-scanning simple output reports no card, frame or code.
func TestARedactedFrameIsNotReportedAgain(t *testing.T) {
	text := strings.Join(append(append([]string{}, frameLines...), codeLines...), "\n")
	once := redactWith(t, redact.Simple, text)
	eng, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"CREDIT_CARD"}, Strategy: redact.Simple})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = eng.Close() }()
	res, err := eng.Redact(context.Background(), redact.Request{Text: once})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings() {
		t.Errorf("re-scan of the redacted output found %s on line %d", f.Type, f.LineNumber)
	}
	if !strings.Contains(once, "[CREDIT-CARD-REDACTED]") {
		t.Fatalf("nothing was redacted, so the re-scan proves nothing: %q", once)
	}
}
