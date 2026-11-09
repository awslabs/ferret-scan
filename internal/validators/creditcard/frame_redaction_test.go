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
	for _, s := range []redact.Strategy{redact.Simple, redact.FormatPreserving} {
		for _, line := range frameLines {
			out := redactWith(t, s, line)
			for _, v := range []string{pan, expSvc, disc[:4], "0012345"} {
				if strings.Contains(out, v) {
					t.Errorf("%s: %q survives in %q (from %q)", s, v, out, line)
				}
			}
			if s == redact.Simple && strings.Contains(out, "JOHN") {
				t.Errorf("simple: the Track 1 name survives in %q", out)
			}
		}
		for _, line := range codeLines {
			out := redactWith(t, s, line)
			if strings.Contains(out, "987") {
				t.Errorf("%s: the code survives in %q (from %q)", s, out, line)
			}
			// format_preserving keeps a plain PAN's last four by design; simple keeps nothing.
			if s == redact.Simple && strings.Contains(out, "7899") {
				t.Errorf("simple: a card digit survives in %q (from %q)", out, line)
			}
		}
	}
}

// TestFormatPreservingKeepsWhatTheCardMaskKeeps pins the limit of reporting a frame under its PAN's
// type until the frame has a type of its own (#905 registers CARD_TRACK_DATA outside
// creditCardTypes, which full-masks it): the card mask writes back every non-digit byte and the last
// four digits of the frame, so a Track 1 keeps its name and the frame its last four discretionary
// digits. No PAN, expiry or service-code digit is kept.
func TestFormatPreservingKeepsWhatTheCardMaskKeeps(t *testing.T) {
	got := redactWith(t, redact.FormatPreserving, frameLines[0])
	want := "%B" + strings.Repeat("*", 16) + "^PUBLIC/JOHN Q^" + strings.Repeat("*", 7+len(disc)-4) + disc[len(disc)-4:] + "?"
	if got != want {
		t.Errorf("format_preserving Track 1:\n got %q\nwant %q", got, want)
	}
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
