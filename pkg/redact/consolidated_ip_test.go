// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// TestRedact_ConsolidatedIPLongLineFullyRedacted is the redaction-coverage lock
// for the bounded consolidated INTELLECTUAL_PROPERTY match text.
//
// Shape under test: a PDF whose every slide carries the standard AWS footer
// extracts to ONE logical line of ~63 concatenated footer copies. The IP
// validator consolidates all same-line matches into a single finding whose
// display Text is now BOUNDED ("<primary> [+N more matches on line]") instead
// of the whole 8KB+ line. Redaction locates matches by searching for
// Match.Text — so if the bounded display text leaked into the redaction path,
// the entire line of sensitive content would silently survive. This test
// proves the full line is still redacted end-to-end through the public
// pkg/redact engine (the same path the goldencorpus redact tests use).
func TestRedact_ConsolidatedIPLongLineFullyRedacted(t *testing.T) {
	const footer = "© 2026, Amazon Web Services, Inc. or its affiliates. All rights reserved. Amazon Confidential and Trademark. "
	var sb strings.Builder
	for sb.Len() < 8000 {
		sb.WriteString(footer)
	}
	line := sb.String()
	input := line + "\nplain trailing prose stays untouched\n"

	e := newTestEngine(t, redact.EngineOptions{
		Checks:   []string{"INTELLECTUAL_PROPERTY"},
		Strategy: redact.Simple,
	})

	res, err := e.Redact(context.Background(), redact.Request{Text: input, Label: "<deck>"})
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	// The consolidated legal notice must be gone in its entirety: none of the
	// sensitive footer's distinctive fragments may survive redaction.
	for _, fragment := range []string{
		"Amazon Web Services",
		"Amazon Confidential",
		"All rights reserved",
		"© 2026",
	} {
		if strings.Contains(res.Redacted, fragment) {
			t.Errorf("redacted output still contains %q — bounded display text weakened redaction coverage", fragment)
		}
	}

	// Untouched, non-sensitive content must survive.
	if !strings.Contains(res.Redacted, "plain trailing prose stays untouched") {
		t.Errorf("redaction destroyed non-sensitive content")
	}

	// And the finding's exported MatchText must be the bounded display form,
	// not the multi-KB line.
	fwts := res.FindingsWithMatchText()
	if len(fwts) == 0 {
		t.Fatalf("no findings reported")
	}
	for _, f := range fwts {
		if f.Type != "INTELLECTUAL_PROPERTY" {
			continue
		}
		if len(f.MatchText) > 256 {
			t.Errorf("finding MatchText is %d bytes, want bounded (<= 256)", len(f.MatchText))
		}
		if !strings.Contains(f.MatchText, "more matches on line]") {
			t.Errorf("finding MatchText %q missing the truncation marker", f.MatchText)
		}
	}
}
