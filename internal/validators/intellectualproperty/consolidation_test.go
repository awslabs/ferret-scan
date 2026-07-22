// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// awsFooter is the standard slide footer that, repeated once per slide, PDF
// text extraction concatenates onto ONE logical line. This is the user-reported
// shape that produced a single 11,871-char Match.Text.
const awsFooter = "© 2026, Amazon Web Services, Inc. or its affiliates. All rights reserved. Amazon Confidential and Trademark. "

// longFooterLine builds a single line (no newline) of >= n bytes of repeated
// AWS footer copies.
func longFooterLine(n int) string {
	var sb strings.Builder
	sb.Grow(n + len(awsFooter))
	for sb.Len() < n {
		sb.WriteString(awsFooter)
	}
	return sb.String()
}

// TestConsolidatedMatchTextBoundedOnLongLine locks the fix for the
// user-reported finding whose Text was the entire 11,871-char extracted line:
// when every match sits on one pathologically long line, the consolidated
// display text must be BOUNDED — primary match + "[+N more matches on line]"
// marker — while metadata keeps the full reconstruction data.
func TestConsolidatedMatchTextBoundedOnLongLine(t *testing.T) {
	line := longFooterLine(8000) // ~63 footer copies, single line

	v := NewValidator()
	matches, err := v.ValidateContent(line+"\n", "deck.pdf")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d", len(matches))
	}
	m := matches[0]

	// Bounded display text.
	if len(m.Text) > consolidatedTextCap {
		t.Errorf("consolidated Text is %d bytes, want <= %d (bounding failed)", len(m.Text), consolidatedTextCap)
	}
	if !strings.Contains(m.Text, "more matches on line]") {
		t.Errorf("consolidated Text %q missing the truncation marker", m.Text)
	}

	// Truncation must be flagged in metadata.
	if truncated, _ := m.Metadata["match_text_truncated"].(bool); !truncated {
		t.Errorf("metadata match_text_truncated = %v, want true", m.Metadata["match_text_truncated"])
	}

	// Full reconstruction data must survive in metadata.
	count, ok := m.Metadata["consolidated_count"].(int)
	if !ok || count < 2 {
		t.Fatalf("consolidated_count = %v, want >= 2", m.Metadata["consolidated_count"])
	}
	texts, ok := m.Metadata["original_match_texts"].([]string)
	if !ok {
		t.Fatalf("original_match_texts missing or wrong type: %T", m.Metadata["original_match_texts"])
	}
	if len(texts) != count {
		t.Errorf("original_match_texts has %d entries, want consolidated_count=%d", len(texts), count)
	}

	// The marker's N must equal consolidated_count-1.
	wantMarker := "[+" + strconv.Itoa(count-1) + " more matches on line]"
	if !strings.HasSuffix(m.Text, wantMarker) {
		t.Errorf("consolidated Text %q does not end with %q", m.Text, wantMarker)
	}

	// Context.FullLine must still carry the whole line — the redaction layer
	// depends on it to restore full-span coverage.
	if strings.TrimSpace(m.Context.FullLine) != strings.TrimSpace(line) {
		t.Errorf("Context.FullLine no longer carries the full line (len=%d, want %d)",
			len(m.Context.FullLine), len(line))
	}
}

// TestConsolidatedMatchTextShortLinePreserved locks the historical behavior:
// an ordinary short legal-notice line consolidates to the FULL trimmed line,
// with no truncation flag.
func TestConsolidatedMatchTextShortLinePreserved(t *testing.T) {
	line := "© 2024 Acme Inc. All rights reserved. Acme Confidential and Acme(TM)."
	if len(line) > consolidatedFullLineCap {
		t.Fatalf("test line unexpectedly exceeds the cap (%d > %d)", len(line), consolidatedFullLineCap)
	}

	v := NewValidator()
	matches, err := v.ValidateContent(line+"\n", "notice.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d", len(matches))
	}
	m := matches[0]

	if m.Text != strings.TrimSpace(line) {
		t.Errorf("short-line consolidated Text = %q, want the full trimmed line %q", m.Text, line)
	}
	if truncated, _ := m.Metadata["match_text_truncated"].(bool); truncated {
		t.Errorf("match_text_truncated = true on a short line, want false")
	}
}

// TestBoundedConsolidatedTextCapsOversizedPrimary exercises the inner
// truncation: when even the primary match text exceeds the budget, it is cut
// with an explicit ellipsis and the total stays within the cap.
func TestBoundedConsolidatedTextCapsOversizedPrimary(t *testing.T) {
	primary := strings.Repeat("Copyright 2026 Amazon Web Services ", 20) // ~700 bytes
	got := boundedConsolidatedText(primary, 63)

	if len(got) > consolidatedTextCap {
		t.Errorf("bounded text is %d bytes, want <= %d", len(got), consolidatedTextCap)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("oversized primary was not visibly truncated: %q", got)
	}
	if !strings.HasSuffix(got, "[+62 more matches on line]") {
		t.Errorf("bounded text missing marker: %q", got)
	}
}

// TestBoundedConsolidatedTextUTF8Safe ensures the cut point never splits a
// multi-byte rune (© is 2 bytes; a naive byte cut can land mid-sequence).
func TestBoundedConsolidatedTextUTF8Safe(t *testing.T) {
	primary := strings.Repeat("©", 300) // 600 bytes of 2-byte runes
	got := boundedConsolidatedText(primary, 10)
	if len(got) > consolidatedTextCap {
		t.Errorf("bounded text is %d bytes, want <= %d", len(got), consolidatedTextCap)
	}
	if strings.ContainsRune(got, '�') || !strings.HasPrefix(got, "©") {
		t.Errorf("UTF-8 damage in bounded text: %q", got)
	}
}

// TestBoundedConsolidatedRedactionCoversFullLine is the redaction-path lock:
// a bounded consolidated finding must still redact the ENTIRE original line.
// Redaction locates matches by searching for Match.Text, and the bounded
// display text does not occur in the document — redactors.RestoreBoundedMatchText
// must restore the full-line span before masking, or the whole line of
// sensitive content silently survives.
func TestBoundedConsolidatedRedactionCoversFullLine(t *testing.T) {
	line := longFooterLine(8000)
	content := line + "\n"

	v := NewValidator()
	matches, err := v.ValidateContent(content, "deck.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 consolidated finding, got %d", len(matches))
	}

	restored := redactors.RestoreBoundedMatchText(matches)
	if len(restored) != 1 {
		t.Fatalf("RestoreBoundedMatchText changed match count: %d", len(restored))
	}
	if restored[0].Text != strings.TrimSpace(line) {
		t.Errorf("restored Text is not the full line (len=%d, want %d)",
			len(restored[0].Text), len(strings.TrimSpace(line)))
	}
	// The caller's match must keep the bounded display text (no mutation).
	if len(matches[0].Text) > consolidatedTextCap {
		t.Errorf("RestoreBoundedMatchText mutated the caller's bounded Text (len=%d)", len(matches[0].Text))
	}
}
