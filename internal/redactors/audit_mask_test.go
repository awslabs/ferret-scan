// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"strings"
	"testing"
)

// An entry names the rendering written (#865). Where a format rewritten in place wrote a mask instead
// of a rendering of the requested strategy that keeps part of the value, the entry says "mask" and
// names the strategy asked for. Audio, video and legacy Office entries used to say format_preserving
// beside a mask.
func TestAMaskedEntryNamesTheMaskAndTheStrategyAskedFor(t *testing.T) {
	_, doc := exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "BUSINESS", RedactedText: strings.Repeat("*", 28), Strategy: RedactionFormatPreserving, Masked: true,
			Confidence: 53, Position: TextPosition{Line: 5}},
		{DataType: "PHONE", RedactedText: "(***) ***-0199", Strategy: RedactionFormatPreserving, Confidence: 100,
			Position: TextPosition{Line: 6}},
	}})
	c := entries(doc, "content_redactions")
	if c[0]["strategy"] != "mask" || c[0]["requested_strategy"] != "format_preserving" || c[0]["line"] != 5.0 {
		t.Errorf("masked entry = %v, want strategy mask, requested_strategy format_preserving, line 5", c[0])
	}
	if _, present := c[1]["requested_strategy"]; present || c[1]["strategy"] != "format_preserving" {
		t.Errorf("an entry written as asked = %v, want strategy format_preserving and no requested_strategy", c[1])
	}
	if s, _ := doc["redaction_summary"].(map[string]any); s["strategy"] != "format_preserving" {
		t.Errorf("summary strategy = %v, want the strategy the run asked for", s["strategy"])
	}

	// simple is the zero RedactionStrategy: when it is the one asked for it is written, not omitted.
	_, doc = exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "SSN", RedactedText: "***********", Strategy: RedactionSimple, Masked: true, Confidence: 90},
	}})
	if c := entries(doc, "content_redactions"); c[0]["requested_strategy"] != "simple" {
		t.Errorf("requested_strategy = %#v, want \"simple\"", c[0]["requested_strategy"])
	}
}

// A mask is not a strategy a run can ask for, and an entry is a mask exactly when it says what it
// stood in for. Anything else fails the export, as an out-of-range strategy does.
func TestAMaskThatDoesNotSayWhatItStoodInForFailsTheExport(t *testing.T) {
	fp, bad := RedactionFormatPreserving, RedactionStrategy(7)
	valid := func(c ContentRedaction) error {
		log := NewRedactionAuditLog("doc_1", "in/a.wav", "out/a.wav", "test")
		c.DataType, c.Confidence = "SSN", 0.5
		log.AddContentRedaction(c)
		return log.Validate()
	}
	for name, c := range map[string]ContentRedaction{
		"mask without requested_strategy":  {Strategy: AuditMask},
		"requested_strategy without mask":  {Strategy: "format_preserving", RequestedStrategy: &fp},
		"requested_strategy out of range":  {Strategy: AuditMask, RequestedStrategy: &bad},
		"a name that is neither":           {Strategy: "masked"},
		"an out-of-range strategy's label": {Strategy: AuditStrategy(bad.String())},
	} {
		if err := valid(c); err == nil || !strings.Contains(err.Error(), "strategy") {
			t.Errorf("%s: Validate = %v, want a failure naming the field", name, err)
		}
	}
	if err := valid(ContentRedaction{Strategy: AuditMask, RequestedStrategy: &fp}); err != nil {
		t.Errorf("a mask that names what it stood in for: %v", err)
	}
	if _, err := ParseRedactionStrategy(string(AuditMask)); err == nil {
		t.Error("a run can ask for mask")
	}
}
