// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// Every audit field from the run, on one declared scale (#865).

// exportedLog adds one result to a fresh manager and returns the export, decoded loosely so the
// assertions read what a consumer of the JSON reads.
func exportedLog(t *testing.T, rm *RedactionManager, result *RedactionResult) (envelope map[string]any, doc map[string]any) {
	t.Helper()
	rm.AddRedactionResult("in/sample.txt", "out/sample.txt", result)
	data, err := rm.auditLogManager.ExportAllAuditLogs()
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	logs, _ := envelope["audit_logs"].(map[string]any)
	if len(logs) != 1 {
		t.Fatalf("want one audit log, got %d", len(logs))
	}
	for _, v := range logs {
		doc, _ = v.(map[string]any)
	}
	return envelope, doc
}

func entries(doc map[string]any, key string) []map[string]any {
	raw, _ := doc[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		m, _ := r.(map[string]any)
		out = append(out, m)
	}
	return out
}

func TestAuditVersionIsTheBuild(t *testing.T) {
	saved := version.Version
	version.Version = "9.9.9-audit"
	t.Cleanup(func() { version.Version = saved })

	env, doc := exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "SSN", RedactedText: "***-**-0001", Strategy: RedactionFormatPreserving, Confidence: 90},
	}})
	if env["ferret_version"] != "9.9.9-audit" || doc["ferret_version"] != "9.9.9-audit" {
		t.Errorf("ferret_version = %v (envelope), %v (document); want the build's version.Short() at both levels",
			env["ferret_version"], doc["ferret_version"])
	}
}

func TestAuditSummaryRecordsTheRun(t *testing.T) {
	_, doc := exportedLog(t, newTestManager(t), &RedactionResult{
		Success:        true,
		ProcessingTime: 1234 * time.Microsecond,
		RedactionMap: []RedactionMapping{
			{DataType: "SSN", RedactedText: "***-**-0001", Strategy: RedactionFormatPreserving, Confidence: 90},
			{DataType: "PHONE", RedactedText: "(***) ***-0199", Strategy: RedactionFormatPreserving, Confidence: 70},
		},
	})
	s, _ := doc["redaction_summary"].(map[string]any)
	if s["strategy"] != "format_preserving" {
		t.Errorf("summary strategy = %#v, want \"format_preserving\" (it used to be 0, which reads as simple)", s["strategy"])
	}
	if s["processing_time_ms"] != 1.234 {
		t.Errorf("processing_time_ms = %v, want 1.234", s["processing_time_ms"])
	}
	if _, stale := s["processing_time"]; stale {
		t.Error("the unit-less processing_time field is still written")
	}
	if s["total_redactions"] != 2.0 || s["successful_redactions"] != 2.0 || s["failed_redactions"] != 0.0 {
		t.Errorf("counts = %v/%v/%v, want 2/2/0", s["total_redactions"], s["successful_redactions"], s["failed_redactions"])
	}
	for _, e := range entries(doc, "content_redactions") {
		if e["strategy"] != "format_preserving" {
			t.Errorf("entry strategy = %#v, want the name", e["strategy"])
		}
	}
	if _, stale := doc["redaction_config"]; stale {
		t.Error("redaction_config is still written; it never had a source")
	}

	// A result with no mapping still records the run's strategy, from the manager's configuration.
	rm := newTestManager(t)
	rm.config.DefaultStrategy = RedactionSynthetic
	_, doc = exportedLog(t, rm, &RedactionResult{Success: true})
	if s, _ := doc["redaction_summary"].(map[string]any); s["strategy"] != "synthetic" {
		t.Errorf("summary strategy with no mappings = %#v, want \"synthetic\"", s["strategy"])
	}
}

func TestAuditConfidenceIsTheDetectionConfidence(t *testing.T) {
	_, doc := exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		// The text-family redactor: placement score in Confidence, detection confidence in metadata.
		{DataType: "EMAIL", RedactedText: "j***@example.com", Strategy: RedactionFormatPreserving, Confidence: 0.95,
			Position: TextPosition{Line: 2},
			Metadata: map[string]interface{}{"original_confidence": 61.0, "position_method": "position_correlation"}},
		{DataType: "VISA", RedactedText: "************0002", Strategy: RedactionFormatPreserving, Confidence: 0.075,
			Position: TextPosition{Line: 3},
			Metadata: map[string]interface{}{"original_confidence": 15.0, "position_method": "simple_text_search"}},
		// Office, audio, video and legacy OLE: the detection confidence itself.
		{DataType: "PHONE", RedactedText: "(***) ***-0199", Strategy: RedactionFormatPreserving, Confidence: 45},
	}})
	want := []struct {
		conf   float64
		line   any
		method any
		score  any
	}{
		{0.61, 2.0, "position_correlation", 0.95},
		{0.15, 3.0, "simple_text_search", 0.075},
		{0.45, nil, nil, nil},
	}
	got := entries(doc, "content_redactions")
	if len(got) != len(want) {
		t.Fatalf("%d entries, want %d", len(got), len(want))
	}
	for i, w := range want {
		e := got[i]
		if e["confidence"] != w.conf {
			t.Errorf("entry %d confidence = %v, want %v (the report's confidence / 100)", i, e["confidence"], w.conf)
		}
		if e["line"] != w.line {
			t.Errorf("entry %d line = %v, want %v", i, e["line"], w.line)
		}
		p, _ := e["placement"].(map[string]any)
		if w.method == nil {
			if e["placement"] != nil {
				t.Errorf("entry %d has a placement, but its redactor records none: %v", i, e["placement"])
			}
			continue
		}
		if p["method"] != w.method || p["score"] != w.score {
			t.Errorf("entry %d placement = %v, want method %v score %v", i, p, w.method, w.score)
		}
	}
}

func TestImageRemovalsAreMetadataRedactions(t *testing.T) {
	_, doc := exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "IMAGE_METADATA", RedactedText: "[METADATA-REMOVED]", Strategy: RedactionSimple, Confidence: 1.0,
			Metadata: map[string]interface{}{"exif_field": "Artist", "metadata_type": "exif"}},
		{DataType: "IMAGE_METADATA", RedactedText: "[METADATA-REMOVED]", Strategy: RedactionSimple, Confidence: 1.0,
			Metadata: map[string]interface{}{"exif_field": "GPSLatitude", "metadata_type": "exif"}},
		{DataType: "IMAGE_METADATA", RedactedText: "[METADATA-REMOVED]", Strategy: RedactionSimple, Confidence: 1.0,
			Metadata: map[string]interface{}{"metadata_type": "png_chunks"}},
	}})
	if c := entries(doc, "content_redactions"); len(c) != 0 {
		t.Errorf("metadata removals are still logged as content redactions: %v", c)
	}
	md := entries(doc, "metadata_redactions")
	var fields []string
	for _, m := range md {
		fields = append(fields, m["field"].(string))
		if m["action"] != "removed" || m["redacted_value"] != nil || m["target_type"] != "parent_document" {
			t.Errorf("metadata entry %v: want action removed, redacted_value null, target parent_document", m)
		}
	}
	if strings.Join(fields, ",") != "Artist,GPSLatitude,png_ancillary_chunks" {
		t.Errorf("metadata fields = %v", fields)
	}
	s, _ := doc["redaction_summary"].(map[string]any)
	if s["total_redactions"] != 3.0 || !strings.Contains(strings.Join(toStrings(s["data_types"]), ","), "IMAGE_METADATA") {
		t.Errorf("summary = %v; want 3 redactions including IMAGE_METADATA", s)
	}
}

func TestAnEmbeddedPartIsNamed(t *testing.T) {
	_, doc := exportedLog(t, newTestManager(t), &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "PHONE", RedactedText: "(***) ***-0199", Strategy: RedactionFormatPreserving, Confidence: 100},
		{DataType: "SSN", RedactedText: "***-**-0001", Strategy: RedactionFormatPreserving, Confidence: 90,
			Metadata: map[string]interface{}{"embedded_part": "word/embeddings/oleObject1.docx", "embedded_in": "outer.docx"}},
		{DataType: "IMAGE_METADATA", RedactedText: "[METADATA-REMOVED]", Strategy: RedactionFormatPreserving, Confidence: 1.0,
			Metadata: map[string]interface{}{"exif_field": "Artist", "embedded_part": "word/media/image1.jpeg"}},
	}})
	c := entries(doc, "content_redactions")
	if c[0]["target_type"] != "parent_document" || c[0]["target_path"] != nil {
		t.Errorf("body entry = %v", c[0])
	}
	if c[1]["target_type"] != "embedded_media" || c[1]["target_path"] != "word/embeddings/oleObject1.docx" {
		t.Errorf("embedded content entry = %v, want embedded_media at word/embeddings/oleObject1.docx", c[1])
	}
	if m := entries(doc, "metadata_redactions"); len(m) != 1 || m[0]["target_type"] != "embedded_media" || m[0]["target_path"] != "word/media/image1.jpeg" {
		t.Errorf("embedded metadata entries = %v", m)
	}
}

func TestAnInvalidStrategyFailsTheExport(t *testing.T) {
	rm := newTestManager(t)
	rm.AddRedactionResult("in/a.txt", "out/a.txt", &RedactionResult{Success: true, RedactionMap: []RedactionMapping{
		{DataType: "SSN", RedactedText: "x", Strategy: RedactionStrategy(7), Confidence: 90},
	}})
	if _, err := rm.auditLogManager.ExportAllAuditLogs(); err == nil || !strings.Contains(err.Error(), "strategy") {
		t.Fatalf("export with an out-of-range strategy = %v, want a named failure", err)
	}
	if _, err := RedactionStrategy(7).MarshalText(); err == nil {
		t.Error("MarshalText accepted an out-of-range strategy")
	}
	for _, s := range []RedactionStrategy{RedactionSimple, RedactionFormatPreserving, RedactionSynthetic} {
		b, err := s.MarshalText()
		var back RedactionStrategy
		if err != nil || back.UnmarshalText(b) != nil || back != s {
			t.Errorf("%s does not round-trip through its text form", s)
		}
	}
}

func toStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if s, ok := r.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
