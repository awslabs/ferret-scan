// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The audit log as the CLI writes it, from the redactors the CLI registers (#865): the real
// text-family and image redactors' mappings, through AddRedactionResult and ExportAuditLog.
// Synthetic values only: a reserved-domain address, a 555-01xx number, zero-serial card numbers.

type auditDoc struct {
	FerretVersion     string `json:"ferret_version"`
	OriginalPath      string `json:"original_path"`
	ContentRedactions []struct {
		DataType   string  `json:"data_type"`
		Strategy   string  `json:"strategy"`
		Confidence float64 `json:"confidence"`
		Line       int     `json:"line"`
		Placement  *struct {
			Method string   `json:"method"`
			Score  *float64 `json:"score"`
		} `json:"placement"`
	} `json:"content_redactions"`
	MetadataRedactions []struct {
		Field  string `json:"field"`
		Action string `json:"action"`
	} `json:"metadata_redactions"`
	Summary struct {
		Strategy         string  `json:"strategy"`
		ProcessingTimeMs float64 `json:"processing_time_ms"`
		Total            int     `json:"total_redactions"`
	} `json:"redaction_summary"`
}

func redactAndAudit(t *testing.T, src string, matches []detector.Match, strategy redactors.RedactionStrategy) auditDoc {
	t.Helper()
	dir := t.TempDir()
	rm, om, err := core.NewDefaultRedactionManager(filepath.Join(dir, "out"), strategy, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rm.GetRedactorForFile(src)
	if err != nil {
		t.Fatal(err)
	}
	out, err := om.CreateMirroredPath(src)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.RedactDocument(src, out, matches, strategy)
	if err != nil || !res.Success {
		t.Fatalf("%s: RedactDocument: %v", r.GetName(), err)
	}
	rm.AddRedactionResult(src, out, res)
	logPath := filepath.Join(dir, "audit.json")
	if err := rm.ExportAuditLog(logPath); err != nil {
		t.Fatalf("export: %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		AuditLogs map[string]auditDoc `json:"audit_logs"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if len(env.AuditLogs) != 1 {
		t.Fatalf("%d audit logs, want 1", len(env.AuditLogs))
	}
	for _, d := range env.AuditLogs {
		return d
	}
	return auditDoc{}
}

// The issue's sample.txt: four findings the report scores 61, 15, 100 and 15. The text-family
// redactor used to log all four at 0.0095, its exact-match placement score / 100.
func TestTheTextRedactorsEntriesCarryTheReportsConfidence(t *testing.T) {
	lines := []string{
		"Customer record (synthetic test data)",
		"Contact email: jane.doe@example.com",
		"Payment card: 4000000000000002",
		"Phone: (555) 010-0199",
		"Backup card 5100000000000008",
	}
	src := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(src, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := func(line int, typ, text string, conf float64) detector.Match {
		return detector.Match{Text: text, Type: typ, LineNumber: line, Confidence: conf, Filename: src,
			Context: detector.ContextInfo{FullLine: lines[line-1]}}
	}
	matches := []detector.Match{
		m(2, "BUSINESS", "jane.doe@example.com", 61),
		m(3, "VISA", "4000000000000002", 15),
		m(4, "PHONE", "(555) 010-0199", 100),
		m(5, "MASTERCARD", "5100000000000008", 15),
	}
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		doc := redactAndAudit(t, src, matches, st)
		if doc.Summary.Strategy != st.String() || doc.Summary.ProcessingTimeMs <= 0 || doc.Summary.Total != 4 {
			t.Errorf("%s summary = %+v", st, doc.Summary)
		}
		got := map[string]float64{}
		lineOf := map[string]int{}
		for _, e := range doc.ContentRedactions {
			got[e.DataType] = e.Confidence
			lineOf[e.DataType] = e.Line
			if e.Strategy != st.String() {
				t.Errorf("%s entry strategy = %q", st, e.Strategy)
			}
			if e.Placement == nil || e.Placement.Method == "" || e.Placement.Score == nil {
				t.Errorf("%s %s: no placement recorded, the only trace of how the value was located", st, e.DataType)
			}
		}
		for _, mm := range matches {
			if want := mm.Confidence / 100; got[mm.Type] != want {
				t.Errorf("%s %s confidence = %v, want %v (the report's %v / 100)", st, mm.Type, got[mm.Type], want, mm.Confidence)
			}
			if lineOf[mm.Type] != mm.LineNumber {
				t.Errorf("%s %s line = %d, want the report's %d", st, mm.Type, lineOf[mm.Type], mm.LineNumber)
			}
		}
	}
}

// A JPEG's EXIF removals are metadata redactions, one per field, and no content entry claims a
// confidence the image redactor never had (it used to log each removal as IMAGE_METADATA at 0.01).
func TestAnImagesRemovalsAreListedByField(t *testing.T) {
	src := filepath.Join(t.TempDir(), "photo.jpg")
	if err := os.WriteFile(src, jpegWithTwoFields(t, "contact jane.doe@example.com", "Jane Doe"), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := redactAndAudit(t, src, []detector.Match{
		{Text: "jane.doe@example.com", Type: "BUSINESS", Confidence: 53, Filename: src},
	}, redactors.RedactionFormatPreserving)
	if len(doc.ContentRedactions) != 0 {
		t.Errorf("content_redactions = %+v, want none", doc.ContentRedactions)
	}
	var fields []string
	for _, m := range doc.MetadataRedactions {
		fields = append(fields, m.Field)
		if m.Action != "removed" {
			t.Errorf("action = %q", m.Action)
		}
	}
	sort.Strings(fields)
	if strings.Join(fields, ",") != "Artist,ImageDescription" {
		t.Errorf("metadata_redactions fields = %v, want Artist and ImageDescription", fields)
	}
}

func jpegWithTwoFields(t *testing.T, desc, artist string) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 32), G: uint8(y * 32), B: 128, A: 255})
		}
	}
	var base bytes.Buffer
	if err := jpeg.Encode(&base, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	d, a := append([]byte(desc), 0), append([]byte(artist), 0)
	var tiff bytes.Buffer
	w := func(v any) { _ = binary.Write(&tiff, binary.BigEndian, v) }
	tiff.WriteString("MM")
	w(uint16(42))
	w(uint32(8))
	w(uint16(2))
	dataOff := uint32(8 + 2 + 2*12 + 4)
	for _, e := range []struct {
		tag uint16
		v   []byte
		off uint32
	}{{0x010E, d, dataOff}, {0x013B, a, dataOff + uint32(len(d))}} {
		w(e.tag)
		w(uint16(2))
		w(uint32(len(e.v)))
		w(e.off)
	}
	w(uint32(0))
	tiff.Write(d)
	tiff.Write(a)
	payload := append([]byte("Exif\x00\x00"), tiff.Bytes()...)
	app1 := binary.BigEndian.AppendUint16([]byte{0xFF, 0xE1}, uint16(len(payload)+2))
	app1 = append(app1, payload...)
	b := base.Bytes()
	return append(append(append([]byte(nil), b[:2]...), app1...), b[2:]...)
}
