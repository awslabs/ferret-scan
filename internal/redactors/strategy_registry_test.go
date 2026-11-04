// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The registry against its declarations, and the CLI's own dispatch against what it writes (#863).
//
// External package so it can build the registry the CLI builds (core.NewDefaultRedactionManager) and
// drive a file through core.RedactFile, whose worker pool is the top-level dispatcher.

var allStrategies = []redactors.RedactionStrategy{
	redactors.RedactionSimple, redactors.RedactionFormatPreserving, redactors.RedactionSynthetic,
}

// declaredStrategies is what each registered redactor may claim. A row is a promise the byte tests
// in that redactor's package hold it to: the same-length redactors (audio, video, legacy OLE) write
// a mask under simple and refuse synthetic; image removes metadata identically under all three; PDF
// refuses every file whatever the strategy.
var declaredStrategies = map[string][]redactors.RedactionStrategy{
	"plaintext_redactor":      allStrategies,
	"office_redactor":         allStrategies,
	"svg_redactor":            allStrategies,
	"rtf_redactor":            allStrategies,
	"image_metadata_redactor": allStrategies,
	"pdf_redactor":            allStrategies,
	"audio_metadata_redactor": {redactors.RedactionSimple, redactors.RedactionFormatPreserving},
	"video_metadata_redactor": {redactors.RedactionSimple, redactors.RedactionFormatPreserving},
	"legacy_ole_redactor":     {redactors.RedactionSimple, redactors.RedactionFormatPreserving},
}

func TestEveryRegisteredRedactorHasADeclarationRow(t *testing.T) {
	manager, _, err := core.NewDefaultRedactionManager(t.TempDir(), redactors.RedactionFormatPreserving, nil)
	if err != nil {
		t.Fatal(err)
	}
	caps := manager.Capabilities()
	types := append([]string(nil), caps.Redactable...)
	for ext := range caps.Unimplemented {
		types = append(types, ext)
	}
	sort.Strings(types)

	matches := []detector.Match{{Text: "jane.doe@example.com", Type: "EMAIL", Confidence: 90}}
	dir := t.TempDir()
	seen := map[string]bool{}
	for _, ext := range types {
		// A path that does not exist: selection falls back to the extension, which is the registry's
		// own answer for the type.
		probe := filepath.Join(dir, "probe"+ext)
		r, err := manager.GetRedactorForFile(probe)
		if err != nil {
			t.Fatalf("%s is registered but GetRedactorForFile refuses it: %v", ext, err)
		}
		name := r.GetName()
		seen[name] = true
		want, ok := declaredStrategies[name]
		if !ok {
			t.Errorf("registered redactor %s (for %s) has no row in declaredStrategies; add one, and a "+
				"byte test that it writes each strategy it declares", name, ext)
			continue
		}
		if got := r.GetSupportedStrategies(); !sameStrategies(got, want) {
			t.Errorf("%s declares %v, want %v", name, got, want)
		}
		for _, s := range allStrategies {
			_, err := manager.RedactorFor(probe, s, matches)
			switch declared := hasStrategy(want, s); {
			case declared && err != nil:
				t.Errorf("RedactorFor(%s, %s) refused a declared strategy: %v", ext, s, err)
			case !declared && !errors.Is(err, redactors.ErrStrategyNotSupported):
				t.Errorf("RedactorFor(%s, %s) = %v, want ErrStrategyNotSupported", ext, s, err)
			}
		}
	}
	for name := range declaredStrategies {
		if !seen[name] {
			t.Errorf("declaredStrategies has a row for %s, which is not registered", name)
		}
	}
}

// ---------- the CLI's dispatch, end to end ----------

const (
	e2eEmail = "jane.doe@example.com"
	e2ePhone = "(555) 010-0199"
	e2eCard  = "4123456789012349"
)

// formatPreservingPartials are the pieces format_preserving keeps of the three values. Under simple
// none of them may appear in a same-length format.
var formatPreservingPartials = []string{"j*******@example.com", "(***) ***-0199", "************2349"}

func redactFile(t *testing.T, path string, strategy redactors.RedactionStrategy, checks []string) (string, []byte, error) {
	t.Helper()
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "out")
	res, err := core.RedactFile(core.RedactConfig{
		FilePath:  path,
		OutputDir: outDir,
		Strategy:  strategy.String(),
		Checks:    checks,
		Config:    cfg,
		LogWriter: io.Discard,
	})
	if err != nil {
		if artifact := anyFile(t, outDir); artifact != "" {
			t.Errorf("%s: an artifact was written beside the refusal: %s", strategy, artifact)
		}
		return outDir, nil, err
	}
	if res.Strategy != strategy.String() {
		t.Errorf("RedactResult.Strategy = %q, want %q", res.Strategy, strategy)
	}
	b, rerr := os.ReadFile(res.RedactedFilePath)
	if rerr != nil {
		t.Fatalf("%s: reading the artifact: %v", strategy, rerr)
	}
	return outDir, b, nil
}

func anyFile(t *testing.T, dir string) string {
	t.Helper()
	found := ""
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && found == "" {
			found = p
		}
		return nil
	})
	return found
}

// wavWithLabelledValues writes a RIFF/WAVE file whose LIST/INFO chunk holds the three values.
func wavWithLabelledValues(fields map[string]string) []byte {
	chunk := func(id string, payload []byte) []byte {
		out := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(out[4:], uint32(len(payload)))
		out = append(out, payload...)
		if len(payload)%2 == 1 {
			out = append(out, 0)
		}
		return out
	}
	fmtPayload := make([]byte, 16)
	binary.LittleEndian.PutUint16(fmtPayload[0:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[2:], 1)
	binary.LittleEndian.PutUint32(fmtPayload[4:], 8000)
	binary.LittleEndian.PutUint32(fmtPayload[8:], 8000)
	binary.LittleEndian.PutUint16(fmtPayload[12:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[14:], 8)
	ids := make([]string, 0, len(fields))
	for id := range fields {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	info := []byte("INFO")
	for _, id := range ids {
		info = append(info, chunk(id, append([]byte(fields[id]), 0))...)
	}
	body := append([]byte("WAVE"), chunk("fmt ", fmtPayload)...)
	body = append(body, chunk("LIST", info)...)
	body = append(body, chunk("data", []byte{1, 2, 3, 4})...)
	return chunk("RIFF", body)
}

func labelledWAV() []byte {
	return wavWithLabelledValues(map[string]string{
		"ICMT": "Email " + e2eEmail, "IART": "Phone " + e2ePhone, "INAM": "Card " + e2eCard})
}

// mp3WithLabelledValues writes an ID3v2.3 tag holding the three values, then a frame sync.
func mp3WithLabelledValues() []byte {
	var body bytes.Buffer
	for _, f := range [][2]string{{"COMM", "Email " + e2eEmail}, {"TIT2", "Card " + e2eCard}, {"TPE1", "Phone " + e2ePhone}} {
		payload := append([]byte{0}, f[1]...)
		body.WriteString(f[0])
		body.Write(binary.BigEndian.AppendUint32(nil, uint32(len(payload))))
		body.Write([]byte{0, 0})
		body.Write(payload)
	}
	n := body.Len()
	tag := []byte{'I', 'D', '3', 3, 0, 0, byte(n >> 21 & 0x7F), byte(n >> 14 & 0x7F), byte(n >> 7 & 0x7F), byte(n & 0x7F)}
	tag = append(tag, body.Bytes()...)
	return append(tag, 0xFF, 0xFB, 0x90, 0x00)
}

// jpegWithDescription encodes a real image and splices in an EXIF ImageDescription.
func jpegWithDescription(t *testing.T, desc string) []byte {
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
	d := append([]byte(desc), 0)
	var tiff bytes.Buffer
	tiff.WriteString("MM")
	_ = binary.Write(&tiff, binary.BigEndian, uint16(42))
	_ = binary.Write(&tiff, binary.BigEndian, uint32(8))
	_ = binary.Write(&tiff, binary.BigEndian, uint16(1))
	_ = binary.Write(&tiff, binary.BigEndian, uint16(0x010E)) // ImageDescription
	_ = binary.Write(&tiff, binary.BigEndian, uint16(2))      // ASCII
	_ = binary.Write(&tiff, binary.BigEndian, uint32(len(d)))
	_ = binary.Write(&tiff, binary.BigEndian, uint32(26))
	_ = binary.Write(&tiff, binary.BigEndian, uint32(0))
	tiff.Write(d)
	payload := append([]byte("Exif\x00\x00"), tiff.Bytes()...)
	app1 := binary.BigEndian.AppendUint16([]byte{0xFF, 0xE1}, uint16(len(payload)+2))
	app1 = append(app1, payload...)
	b := base.Bytes()
	out := append(append(append([]byte(nil), b[:2]...), app1...), b[2:]...)
	if !bytes.Contains(out, []byte(desc)) {
		t.Fatal("EXIF splice failed")
	}
	return out
}

// docxWith builds a minimal WordprocessingML package with one body paragraph and one extra part.
func docxWith(t *testing.T, body, partName string, part []byte) []byte {
	t.Helper()
	const o = "http://schemas.openxmlformats.org/"
	files := []struct {
		name string
		data []byte
	}{
		{"[Content_Types].xml", []byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="` + o + `package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`)},
		{"_rels/.rels", []byte(`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="` + o + `package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + o + `officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`)},
		{"word/document.xml", []byte(`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="` + o + `wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`)},
		{partName, part},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(f.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zipPart(t *testing.T, pkg []byte, name string) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			b, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatalf("no part %s in the artifact", name)
	return nil
}

func write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var e2eChecks = []string{"EMAIL", "PHONE", "CREDIT_CARD"}

// assertMasked fails if a value's format_preserving partial survives, or a value is not masked.
func assertMasked(t *testing.T, what string, b []byte) {
	t.Helper()
	for _, p := range formatPreservingPartials {
		if bytes.Contains(b, []byte(p)) {
			t.Errorf("%s under simple holds the format_preserving rendering %q", what, p)
		}
	}
	for label, v := range map[string]string{"Email ": e2eEmail, "Phone ": e2ePhone, "Card ": e2eCard} {
		if !bytes.Contains(b, []byte(label+strings.Repeat("*", len(v)))) {
			t.Errorf("%s under simple: %q is not followed by a %d-byte mask", what, label, len(v))
		}
	}
}

// TestTheCLIDispatchHonoursTheDeclaration drives a .wav through core.RedactFile, i.e. through the
// worker pool's own dispatch, which this package does not own: the audio redactor's entry check is
// what refuses synthetic there.
func TestTheCLIDispatchHonoursTheDeclaration(t *testing.T) {
	src := write(t, "clip.wav", labelledWAV())

	_, b, err := redactFile(t, src, redactors.RedactionSimple, e2eChecks)
	if err != nil {
		t.Fatalf("simple: %v", err)
	}
	assertMasked(t, "clip.wav", b)

	_, b, err = redactFile(t, src, redactors.RedactionFormatPreserving, e2eChecks)
	if err != nil {
		t.Fatalf("format_preserving: %v", err)
	}
	for _, p := range formatPreservingPartials {
		if !bytes.Contains(b, []byte(p)) {
			t.Errorf("format_preserving no longer writes %q", p)
		}
	}

	_, _, err = redactFile(t, src, redactors.RedactionSynthetic, e2eChecks)
	if err == nil || !strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("synthetic: err = %v, want a refusal naming the strategy", err)
	}
}

// TestAnEmbeddedInClassPartFollowsTheDeclaration is the embedded dispatch site end to end: a clean
// .docx carrying an .mp3 or a legacy .doc. simple masks the part; synthetic refuses the .docx and
// names the part.
func TestAnEmbeddedInClassPartFollowsTheDeclaration(t *testing.T) {
	parts := map[string][]byte{
		"word/media/clip.mp3":            mp3WithLabelledValues(),
		"word/embeddings/oleObject1.doc": olefixture.LegacyDoc("Email "+e2eEmail+"\rPhone "+e2ePhone+"\rCard "+e2eCard+"\r", nil),
	}
	for name, part := range parts {
		t.Run(name, func(t *testing.T) {
			src := write(t, "notes.docx", docxWith(t, "Quarterly notes", name, part))

			_, b, err := redactFile(t, src, redactors.RedactionSimple, e2eChecks)
			if err != nil {
				t.Fatalf("simple: %v", err)
			}
			assertMasked(t, name, zipPart(t, b, name))

			_, _, err = redactFile(t, src, redactors.RedactionSynthetic, e2eChecks)
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "synthetic") {
				t.Fatalf("synthetic: err = %v, want the .docx refused, naming %s and the strategy", err, name)
			}
		})
	}
}

// TestTheDeclarationRefusesNothingElse holds the decoys: text formats still write synthetic values,
// a clean audio file is not refused, and an image -- top level or embedded -- is redacted under every
// strategy, identically.
func TestTheDeclarationRefusesNothingElse(t *testing.T) {
	t.Run("txt keeps synthetic values", func(t *testing.T) {
		src := write(t, "rec.txt", []byte("Email "+e2eEmail+"\nPhone "+e2ePhone+"\nCard "+e2eCard+"\n"))
		_, b, err := redactFile(t, src, redactors.RedactionSynthetic, e2eChecks)
		if err != nil {
			t.Fatalf("synthetic on .txt: %v", err)
		}
		for _, v := range []string{e2eEmail, e2ePhone, e2eCard, strings.Repeat("*", len(e2eCard))} {
			if bytes.Contains(b, []byte(v)) {
				t.Errorf("synthetic on .txt wrote %q", v)
			}
		}
		if !bytes.Contains(b, []byte("@example.com")) {
			t.Errorf("synthetic on .txt did not write a synthetic address: %q", b)
		}
	})

	t.Run("clean wav is not refused", func(t *testing.T) {
		src := write(t, "clean.wav", wavWithLabelledValues(map[string]string{"INAM": "Synthetic Recording"}))
		if _, _, err := redactFile(t, src, redactors.RedactionSynthetic, e2eChecks); err != nil {
			t.Fatalf("a file with nothing to redact was refused: %v", err)
		}
	})

	jpg := jpegWithDescription(t, "contact "+e2eEmail)
	cases := map[string]func(b []byte) []byte{
		"photo.jpg":  func(b []byte) []byte { return b },
		"photo.docx": func(b []byte) []byte { return zipPart(t, b, "word/media/image1.jpeg") },
	}
	for name, part := range cases {
		t.Run(name+" under every strategy", func(t *testing.T) {
			src := write(t, name, jpg)
			if name == "photo.docx" {
				src = write(t, name, docxWith(t, "Quarterly notes", "word/media/image1.jpeg", jpg))
			}
			var first []byte
			for _, s := range allStrategies {
				_, b, err := redactFile(t, src, s, []string{"EMAIL"})
				if err != nil {
					t.Fatalf("%s: %v", s, err)
				}
				img := part(b)
				if bytes.Contains(img, []byte(e2eEmail)) {
					t.Errorf("%s: the reported address survives in the image", s)
				}
				if first == nil {
					first = img
				} else if !bytes.Equal(first, img) {
					t.Errorf("%s: the image differs from simple's; removal does not depend on the strategy", s)
				}
			}
		})
	}
}

func hasStrategy(list []redactors.RedactionStrategy, s redactors.RedactionStrategy) bool {
	for _, d := range list {
		if d == s {
			return true
		}
	}
	return false
}

func sameStrategies(a, b []redactors.RedactionStrategy) bool {
	if len(a) != len(b) {
		return false
	}
	for _, s := range a {
		if !hasStrategy(b, s) {
			return false
		}
	}
	return true
}
