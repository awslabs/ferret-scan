// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #886 end to end over the CLI's registry (core.NewDefaultRedactionManager): one manager is one run, and
// a value gets one synthetic replacement in every file and every format the run writes. Synthetic
// values only (SSN 234-56-000N, example.org, fictional names).

const (
	e2eSSN    = "234-56-0001"
	e2eSSNRE  = `\d{3}-\d{2}-\d{4}`
	e2eHolder = "Dana Whitfield"
)

func defaultManager(t *testing.T) *redactors.RedactionManager {
	t.Helper()
	m, _, err := core.NewDefaultRedactionManager(t.TempDir(), redactors.RedactionSynthetic, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// minimalDocx is a one-paragraph .docx.
func minimalDocx(t *testing.T, body string) []byte {
	t.Helper()
	const o = "http://schemas.openxmlformats.org/"
	files := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="` + o + `package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="` + o + `package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + o + `officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="` + o + `wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		w, err := zw.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, f[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// readable is what a reader of the output sees: the file, or a .docx's document part.
func readable(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".docx") {
		return string(b)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
	t.Fatalf("%s has no word/document.xml", path)
	return ""
}

// redactWith runs one file through the manager's redactor for it, as the worker pool does: through
// RedactContent when the redactor offers it, RedactDocument otherwise.
func redactWith(t *testing.T, m *redactors.RedactionManager, in, out string, ms []detector.Match) {
	t.Helper()
	r, err := m.GetRedactorForFile(in)
	if err != nil {
		t.Fatal(err)
	}
	if cr, ok := r.(redactors.ContentRedactor); ok {
		raw, err := os.ReadFile(in)
		if err != nil {
			t.Fatal(err)
		}
		content := &preprocessors.ProcessedContent{OriginalPath: in, Filename: filepath.Base(in), Text: string(raw), Success: true}
		if _, err := cr.RedactContent(content, out, ms, redactors.RedactionSynthetic); err != nil {
			t.Fatalf("%s: %v", filepath.Base(in), err)
		}
		return
	}
	if _, err := r.RedactDocument(in, out, ms, redactors.RedactionSynthetic); err != nil {
		t.Fatalf("%s: %v", filepath.Base(in), err)
	}
}

func ssnMatches(line string, n int) []detector.Match {
	ms := make([]detector.Match, n)
	for i := range ms {
		ms[i] = detector.Match{Text: e2eSSN, Type: "SSN", Confidence: 95, LineNumber: 1, Validator: "ssn",
			Context: detector.ContextInfo{FullLine: line}}
	}
	return ms
}

// One SSN in five formats, one run: one replacement. Every redactor of the registry that writes
// synthetic values shares the manager's scope.
func TestOneValueOneReplacementAcrossFormats(t *testing.T) {
	m := defaultManager(t)
	dir := t.TempDir()
	files := map[string][]byte{
		"a.txt":  []byte("SSN: " + e2eSSN + "\n"),
		"b.csv":  []byte("id,ssn\n1," + e2eSSN + "\n"),
		"c.svg":  []byte(`<svg xmlns="http://www.w3.org/2000/svg"><text x="1" y="20">SSN ` + e2eSSN + `</text></svg>` + "\n"),
		"d.rtf":  []byte(`{\rtf1\ansi{\fonttbl\f0 Helvetica;}\f0 SSN ` + e2eSSN + `\par}` + "\n"),
		"e.docx": minimalDocx(t, "SSN "+e2eSSN),
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	written := map[string]bool{}
	for _, n := range names {
		in, out := filepath.Join(dir, n), filepath.Join(dir, "out-"+n)
		if err := os.WriteFile(in, files[n], 0o600); err != nil {
			t.Fatal(err)
		}
		redactWith(t, m, in, out, ssnMatches("SSN "+e2eSSN, 1))
		text := readable(t, out)
		if strings.Contains(text, e2eSSN) {
			t.Fatalf("%s: the SSN survived", n)
		}
		got := regexp.MustCompile(e2eSSNRE).FindAllString(text, -1)
		if len(got) != 1 {
			t.Fatalf("%s: %d SSN-shaped values in the output: %q", n, len(got), text)
		}
		written[got[0]] = true
	}
	if len(written) != 1 {
		t.Errorf("one SSN in %d formats of one run was written as %d values: %v", len(files), len(written), written)
	}
}

// #886 case D: one name in 24 files, redacted concurrently by one manager. The name database race
// wrote the placeholder in 1 to 7 of the 24, and the other files got 17 to 24 different fakes.
func TestOneNameInManyFilesIsOneFake(t *testing.T) {
	m := defaultManager(t)
	dir := t.TempDir()
	var wg sync.WaitGroup
	outs := make([]string, 24)
	errs := make([]error, 24)
	for i := range outs {
		content := fmt.Sprintf("Customer record %02d\nName: %s\nNotes: called back.\n", i+1, e2eHolder)
		in := filepath.Join(dir, fmt.Sprintf("rec%02d.txt", i+1))
		if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		outs[i] = filepath.Join(dir, fmt.Sprintf("out%02d.txt", i+1))
		ms := []detector.Match{{Text: e2eHolder, Type: "PERSON_NAME", Confidence: 100, LineNumber: 2, Validator: "PERSON_NAME",
			Context: detector.ContextInfo{FullLine: "Name: " + e2eHolder}}}
		wg.Add(1)
		go func(i int, in string) {
			defer wg.Done()
			r, err := m.GetRedactorForFile(in)
			if err == nil {
				_, err = r.RedactDocument(in, outs[i], ms, redactors.RedactionSynthetic)
			}
			errs[i] = err
		}(i, in)
	}
	wg.Wait()
	names := map[string]int{}
	for i, out := range outs {
		if errs[i] != nil {
			t.Fatalf("file %d: %v", i+1, errs[i])
		}
		for _, line := range strings.Split(readable(t, out), "\n") {
			if strings.HasPrefix(line, "Name: ") {
				names[strings.TrimPrefix(line, "Name: ")]++
			}
		}
	}
	if len(names) != 1 {
		t.Fatalf("one name in 24 files was written as %d values: %v", len(names), names)
	}
	for n := range names {
		if strings.Contains(n, "REDACTED") || n == e2eHolder {
			t.Errorf("the name was written as %q", n)
		}
	}
}

// A seeded run is byte-identical however its files are scheduled: draws depend on the value, never on
// what was drawn before it. The seed is a test hook (redactors.NewSeededSyntheticScope); nothing a user
// sets reaches it.
func TestASeededRunIsReproducible(t *testing.T) {
	dir := t.TempDir()
	type file struct {
		name string
		body string
		ms   []detector.Match
	}
	line := func(s string) detector.ContextInfo { return detector.ContextInfo{FullLine: s} }
	files := []file{
		{"one.txt", "SSN " + e2eSSN + "\nName: " + e2eHolder + "\n", []detector.Match{
			{Text: e2eSSN, Type: "SSN", Confidence: 95, LineNumber: 1, Context: line("SSN " + e2eSSN)},
			{Text: e2eHolder, Type: "PERSON_NAME", Confidence: 100, LineNumber: 2, Context: line("Name: " + e2eHolder)}}},
		{"two.txt", "contact dana.whitfield@example.org\nSSN 234-56-0002\n", []detector.Match{
			{Text: "dana.whitfield@example.org", Type: "BUSINESS", Confidence: 60, LineNumber: 1, Context: line("contact dana.whitfield@example.org")},
			{Text: "234-56-0002", Type: "SSN", Confidence: 95, LineNumber: 2, Context: line("SSN 234-56-0002")}}},
		{"three.txt", "SSN 234-56-0002 and " + e2eSSN + "\n", []detector.Match{
			{Text: "234-56-0002", Type: "SSN", Confidence: 95, LineNumber: 1, Context: line("SSN 234-56-0002 and " + e2eSSN)},
			{Text: e2eSSN, Type: "SSN", Confidence: 95, LineNumber: 1, Context: line("SSN 234-56-0002 and " + e2eSSN)}}},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(seed string, order []int) map[string]string {
		m := defaultManager(t)
		m.SetSyntheticScope(redactors.NewSeededSyntheticScope([]byte(seed)))
		outDir := t.TempDir()
		out := map[string]string{}
		for _, i := range order {
			f := files[i]
			dst := filepath.Join(outDir, f.name)
			redactWith(t, m, filepath.Join(dir, f.name), dst, f.ms)
			out[f.name] = readable(t, dst)
		}
		return out
	}
	a := run("seed-886", []int{0, 1, 2})
	b := run("seed-886", []int{2, 1, 0})
	for _, f := range files {
		if a[f.name] != b[f.name] {
			t.Errorf("%s differs between two runs with one seed:\n%s\n---\n%s", f.name, a[f.name], b[f.name])
		}
		if strings.Contains(a[f.name], e2eSSN) || strings.Contains(a[f.name], "234-56-0002") || strings.Contains(a[f.name], e2eHolder) {
			t.Errorf("%s: a value survived:\n%s", f.name, a[f.name])
		}
	}
	if c := run("another seed", []int{0, 1, 2}); c["one.txt"] == a["one.txt"] {
		t.Error("a different seed wrote the same bytes")
	}
}

// Every registered redactor that declares synthetic receives the manager's scope. One that did not
// would refuse synthetic (no scope) -- or, if it drew some other way, give each of its files values of
// their own.
func TestEveryRedactorThatWritesSyntheticGetsTheScope(t *testing.T) {
	m := defaultManager(t)
	caps := m.Capabilities()
	dir := t.TempDir()
	seen := map[string]bool{}
	for _, ext := range caps.Redactable {
		r, err := m.GetRedactorForFile(filepath.Join(dir, "probe"+ext))
		if err != nil || seen[r.GetName()] {
			continue
		}
		seen[r.GetName()] = true
		_, user := r.(redactors.SyntheticScopeUser)
		declares := false
		for _, s := range r.GetSupportedStrategies() {
			declares = declares || s == redactors.RedactionSynthetic
		}
		// image and pdf declare synthetic but write no synthetic value (metadata removal; refusal).
		writesNone := r.GetName() == "image_metadata_redactor" || r.GetName() == "pdf_redactor"
		if declares && !writesNone && !user {
			t.Errorf("%s declares synthetic but takes no synthetic scope", r.GetName())
		}
	}
	for _, name := range []string{"plaintext_redactor", "office_redactor", "svg_redactor", "rtf_redactor"} {
		if !seen[name] {
			t.Errorf("%s is not registered", name)
		}
	}
}
