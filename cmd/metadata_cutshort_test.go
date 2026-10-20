// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #771, end to end. With METADATA not selected, any coverage cut-short on a metadata-capable file
// (office, PDF, image, audio, video) discarded EVERY finding for the file and the disclosure with
// it: exit 0 under --fail-on-incomplete, an empty stderr, no SARIF notification, no redacted copy.
// The same text as .txt kept its findings and exited 3. These runs are the issue's acceptance
// criteria on the real binary, over containers built in the test.

// cutShortDocx is a minimal .docx: one paragraph per element of paras, plus docProps/core.xml with
// an author, so the file takes the dual-extractor arm a real Word file takes.
func cutShortDocx(t *testing.T, paras []string) []byte {
	t.Helper()
	const w = "http://schemas.openxmlformats.org/"
	var body strings.Builder
	for _, p := range paras {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`)
	}
	parts := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="` + w + `package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="` + w + `package/2006/relationships">` +
			`<Relationship Id="rId1" Type="` + w + `officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="` + w + `package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`},
		{"word/document.xml", `<w:document xmlns:w="` + w + `wordprocessingml/2006/main"><w:body>` + body.String() + `</w:body></w:document>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="` + w +
			`package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Sample Author</dc:creator></cp:coreProperties>`},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		f, err := zw.Create(p[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(p[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// cutShortEmails is the issue's small fixture: ten addresses under the reserved example.com.
func cutShortEmails() []string {
	paras := make([]string, 0, 10)
	for i := 1; i <= 10; i++ {
		paras = append(paras, fmt.Sprintf("Contact user%05d@example.com for the record.", i))
	}
	return paras
}

// cutShortCapParas is the issue's cap fixture: one address, then 4,560 copies of a neutral
// 1,150-byte filler, which puts the body at 5,248,606 bytes, just over CLOUD_RESOURCES's
// 5,242,880-byte cap. The deflated .docx is about 28 KB.
func cutShortCapParas() []string {
	filler := strings.Repeat("the quarterly report covers routine operational matters for the period under review ", 14)[:1150]
	paras := []string{"Contact user00001@example.com for the record."}
	for i := 0; i < 4560; i++ {
		paras = append(paras, filler)
	}
	return paras
}

type cutShortRun struct {
	rc     int
	stdout string
	stderr string
	report struct {
		Stats struct {
			FilesNotExamined int `json:"files_not_examined"`
		} `json:"stats"`
		Results []struct {
			Filename string `json:"filename"`
		} `json:"results"`
	}
}

func runCutShort(t *testing.T, bin, dir string, args ...string) cutShortRun {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = isolatedEnv(t, dir)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	r := cutShortRun{stdout: so.String(), stderr: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	if strings.HasPrefix(strings.TrimSpace(r.stdout), "{") {
		if jerr := json.Unmarshal([]byte(r.stdout), &r.report); jerr != nil {
			t.Fatalf("parse JSON report: %v\nstdout: %.400s", jerr, r.stdout)
		}
	}
	return r
}

func writeCutShortFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMetadataCapableFileKeepsFindingsOnACutShort(t *testing.T) {
	bin := buildForExitTest(t)
	jsonArgs := []string{"--fail-on-incomplete", "--format", "json", "--confidence", "all", "--limit", "0", "--config", os.DevNull}

	t.Run("budget docx", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "small.docx", cutShortDocx(t, cutShortEmails()))

		control := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "EMAIL,PHONE"}, jsonArgs...)...)
		if control.rc != 0 || len(control.report.Results) != 10 {
			t.Fatalf("control (no budget): rc %d, %d findings; want rc 0, 10\nstderr: %s", control.rc, len(control.report.Results), control.stderr)
		}

		run := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "EMAIL,PHONE",
			"--validator-budget", "PHONE=1ns"}, jsonArgs...)...)
		if run.rc != 3 || len(run.report.Results) != 10 || run.report.Stats.FilesNotExamined != 1 {
			t.Errorf("PHONE=1ns on a .docx without METADATA: rc %d, %d findings, files_not_examined %d; "+
				"want rc 3, 10, 1. PHONE's budget never touched EMAIL, so losing its findings, or exiting 0, "+
				"reports a partly scanned file as clean.\nstderr: %s",
				run.rc, len(run.report.Results), run.report.Stats.FilesNotExamined, run.stderr)
		}
	})

	t.Run("cap docx", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "cap.docx", cutShortDocx(t, cutShortCapParas()))

		control := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "EMAIL"}, jsonArgs...)...)
		if control.rc != 0 || len(control.report.Results) != 1 {
			t.Fatalf("control (EMAIL only): rc %d, %d findings; want rc 0, 1", control.rc, len(control.report.Results))
		}

		// No budget at all: CLOUD_RESOURCES declines the oversize body, which is the #414 disclosure
		// that #424 turned into a total loss on metadata-capable files.
		run := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "EMAIL,CLOUD_RESOURCES"}, jsonArgs...)...)
		if run.rc != 3 || len(run.report.Results) != 1 {
			t.Errorf("EMAIL,CLOUD_RESOURCES on a .docx over the size cap: rc %d, %d findings; want rc 3, 1\nstderr: %s",
				run.rc, len(run.report.Results), run.stderr)
		}
		if !strings.Contains(run.stderr, "byte cap") {
			t.Errorf("stderr does not name the cap that fired:\n%s", run.stderr)
		}
	})

	t.Run("docx and txt directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		scanDir := filepath.Join(dir, "in")
		if err := os.Mkdir(scanDir, 0o750); err != nil {
			t.Fatal(err)
		}
		writeCutShortFile(t, scanDir, "small.docx", cutShortDocx(t, cutShortEmails()))
		writeCutShortFile(t, scanDir, "small.txt", []byte(strings.Join(cutShortEmails(), "\n")+"\n"))

		run := runCutShort(t, bin, dir, append([]string{"--file", scanDir, "--recursive", "--checks", "EMAIL,PHONE",
			"--validator-budget", "PHONE=1ns"}, jsonArgs...)...)
		files := map[string]int{}
		for _, r := range run.report.Results {
			files[r.Filename]++
		}
		if run.rc != 3 || files["small.docx"] != 10 || files["small.txt"] != 10 {
			t.Errorf("rc %d, findings per file %v; want rc 3 and 10 in each: the .docx was reported "+
				"clean while its .txt twin was disclosed\nstderr: %s", run.rc, files, run.stderr)
		}
		if !strings.Contains(run.stderr, "2 of 2 files") {
			t.Errorf("stderr does not count both files as not fully examined:\n%s", run.stderr)
		}
	})

	t.Run("precommit profile", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "small.docx", cutShortDocx(t, cutShortEmails()))

		// The built-in precommit profile's checks omit METADATA (internal/config), as does the
		// examples/ferret.yaml one.
		run := runCutShort(t, bin, dir, append([]string{"--file", docx, "--profile", "precommit",
			"--validator-budget", "SSN=1ns"}, jsonArgs...)...)
		if run.rc != 3 || len(run.report.Results) != 10 {
			t.Errorf("--profile precommit with SSN=1ns: rc %d, %d findings; want rc 3, 10\nstderr: %s",
				run.rc, len(run.report.Results), run.stderr)
		}
	})

	t.Run("redaction", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "small.docx", cutShortDocx(t, cutShortEmails()))
		out := filepath.Join(dir, "redacted")

		run := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "EMAIL,PHONE",
			"--validator-budget", "PHONE=1ns", "--enable-redaction", "--redaction-output-dir", out,
			"--redaction-strategy", "simple"}, jsonArgs...)...)
		if run.rc != 3 {
			t.Errorf("rc %d, want 3\nstderr: %s", run.rc, run.stderr)
		}
		var copies []string
		_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && strings.HasSuffix(p, ".docx") {
				copies = append(copies, p)
			}
			return nil
		})
		if len(copies) != 1 {
			t.Fatalf("redacted copies: %v, want exactly one. A scan that reports nothing writes no copy, "+
				"so the operator is left holding the original.", copies)
		}
		zr, err := zip.OpenReader(copies[0])
		if err != nil {
			t.Fatal(err)
		}
		defer zr.Close()
		address := regexp.MustCompile(`user\d{5}@example\.com`)
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			var b bytes.Buffer
			_, _ = b.ReadFrom(rc)
			rc.Close()
			if n := len(address.FindAll(b.Bytes(), -1)); n != 0 {
				t.Errorf("%s in the redacted copy still holds %d cleartext addresses", f.Name, n)
			}
		}
	})

	t.Run("sarif", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "small.docx", cutShortDocx(t, cutShortEmails()))
		sarif := filepath.Join(dir, "out.sarif")

		run := runCutShort(t, bin, dir, "--file", docx, "--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns",
			"--fail-on-incomplete", "--format", "sarif", "--output", sarif, "--confidence", "all", "--limit", "0",
			"--config", os.DevNull)
		raw, err := os.ReadFile(sarif) // #nosec G304 -- test temp dir
		if err != nil {
			t.Fatalf("no SARIF written: %v\nstderr: %s", err, run.stderr)
		}
		var doc struct {
			Runs []struct {
				Results     []json.RawMessage `json:"results"`
				Invocations []struct {
					Notifications []json.RawMessage `json:"toolExecutionNotifications"`
				} `json:"invocations"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Runs) != 1 {
			t.Fatalf("parse SARIF: %v (runs %d)", err, len(doc.Runs))
		}
		notes := 0
		for _, inv := range doc.Runs[0].Invocations {
			notes += len(inv.Notifications)
		}
		if len(doc.Runs[0].Results) != 10 || notes == 0 {
			t.Errorf("SARIF has %d results and %d toolExecutionNotifications; want 10 and at least 1, "+
				"or a code-scanning consumer sees a clean, complete run", len(doc.Runs[0].Results), notes)
		}
	})

	t.Run("METADATA budget", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		docx := writeCutShortFile(t, dir, "small.docx", cutShortDocx(t, cutShortEmails()))

		control := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "METADATA"}, jsonArgs...)...)
		if control.rc != 0 || len(control.report.Results) != 1 {
			t.Fatalf("control: rc %d, %d findings; want rc 0, 1", control.rc, len(control.report.Results))
		}
		// Accepted and ignored before #771: the same one finding at rc 0.
		for _, spec := range []string{"METADATA=1ns", "all=1ns"} {
			run := runCutShort(t, bin, dir, append([]string{"--file", docx, "--checks", "METADATA",
				"--validator-budget", spec}, jsonArgs...)...)
			if run.rc != 3 {
				t.Errorf("--validator-budget %s with --checks METADATA: rc %d with %d findings; want rc 3. "+
					"An accepted budget that does nothing is the silently ignored budget the flag promises "+
					"not to have.", spec, run.rc, len(run.report.Results))
			}
		}
	})

	t.Run("help", func(t *testing.T) {
		t.Parallel()
		run := runCutShort(t, bin, t.TempDir(), "--help")
		var line string
		for _, l := range strings.Split(run.stdout+run.stderr, "\n") {
			if strings.Contains(l, "--validator-budget") && strings.Contains(l, "NAME=DURATION") {
				line = l
			}
		}
		if !strings.Contains(line, "METADATA") || !strings.Contains(line, "between metadata items") {
			t.Errorf("--help does not say how a METADATA budget applies:\n%s", line)
		}
	})
}
