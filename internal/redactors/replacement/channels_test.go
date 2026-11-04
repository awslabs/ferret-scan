// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement_test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// The email family end to end (#864): the issue's 24-type fixture, plus alias and mixed-case
// domains, through pkg/redact and through core.RedactFile on a .txt and a .docx. Every address is
// synthetic (zz.synthetic.NNNN at the providers' own domains, or a reserved one).

var providerDomains = []string{
	"gmx.de", "gmail.com", "google.com", "outlook.com", "microsoft.com", "yahoo.com", "icloud.com",
	"apple.com", "aol.com", "proton.me", "tutanota.com", "fastmail.com", "zoho.com", "yandex.com",
	"mail.ru", "salesforce.com", "slack.com", "atlassian.com", "github.com", "gitlab.com",
	"zz-synthetic.edu", "zz-synthetic.gov", "mailinator.com", "example.com",
	// Alias and mixed-case domains of the same providers.
	"hotmail.com", "pm.me", "Hotmail.COM",
}

func fixtureLines() []string {
	lines := make([]string, len(providerDomains))
	for i, d := range providerDomains {
		lines[i] = fmt.Sprintf("Contact %02d: zz.synthetic.%04d@%s", i+1, i+1, d)
	}
	return lines
}

var (
	preserved = regexp.MustCompile(`^Contact \d\d: z\*{16}@(\S+)$`)
	synthetic = regexp.MustCompile(`^Contact \d\d: [a-z0-9]{17}@example\.com$`)
)

// checkLines asserts what every line of the fixture becomes under one strategy.
func checkLines(t *testing.T, channel, strategy string, out []string) {
	t.Helper()
	lines := fixtureLines()
	if len(out) < len(lines) {
		t.Fatalf("%s %s: %d lines out, want %d", channel, strategy, len(out), len(lines))
	}
	for i, line := range lines {
		got := out[i]
		domain := providerDomains[i]
		switch strategy {
		case "simple":
			if want := line[:len("Contact 00: ")] + "[EMAIL-REDACTED]"; got != want {
				t.Errorf("%s simple line %d = %q, want %q", channel, i+1, got, want)
			}
		case "format_preserving":
			m := preserved.FindStringSubmatch(got)
			if m == nil || m[1] != domain {
				t.Errorf("%s format_preserving line %d = %q, want the first character, the mask and @%s byte for byte",
					channel, i+1, got, domain)
			}
		case "synthetic":
			if !synthetic.MatchString(got) {
				t.Errorf("%s synthetic line %d = %q, want a random 17-character local part at example.com", channel, i+1, got)
			}
		}
	}
}

var strategies = []struct {
	name string
	lib  redact.Strategy
}{
	{"simple", redact.Simple},
	{"format_preserving", redact.FormatPreserving},
	{"synthetic", redact.Synthetic},
}

func TestEveryEmailTypeThroughPkgRedact(t *testing.T) {
	text := strings.Join(fixtureLines(), "\n") + "\n"
	for _, st := range strategies {
		e, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"EMAIL"}, Strategy: st.lib})
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Redact(context.Background(), redact.Request{Text: text})
		e.Close()
		if err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		if n := len(res.Findings()); n != len(providerDomains) {
			t.Fatalf("%s: %d findings, want %d (the fixture must reach the renderer once per line)", st.name, n, len(providerDomains))
		}
		checkLines(t, "pkg/redact", st.name, strings.Split(res.Redacted, "\n"))
	}
}

func redactFile(t *testing.T, path, strategy string, checks []string) string {
	t.Helper()
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	res, err := core.RedactFile(core.RedactConfig{
		FilePath: path, OutputDir: filepath.Join(t.TempDir(), "out"), Strategy: strategy,
		Checks: checks, Config: cfg, LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile(%s, %s): %v", filepath.Base(path), strategy, err)
	}
	return res.RedactedFilePath
}

func TestEveryEmailTypeThroughATextFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "emails.txt")
	if err := os.WriteFile(src, []byte(strings.Join(fixtureLines(), "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, st := range strategies {
		b, err := os.ReadFile(redactFile(t, src, st.name, []string{"EMAIL"}))
		if err != nil {
			t.Fatal(err)
		}
		checkLines(t, ".txt", st.name, strings.Split(string(b), "\n"))
	}
}

// docx builds a WordprocessingML package: one paragraph per line, and an address in core.xml's
// subject, the property both the email and the metadata validators report.
func docx(t *testing.T, lines []string, subject string) []byte {
	t.Helper()
	const o = "http://schemas.openxmlformats.org/"
	var body strings.Builder
	for _, l := range lines {
		body.WriteString("<w:p><w:r><w:t>" + l + "</w:t></w:r></w:p>")
	}
	parts := []struct{ name, data string }{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="` + o + `package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="` + o + `package/2006/relationships">` +
			`<Relationship Id="r1" Type="` + o + `officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="r2" Type="` + o + `package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>`},
		{"word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="` + o + `wordprocessingml/2006/main"><w:body>` +
			body.String() + `</w:body></w:document>`},
		{"docProps/core.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="` + o +
			`package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:subject>` + subject +
			`</dc:subject></cp:coreProperties>`},
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(p.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func part(t *testing.T, path, name string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
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
			return string(b)
		}
	}
	t.Fatalf("no %s in %s", name, path)
	return ""
}

var wText = regexp.MustCompile(`<w:t>([^<]*)</w:t>`)

func TestEveryEmailTypeThroughADocx(t *testing.T) {
	src := filepath.Join(t.TempDir(), "rec.docx")
	if err := os.WriteFile(src, docx(t, fixtureLines(), "zz.synthetic.0004@outlook.com"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, st := range strategies {
		out := redactFile(t, src, st.name, []string{"EMAIL"})
		var got []string
		for _, m := range wText.FindAllStringSubmatch(part(t, out, "word/document.xml"), -1) {
			got = append(got, m[1])
		}
		checkLines(t, ".docx", st.name, got)
	}

	// The same core.xml value is reported as OUTLOOK by the email validator and as EMAIL by the
	// metadata validator. With both reporting it, it used to be masked whole (the OUTLOOK rendering
	// kept nothing, so the group kept nothing); now both render as an email, as --checks METADATA did.
	for _, checks := range [][]string{{"METADATA"}, nil} {
		subject := regexp.MustCompile(`<dc:subject>([^<]*)</dc:subject>`).FindStringSubmatch(
			part(t, redactFile(t, src, "format_preserving", checks), "docProps/core.xml"))
		if subject == nil || subject[1] != "z****************@outlook.com" {
			t.Errorf("checks %v: core.xml subject = %v, want z****************@outlook.com", checks, subject)
		}
	}
}
