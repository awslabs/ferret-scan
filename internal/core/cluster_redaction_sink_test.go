// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// A clustered social-media finding must not survive redaction in cleartext.
//
// This is the assertion the existing gates could not make. SOCIAL_MEDIA_CLUSTER appears
// in ZERO golden-corpus and ZERO score-corpus cases, and the only cluster test in the
// tree asserts partition stability, not redaction — so the leak was outside everything
// that runs on every change.
//
// Clustering replaced the matches it grouped with ONE synthesized match whose Text is a
// rendered summary ("twitter: janedoe | linkedin: janedoe") occurring nowhere in the
// document. Every redactor locates a match by searching for its Text, so the cluster
// masked nothing while the real spans had already been dropped from the returned slice.
//
// Measured on the shipped binary with the shipped config, before the fix:
//
//	[HIGH] SOCIAL_MEDIA SOCIAL_MEDIA_CLUSTER 95.00% line 1
//	Files: 1 scanned | Findings: 1 (1 high)
//	diff input redacted  ->  IDENTICAL
//
// for simple, synthetic AND format_preserving. One HIGH finding at 95% and both handles
// in the clear. See #289.
//
// It goes through core.RedactFile — the public path pkg/redact and the CLI both reach —
// and asserts on the BYTES of the written file, because that is the only assertion that
// distinguishes "reported" from "removed".
func TestClusteredSocialMediaDoesNotSurviveRedaction(t *testing.T) {
	// Platform patterns must be supplied: SOCIAL_MEDIA ships none built-in, so with a
	// default config the scan reports nothing and there is no leak to observe. These
	// mirror the shipped examples/ferret.yaml, minus its instagram trailing-slash bug
	// (#343), which is why instagram is not used here.
	cfg := config.LoadConfigOrDefault("")
	if cfg.Validators == nil {
		cfg.Validators = map[string]map[string]any{}
	}
	cfg.Validators["social_media"] = map[string]any{
		"platform_patterns": map[string]any{
			"twitter": []any{
				`(?i)https?://(?:www\.)?(twitter|x)\.com/[a-zA-Z0-9_]+`,
			},
			"linkedin": []any{
				`(?i)https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+`,
			},
		},
		"positive_keywords": []any{"profile", "connect with me"},
	}

	const (
		twitterURL  = "https://twitter.com/janedoe"
		linkedinURL = "https://linkedin.com/in/janedoe"
	)
	// Multi-line on purpose: a cluster's own LineNumber/FullLine name only the primary
	// sub-match's line, so a fix that restored to the full line would mask line 1 and
	// leave line 3 in the clear.
	content := "Profile: " + twitterURL + "\n" +
		"connect with me\n" +
		"And " + linkedinURL + "\n"

	// NOT under a path containing "tmp": exclude_patterns in the shipped config include
	// "tmp", and a fixture there is skipped before it is ever scanned. t.TempDir() is
	// safe here only because this test supplies its own config; the note stands as a
	// warning for anyone reproducing by hand.
	dir := t.TempDir()
	src := filepath.Join(dir, "cluster.txt")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, strategy := range []string{"simple", "format_preserving", "synthetic"} {
		t.Run(strategy, func(t *testing.T) {
			outDir := filepath.Join(dir, "out-"+strategy)
			res, err := RedactFile(RedactConfig{
				FilePath:  src,
				OutputDir: outDir,
				Strategy:  strategy,
				Checks:    []string{"SOCIAL_MEDIA"},
				Config:    cfg,
			})
			if err != nil {
				t.Fatalf("RedactFile: %v", err)
			}
			if res == nil {
				t.Fatal("RedactFile returned no result")
			}

			// Non-vacuity: the fixture must actually produce a clustered finding. If
			// clustering stops firing (a config change, a threshold change) this test
			// would otherwise pass while asserting nothing about clusters at all.
			var sawCluster bool
			for _, m := range res.Matches {
				if m.Type == "SOCIAL_MEDIA_CLUSTER" {
					sawCluster = true
				}
			}
			if len(res.Matches) == 0 {
				t.Fatal("no findings at all — the fixture or its platform patterns no longer " +
					"detect anything, so this test cannot observe the leak")
			}
			if !sawCluster {
				t.Fatalf("no SOCIAL_MEDIA_CLUSTER among %d finding(s) — clustering did not fire, "+
					"so this test is not exercising the clustered path", len(res.Matches))
			}

			// Find the written file and read its BYTES.
			var written string
			err = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !info.IsDir() && filepath.Base(p) == "cluster.txt" {
					written = p
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk output dir: %v", err)
			}
			if written == "" {
				t.Fatalf("no redacted copy was written under %s — a clustered finding must "+
					"either be redacted or refused, never silently skipped", outDir)
			}
			got, err := os.ReadFile(written) // #nosec G304 -- test temp dir
			if err != nil {
				t.Fatal(err)
			}
			out := string(got)

			if out == content {
				t.Fatalf("the redacted file is BYTE-IDENTICAL to the input — every clustered "+
					"handle survived in cleartext.\ninput:    %q\nredacted: %q", content, out)
			}
			// Each real span, on its own line, must be gone. Asserting both is what
			// catches a fix that only covers the cluster's primary line.
			for _, secret := range []string{twitterURL, linkedinURL} {
				if strings.Contains(out, secret) {
					t.Errorf("redacted output still contains %q — it was reported (inside the "+
						"cluster) and not removed:\n%s", secret, out)
				}
			}
			// The synthesized summary must never be written INTO the document either.
			if strings.Contains(out, "twitter: janedoe") || strings.Contains(out, "|") {
				t.Errorf("the consolidated summary leaked into the redacted document:\n%s", out)
			}
		})
	}
}

// A clustered value inside an EMBEDDED part must be redacted, not merely refused.
//
// The office redactor has TWO consumers of Match.Text: redactOfficeContent and
// redactEmbeddedParts. The cluster expansion lived inside the former, which takes `matches`
// as a parameter, so reassigning it there normalized only that local slice — and the
// ORIGINAL slice was handed to the embedded path. That path builds the residue value set
// used by both the dispatch gate and the post-redaction verification, so a cluster's
// rendered summary made every part look clean: the part holding the real handles was never
// dispatched, and the fail-closed refusal never fired.
//
// Measured on a binary built from fefc0ee: 2 HIGH findings, rc=0, body cleaned, embedded
// inner.docx still holding BOTH handles verbatim.
//
// This goes through core.RedactFile because only the real wiring injects an embedded
// dispatcher — a bare OfficeRedactor has none and correctly refuses instead, which proves
// "no leaking output" but not that the part is actually redacted.
func TestClusteredValueInsideEmbeddedPartIsRedactedEndToEnd(t *testing.T) {
	cfg := config.LoadConfigOrDefault("")
	if cfg.Validators == nil {
		cfg.Validators = map[string]map[string]any{}
	}
	cfg.Validators["social_media"] = map[string]any{
		"platform_patterns": map[string]any{
			"twitter":  []any{`(?i)https?://(?:www\.)?(twitter|x)\.com/[a-zA-Z0-9_]+`},
			"linkedin": []any{`(?i)https?://(?:www\.)?linkedin\.com/in/[a-zA-Z0-9_-]+`},
		},
		"positive_keywords": []any{"profile", "connect with me"},
	}

	const (
		twitterURL  = "https://twitter.com/janedoe"
		linkedinURL = "https://linkedin.com/in/janedoe"
	)
	body := `<w:p><w:r><w:t>Profile: ` + twitterURL + `</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>connect with me</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>And ` + linkedinURL + `</w:t></w:r></w:p>`

	dir := t.TempDir()
	src := filepath.Join(dir, "outer.docx")
	writeEmbeddedDocx(t, src, body, buildInnerDocx(t, body))

	outDir := filepath.Join(dir, "out")
	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: outDir,
		Strategy:  "simple",
		Checks:    []string{"SOCIAL_MEDIA"},
		Config:    cfg,
	})
	if err != nil {
		// A refusal is safe, but then nothing may have been written.
		if written := findWritten(t, outDir, "outer.docx"); written != "" {
			t.Fatalf("RedactFile errored (%v) but still wrote %s", err, written)
		}
		return
	}

	// Non-vacuity: the fixture must actually produce a cluster.
	var sawCluster bool
	for _, m := range res.Matches {
		if m.Type == "SOCIAL_MEDIA_CLUSTER" {
			sawCluster = true
		}
	}
	if !sawCluster {
		t.Fatalf("no SOCIAL_MEDIA_CLUSTER among %d finding(s) — clustering did not fire, so this "+
			"test is not exercising the clustered embedded path", len(res.Matches))
	}

	written := findWritten(t, outDir, "outer.docx")
	if written == "" {
		return // refused to write: safe
	}
	for _, secret := range []string{twitterURL, linkedinURL} {
		if embeddedPartContains(t, written, secret) {
			t.Errorf("the EMBEDDED part of the written container still contains %q — it was "+
				"reported inside a cluster and the container was written anyway", secret)
		}
	}
}

// writeEmbeddedDocx builds a .docx whose body holds bodyText and which embeds inner at
// word/embeddings/inner.docx.
func writeEmbeddedDocx(t *testing.T, path, bodyText string, inner []byte) {
	t.Helper()

	const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Default Extension="docx" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`</Relationships>`
	doc := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		bodyText + `</w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range []struct{ name, body string }{
		{"[Content_Types].xml", ct}, {"_rels/.rels", rels}, {"word/document.xml", doc},
	} {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			t.Fatal(err)
		}
	}
	if inner != nil {
		w, err := zw.Create("word/embeddings/inner.docx")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(inner); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildInnerDocx returns the bytes of a standalone .docx holding bodyText.
func buildInnerDocx(t *testing.T, bodyText string) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inner.docx")
	writeEmbeddedDocx(t, p, bodyText, nil)
	b, err := os.ReadFile(p) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// findWritten locates a written file by base name beneath dir, or "" if none.
func findWritten(t *testing.T, dir, base string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // the dir may not exist when the write was refused
		}
		if !info.IsDir() && filepath.Base(p) == base {
			found = p
		}
		return nil
	})
	return found
}

// embeddedPartContains reports whether value survives inside an embedded .docx of path.
//
// It inflates the NESTED package: grepping its compressed bytes finds nothing whether or not
// redaction worked, which is how this defect stayed invisible.
func embeddedPartContains(t *testing.T, path, value string) bool {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if filepath.Ext(f.Name) != ".docx" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		nested, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		nz, err := zip.NewReader(bytes.NewReader(nested), int64(len(nested)))
		if err != nil {
			continue
		}
		for _, nf := range nz.File {
			nrc, err := nf.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(nrc)
			nrc.Close()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(body, []byte(value)) {
				return true
			}
		}
	}
	return false
}
