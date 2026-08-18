// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
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
