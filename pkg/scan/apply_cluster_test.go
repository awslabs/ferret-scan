// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clusterFixture writes a config that turns SOCIAL_MEDIA on and returns a 3-line input whose handles
// cluster.
//
// SOCIAL_MEDIA ships NO platform patterns, so a default config detects nothing at all and a test written
// without this would pass against a scan that found zero findings — the vacuity #293 is about. The
// patterns mirror examples/ferret.yaml.
//
// THREE LINES, not one, and that is the whole point: a cluster's LineNumber and Context.FullLine carry
// only its primary member's line, so a single-line fixture is masked by the FullLine restore alone and
// proves nothing about clusters.
func clusterFixture(t *testing.T) (text, cfgPath string) {
	t.Helper()
	cfgPath = filepath.Join(t.TempDir(), "ferret.yaml")
	cfg := "validators:\n" +
		"  social_media:\n" +
		"    platform_patterns:\n" +
		"      twitter:\n" +
		"        - \"(?i)https?://(?:www\\\\.)?(twitter|x)\\\\.com/[a-zA-Z0-9_]+\"\n" +
		"      linkedin:\n" +
		"        - \"(?i)https?://(?:www\\\\.)?linkedin\\\\.com/in/[a-zA-Z0-9_-]+\"\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return "Profile: https://twitter.com/janedoe\nconnect with me\nAnd https://linkedin.com/in/janedoe\n", cfgPath
}

// TestRedactTextMasksEveryMemberOfAConsolidatedFinding is #631's sink test.
//
// A cluster's Text is a rendered summary ("linkedin: janedoe | twitter: janedoe") that occurs nowhere in
// the document, so it masks nothing on its own. Before Finding.ClusterMembers existed, RedactText dropped
// the members at the public boundary, redactors.ExpandClusterMatches found nothing to expand, and the
// handles stayed in the clear — while Count reported them redacted:
//
//	simple / synthetic / format_preserving:  Count=1  len(findings)=1  'janedoe' still present: 1
//
// Count could not reveal it: one mapping genuinely occurred (the handle on the cluster's own line), so the
// documented Count < len(findings) check read 1 < 1 and said COMPLETE.
func TestRedactTextMasksEveryMemberOfAConsolidatedFinding(t *testing.T) {
	text, cfgPath := clusterFixture(t)

	res, err := ScanText(context.Background(), text, TextOptions{
		Checks:     []string{"SOCIAL_MEDIA"},
		ConfigPath: cfgPath,
	})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}

	// Non-vacuity, in three parts. Without all three this test would pass against a scan that produced
	// no cluster at all, which is the failure mode it exists to catch.
	if len(res.Findings) == 0 {
		t.Fatal("no findings: the fixture never reached the cluster path, so nothing below is tested")
	}
	var cluster *Finding
	for i := range res.Findings {
		if len(res.Findings[i].ClusterMembers) > 0 {
			cluster = &res.Findings[i]
			break
		}
	}
	if cluster == nil {
		t.Fatalf("no finding carries ClusterMembers, so the carrier is not populated and this test would "+
			"pass for the wrong reason. findings=%d, first type=%q", len(res.Findings), res.Findings[0].Type)
	}
	if len(cluster.ClusterMembers) < 2 {
		t.Fatalf("the cluster has %d member(s); a single-member cluster does not span lines and cannot "+
			"exhibit the defect", len(cluster.ClusterMembers))
	}
	// The members must sit on DIFFERENT lines, or a FullLine restore alone would have masked them and the
	// carrier is not what is being tested.
	lines := map[int]bool{}
	for _, m := range cluster.ClusterMembers {
		lines[m.LineNumber] = true
	}
	if len(lines) < 2 {
		t.Fatalf("all %d members are on line %v; the fixture must span lines for this to be about "+
			"clusters rather than about RestoreBoundedMatchText", len(cluster.ClusterMembers), lines)
	}
	t.Logf("cluster %q with %d members across %d lines", cluster.Type, len(cluster.ClusterMembers), len(lines))

	for _, tc := range []struct {
		name     string
		strategy RedactStrategy
	}{
		{"simple", StrategySimple},
		{"synthetic", StrategySynthetic},
		{"format_preserving", StrategyFormatPreserving},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RedactText(text, res.Findings, tc.strategy)
			if err != nil {
				t.Fatalf("RedactText: %v", err)
			}

			// THE SINK. Every member's value must be gone from the output, whichever line it was on.
			for _, m := range cluster.ClusterMembers {
				if strings.Contains(out.Text, m.Text) {
					t.Errorf("member %q (line %d) is still in the redacted output — this is the #631 leak. "+
						"Count=%d, len(findings)=%d, so the documented Count < len(findings) check reports "+
						"COMPLETE.\noutput:\n%s", m.Text, m.LineNumber, out.Count, len(res.Findings), out.Text)
				}
			}
			// The handle itself, independent of how the member Text is rendered.
			if n := strings.Count(out.Text, "janedoe"); n != 0 {
				t.Errorf("%d occurrence(s) of the handle survive redaction\noutput:\n%s", n, out.Text)
			}

			// A cluster expands to one mapping per member, so Count exceeding len(findings) is correct
			// here. Asserting it pins the semantics the doc comment on Redacted.Count now states.
			if out.Count < len(cluster.ClusterMembers) {
				t.Errorf("Count=%d for a cluster with %d members: at least one member was not replaced",
					out.Count, len(cluster.ClusterMembers))
			}
			t.Logf("%s: Count=%d len(findings)=%d members=%d — all masked",
				tc.name, out.Count, len(res.Findings), len(cluster.ClusterMembers))
		})
	}
}
