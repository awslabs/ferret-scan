// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"fmt"
	"strings"
	"testing"
)

// confidences scans one line and returns each match's confidence, formatted.
func confidences(t *testing.T, line string) string {
	t.Helper()
	ms, err := NewValidator().ValidateContent(line+"\n", "notice.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, fmt.Sprintf("%.2f", m.Confidence))
	}
	return strings.Join(parts, ",")
}

// TestNonNoticeShapesAreNotReported pins #934: regex alternatives, quoted
// keyword lists, prose about trademarks, a "(r)" call argument, a lone ™ and
// an ISO BMFF atom name. Each line read INTELLECTUAL_PROPERTY at 80-98 before
// the fix (the confidence on main is in the comment) and reads nothing now.
func TestNonNoticeShapesAreNotReported(t *testing.T) {
	decoys := []string{
		// 93.50: the validator's own trade_secret regex.
		"patternTradeSecret: `(?i)\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b`,",
		// 93.50: config.yaml's trade_secret override, YAML-escaped.
		`      trade_secret: "\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b"`,
		// 93.50: config.yaml's profile override, every keyword glued to \\s+.
		`          trade_secret: "\\b(Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted\\s+Access|Classified\\s+Information|Proprietary\\s+to\\s+Company|Company\\s+Proprietary|Confidential\\s+and\\s+Proprietary)\\b"`,
		// 93.50: a Go keyword table.
		"\texplicitMarkers := []string{\"Company Confidential\", \"Trade Secret\", \"Internal Use Only\", \"Confidential\", \"Privileged\"}",
		// 97.00: a comment quoting example markers.
		`// confidentiality statements (e.g. "Trade Secret", "Internal Use Only") and earn`,
		// 98.00: a description string.
		"\t\tdescription = \"Copyright notice with trademark indicators\"",
		// 98.00: a comment about the patterns.
		"// Pattern 3: Copyright + Trademark (copyright notice with trademark)",
		// 98.00: a comment listing example notices as a quoted list.
		`// ("© 2024", "© 2024 — Acme", "© 2024 (Acme)", "© Acme Corporation",`,
		// 90.00: the QuickTime location atom.
		"// a fixture holding each: zeroing only ©xyz left loci decoding to 37.7749,-122.4194",
		// 90.00: a lone ™ in prose.
		"// file. A short line with a ™ (3 bytes) or an em-dash, counted in runes",
		// 80.00: a call argument named r.
		"self._by_base = {os.path.basename(r): r for r in self.files}",
		"rows = [r for r in pending if pub_key(r) not in pub]",
		// 98.00 consolidated; "when trademark" alone read 94 after the
		// copyright half was dropped.
		`t.Error("copyright should still be detected when trademark is disabled")`,
	}
	for _, line := range decoys {
		if got := confidences(t, line); got != "" {
			t.Errorf("%q: got findings at %s, want none", line, got)
		}
	}
	// A lone lowercase "confidential" stays a weak trade_secret marker (59,
	// below MEDIUM): the identifier and "for trademark" no longer lift it to 98.
	if got := confidences(t, "\tDefaultTrademarkNoticeBoost = 5.5 // Boost for trademark + confidential combinations"); got != "59.00" {
		t.Errorf("boost comment: got %q, want 59.00 (98.00 on main)", got)
	}
}

// TestNoticeControlsKeepConfidence: real notices next to each decoy shape
// keep the exact confidence they had before #934 (measured on main 2fb4719).
func TestNoticeControlsKeepConfidence(t *testing.T) {
	controls := []struct{ line, want string }{
		{"Copyright 2024 Acme Corporation. All rights reserved.", "86.00"},
		{"© Acme Corporation", "70.00"},
		{"Footer: © 2024", "90.00"},
		{"©2024 Initech", "90.00"},
		{"(c) 2024 Acme Inc.", "80.00"},
		{"Copyright Acme Inc.", "63.00"},
		{"Acme™ is a registered trademark of Acme Corp.", "98.00"},
		{"Windows(R) runs on Intel (R) processors.", "80.00,80.00"},
		{"Java(TM) is a trademark of Oracle.", "98.00"},
		{"Widgetron is a trademark of Initech.", "87.00"},
		{"© 2026, Amazon Web Services, Inc. or its affiliates. All rights reserved. Amazon Confidential and Trademark.", "98.00"},
		{"CONFIDENTIAL - DO NOT DISTRIBUTE", "48.00"},
		{`This document is "Confidential".`, "73.00"},
		{`"Acme","Confidential","2024"`, "73.00"},
		{"Proprietary and Confidential (Restricted)", "92.12"},
		{"Company Confidential - Trade Secret - Internal Use Only", "92.00"},
		{"Covered by US 9,123,456 and EP 1234567.", "80.00,50.00"},
	}
	for _, c := range controls {
		if got := confidences(t, c.line); got != c.want {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}

// TestNoticeAfterProseCopyrightIsKept: the copyright regex's entity class
// runs on through commas and parentheses, so a prose "copyright ..." match
// can swallow a real notice later on the line. Dropping the prose match must
// not drop the notice: it is reported from its own marker, at the confidence
// main gave the combined match.
func TestNoticeAfterProseCopyrightIsKept(t *testing.T) {
	cases := []struct{ line, text, conf string }{
		{"copyright notices (e.g., Copyright 2023 Company Name)", "Copyright 2023 Company Name)", "87.00"},
		{"the copyright holder, Copyright 2024 Acme Corp", "Copyright 2024 Acme Corp", "87.00"},
		{"copyright owner (c) 2021 Globex Corporation", "(c) 2021 Globex Corporation", "87.00"},
	}
	for _, c := range cases {
		ms, err := NewValidator().ValidateContent(c.line+"\n", "notice.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", c.line, err)
		}
		if len(ms) != 1 || ms[0].Text != c.text || fmt.Sprintf("%.2f", ms[0].Confidence) != c.conf {
			var got []string
			for _, m := range ms {
				got = append(got, fmt.Sprintf("%q@%.2f", m.Text, m.Confidence))
			}
			t.Errorf("%q: got %v, want %q@%s", c.line, got, c.text, c.conf)
		}
	}
	if got := confidences(t, "copyright copyright copyright notice"); got != "" {
		t.Errorf("repeated prose marker: got %s, want none", got)
	}
}
