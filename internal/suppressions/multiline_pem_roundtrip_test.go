// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
)

// pemArmour builds a PEM-shaped block with a random body, at test time: the shape is the reserved
// one, the body is no key anybody holds.
func pemArmour(t *testing.T, label, sep string) string {
	t.Helper()
	raw := make([]byte, 48*8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	var lines []string
	for len(b64) > 64 {
		lines = append(lines, b64[:64])
		b64 = b64[64:]
	}
	lines = append(lines, b64)
	dashes := strings.Repeat("-", 5)
	return dashes + "BEGIN " + label + dashes + sep + strings.Join(lines, sep) + sep + dashes + "END " + label + dashes
}

// roundTrip generates enabled rules for matches into a fresh file, loads that file the way the next
// run does, and returns the matches no rule suppresses.
func roundTrip(t *testing.T, matches []detector.Match) (rules int, left []detector.Match) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	gen := NewSuppressionManager(path)
	if err := gen.GenerateSuppressionRules(matches, "round trip", true); err != nil {
		t.Fatalf("GenerateSuppressionRules: %v", err)
	}
	next := NewSuppressionManager(path)
	for _, m := range matches {
		if ok, _ := next.IsSuppressed(m); !ok {
			left = append(left, m)
		}
	}
	return len(next.ListSuppressions()), left
}

// #981: two findings of one run where one's empty-context compatibility candidate is the other's
// current hash. That is what main's secrets validator emitted for a one-line PEM before #979 (the
// multi-line pass's finding, recorded with no context, beside a keyword copy that carries its line),
// and the rule written for the first was migrated onto the second, so the first was never suppressed.
// Both orders, and a second generation over the file the first wrote, which used to migrate again.
func TestGeneratedRulesSuppressAContextlessFindingBesideItsContextCopy(t *testing.T) {
	pem := pemArmour(t, "RSA PRIVATE KEY", " ")
	bare := detector.Match{
		Type: "SSH_PRIVATE_KEY", Text: pem, Filename: "k.txt", LineNumber: 1,
		Confidence: 95, Validator: "secrets",
	}
	withLine := bare
	withLine.Context = detector.ContextInfo{FullLine: pem}

	for name, matches := range map[string][]detector.Match{
		"contextless first":  {bare, withLine},
		"context copy first": {withLine, bare},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			for run := 1; run <= 2; run++ {
				if err := NewSuppressionManager(path).GenerateSuppressionRules(matches, "round trip", true); err != nil {
					t.Fatalf("run %d: GenerateSuppressionRules: %v", run, err)
				}
				next := NewSuppressionManager(path)
				for i, m := range matches {
					if ok, _ := next.IsSuppressed(m); !ok {
						t.Errorf("after generation %d, finding %d (context %d bytes) has no rule; rules: %d",
							run, i, len(m.Context.FullLine), len(next.ListSuppressions()))
					}
				}
			}
		})
	}
}

// The acceptance of #981: rules generated for the secrets validator's own PEM findings suppress
// every one of them on the next run, for every label and shape of #979's matrix.
func TestGeneratedRulesSuppressEveryPEMShape(t *testing.T) {
	v := secrets.NewValidator()
	labels := []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"}
	shapes := map[string]func(string) string{
		"multi-line": func(label string) string {
			return "deploy notes\n" + pemArmour(t, label, "\n") + "\nend of notes\n"
		},
		"space-joined": func(label string) string { return pemArmour(t, label, " ") + "\n" },
		"json neutral key": func(label string) string {
			return `{"note": "` + pemArmour(t, label, `\n`) + `\n"}` + "\n"
		},
		"json private_key": func(label string) string {
			return `{"type": "service_account", "private_key": "` + pemArmour(t, label, `\n`) + `\n"}` + "\n"
		},
	}
	total := 0
	for _, label := range labels {
		for shape, build := range shapes {
			name := fmt.Sprintf("%s/%s", label, shape)
			t.Run(name, func(t *testing.T) {
				matches, err := v.ValidateContent(build(label), "fixture.txt")
				if err != nil {
					t.Fatalf("ValidateContent: %v", err)
				}
				if len(matches) == 0 {
					t.Fatal("the validator reported nothing; the round trip is vacuous")
				}
				total += len(matches)
				rules, left := roundTrip(t, matches)
				for _, m := range left {
					t.Errorf("%s at line %d (%s) is not suppressed by the %d generated rule(s)",
						m.Type, m.LineNumber, m.Metadata["detection_method"], rules)
				}
			})
		}
	}
	if total < len(labels)*len(shapes) {
		t.Errorf("%d findings over %d files: some shape reported nothing", total, len(labels)*len(shapes))
	}
}
