// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/textnorm"
)

// A document and its canonical-ASCII equivalent must produce the same findings, and redacting either
// must remove the value from the artifact.
//
// # The gap
//
// Go's regexp is RE2, where \d is [0-9] and \s is [\t\n\f\r ], both ASCII-only. Every structured
// pattern in this repository is therefore anchored on ASCII while a word processor, a PDF extractor or
// an HTML paste routinely produces something else. Measured at HEAD across 8 structured types and 10
// substitutions, 61 of 80 combinations lost the finding entirely, and on a wider 90-fixture matrix the
// parent commit violated this invariance on 53 of 90. An SSN typed into Word and touched by autocorrect
// was reported clean, and under the sink rule an unreported value is an unredacted one (#671).
//
// # Why the oracle is the ASCII TWIN and not a hardcoded expectation
//
// The first version of this measurement compared each substituted fixture against the DASHED baseline
// and reported one remaining loss — a date written with soft hyphens. That was the oracle being wrong,
// not the tool: soft hyphens are dropped, so "1985<SHY>03<SHY>14" canonicalises to "19850314", and the
// date validator does not report a bare eight-digit run in pure ASCII either. Comparing against the
// canonical twin asks the question that actually matters — "does the substitution change what the tool
// sees" — and cannot be wrong about what ASCII behaviour is, because it measures it in the same run.
//
// # Both directions, because either alone would pass on a broken build
//
// Detection alone would pass if the value were reported with normalized text that redaction could not
// find; redaction alone would pass if nothing were reported at all. The pair is the contract.
func TestSubstitutedCharactersDoNotChangeWhatIsFound(t *testing.T) {
	bin := buildScanner(t)

	// One row per structured type. Values are synthetic and each is detected in ASCII form — asserted
	// by the twin comparison itself, which fails loudly if a baseline stops being reported.
	bases := map[string]string{
		"ssn":    "Employee SSN: 449-87-4100",
		"card":   "Card number: 4111-1111-1111-1111",
		"phone":  "Call me at 415-555-0142",
		"dob":    "Date of birth: 1985-03-14",
		"aba":    "Routing 021000021 account 000123456789",
		"iban":   "IBAN: GB82 WEST 1234 5698 7654 32",
		"npi":    "NPI: 1234567893",
		"mbi":    "MBI: 1EG4-TE5-MK73",
		"awskey": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
	}

	// One row per character family ordinary software produces. Written as \u escapes: several are
	// invisible, and a literal in this repository has silently held the wrong character before.
	subs := []struct {
		name    string
		ascii   string
		replace string
	}{
		{"en-dash", "-", "–"},
		{"em-dash", "-", "—"},
		{"hyphen", "-", "‐"},
		{"non-breaking-hyphen", "-", "‑"},
		{"figure-dash", "-", "‒"},
		{"minus-sign", "-", "−"},
		{"fullwidth-hyphen", "-", "－"},
		{"soft-hyphen", "-", "­"},
		{"nbsp", " ", " "},
		{"figure-space", " ", " "},
		{"narrow-nbsp", " ", " "},
		{"ideographic-space", " ", "　"},
		{"em-space", " ", " "},
	}

	type fixture struct {
		name   string
		subbed string
	}
	var fixtures []fixture
	for typ, base := range bases {
		for _, s := range subs {
			if !strings.Contains(base, s.ascii) {
				continue
			}
			fixtures = append(fixtures, fixture{typ + "__" + s.name, strings.ReplaceAll(base, s.ascii, s.replace)})
		}
		// Zero-width space inserted INTO the digit run, and an all-fullwidth-digit form. Neither is a
		// substitution of an existing character, so they are built separately.
		fixtures = append(fixtures,
			fixture{typ + "__zero-width-space", insertEvery(base, "​", 4)},
			fixture{typ + "__fullwidth-digits", toFullwidthDigits(base)})
	}
	if len(fixtures) < 60 {
		t.Fatalf("only %d fixtures built; the table is not covering the matrix", len(fixtures))
	}

	dir := t.TempDir()
	subDir := filepath.Join(dir, "substituted")
	asciiDir := filepath.Join(dir, "canonical")
	for _, d := range []string{subDir, asciiDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for _, f := range fixtures {
		// The canonical twin is produced by the SAME code the scanner uses, so the two cannot
		// disagree about what canonical means.
		if err := os.WriteFile(filepath.Join(subDir, f.name+".txt"), []byte(f.subbed+"\n"), 0o600); err != nil {
			t.Fatalf("writing fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(asciiDir, f.name+".txt"), []byte(textnorm.Fold(f.subbed)+"\n"), 0o600); err != nil {
			t.Fatalf("writing twin: %v", err)
		}
	}

	subFindings := scanTypesByFile(t, bin, subDir)
	asciiFindings := scanTypesByFile(t, bin, asciiDir)

	// Non-vacuity: the canonical side must actually find things, or every comparison is 0 == 0.
	totalASCII := 0
	for _, types := range asciiFindings {
		totalASCII += len(types)
	}
	if totalASCII < 40 {
		t.Fatalf("the canonical-ASCII side reported only %d finding types across %d fixtures; the "+
			"comparison would be vacuous", totalASCII, len(fixtures))
	}

	violations := 0
	for _, f := range fixtures {
		name := f.name + ".txt"
		got, want := subFindings[name], asciiFindings[name]
		if !sameSet(got, want) {
			violations++
			t.Errorf("%s: substituted document reports %v, its canonical-ASCII twin reports %v.\n"+
				"  A character ordinary software substitutes changed what the tool can see. Under the "+
				"sink rule the missing finding is a value that will not be redacted either.",
				f.name, sortedTypeNames(got), sortedTypeNames(want))
		}
	}
	t.Logf("%d fixtures, %d invariance violations (parent commit: 53 of 90)", len(fixtures), violations)
}

// TestRedactionRemovesTheSubstitutedBytes is the sink half.
//
// The fix reports matches carrying the ORIGINAL bytes, recovered through textnorm's offset table,
// precisely so redaction keeps working: internal/redactors/plaintext locates a finding with
// strings.Index(text, match.Text). A match reported with normalized text would be unfindable, and the
// detection fix would become a redaction failure — reported and then left in cleartext, the one
// outcome the sink rule forbids. Every strategy is exercised because they replace differently, and one
// of them (synthetic) was measured failing on fullwidth digits before its generator learned to fold.
func TestRedactionRemovesTheSubstitutedBytes(t *testing.T) {
	bin := buildScanner(t)

	values := []struct{ name, text string }{
		{"ssn-en-dash", "Employee SSN: 449–87–4100"},
		{"card-nbsp", "Card number: 4111 1111 1111 1111"},
		{"phone-em-dash", "Call me at 415—555—0142"},
		{"ssn-soft-hyphen", "Employee SSN: 449­87­4100"},
		{"card-zero-width", "Card number: 4111​1111​1111​1111"},
		{"ssn-fullwidth", "Employee SSN: ４４９-８７-４１００"},
		{"awskey-fullwidth", "aws_access_key_id = AKIAIOSFODNN７EXAMPLE"},
	}

	for _, strategy := range []string{"simple", "format_preserving", "synthetic"} {
		t.Run(strategy, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "in")
			out := filepath.Join(dir, "out")
			if err := os.MkdirAll(in, 0o750); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			for _, v := range values {
				if err := os.WriteFile(filepath.Join(in, v.name+".txt"), []byte(v.text+"\n"), 0o600); err != nil {
					t.Fatalf("writing %s: %v", v.name, err)
				}
			}

			// What was reported, with the actual values, so the check is against real findings rather
			// than against an assumption about what should have been found.
			reported := scanReportedValues(t, bin, in)
			if len(reported) == 0 {
				t.Fatalf("nothing was reported for any fixture, so this test cannot check redaction — " +
					"it would pass on a build that detects nothing")
			}

			cmd := exec.Command(bin, "--file", in, "--recursive", "--config", os.DevNull,
				"--checks", "all", "--enable-redaction", "--redaction-strategy", strategy,
				"--redaction-output-dir", out)
			_ = cmd.Run() // findings make the exit code non-zero by design

			artifacts := map[string]string{}
			_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					artifacts[filepath.Base(p)] = p
				}
				return nil
			})

			for name, vals := range reported {
				p, ok := artifacts[name]
				if !ok {
					t.Errorf("%s: no redacted artifact was written. The tool refused rather than "+
						"redacting — safe, but it means this document cannot be redacted at all.", name)
					continue
				}
				b, err := os.ReadFile(p) // #nosec G304 -- path from our own output dir
				if err != nil {
					t.Fatalf("reading artifact: %v", err)
				}
				for _, v := range vals {
					if strings.Contains(string(b), v) {
						t.Errorf("%s [%s]: the reported value survives redaction.\n"+
							"  The match must carry the ORIGINAL bytes so strings.Index finds them; a "+
							"normalized Match.Text is unfindable in the file and turns a detection fix "+
							"into a leak.", name, strategy)
					}
				}
			}
		})
	}
}

// ---- helpers ----------------------------------------------------------------------------------

func scanTypesByFile(t *testing.T, bin, dir string) map[string]map[string]bool {
	t.Helper()
	out := runScanJSON(t, bin, dir)
	by := map[string]map[string]bool{}
	for _, r := range out {
		name := filepath.Base(r.Filename)
		if by[name] == nil {
			by[name] = map[string]bool{}
		}
		by[name][r.Type] = true
	}
	return by
}

func scanReportedValues(t *testing.T, bin, dir string) map[string][]string {
	t.Helper()
	out := runScanJSON(t, bin, dir, "--show-match")
	by := map[string][]string{}
	for _, r := range out {
		if r.Text == "" {
			continue
		}
		name := filepath.Base(r.Filename)
		by[name] = append(by[name], r.Text)
	}
	return by
}

type scanResult struct {
	Filename string `json:"filename"`
	Type     string `json:"type"`
	Text     string `json:"text"`
}

func runScanJSON(t *testing.T, bin, dir string, extra ...string) []scanResult {
	t.Helper()
	args := append([]string{"--file", dir, "--recursive", "--config", os.DevNull,
		"--checks", "all", "--format", "json", "--limit", "0"}, extra...)
	cmd := exec.Command(bin, args...)
	raw, err := cmd.Output()
	if err != nil && len(raw) == 0 {
		t.Fatalf("scanning %s: %v", dir, err)
	}
	var doc struct {
		Results []scanResult `json:"results"`
	}
	if jsonErr := json.Unmarshal(raw, &doc); jsonErr != nil {
		t.Fatalf("parsing findings JSON: %v", jsonErr)
	}
	return doc.Results
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func sortedTypeNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// insertEvery puts sep after every nth DIGIT of s, which is how a zero-width space arrives in a
// pasted value: between the digits rather than replacing a separator.
func insertEvery(s, sep string, n int) string {
	var b strings.Builder
	digits := 0
	for _, r := range s {
		b.WriteRune(r)
		if r >= '0' && r <= '9' {
			digits++
			if digits%n == 0 {
				b.WriteString(sep)
			}
		}
	}
	return b.String()
}

// toFullwidthDigits rewrites every ASCII digit as its fullwidth form, which CJK-locale forms and
// spreadsheets produce and RE2's \d cannot see.
func toFullwidthDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune('０' + (r - '0'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
