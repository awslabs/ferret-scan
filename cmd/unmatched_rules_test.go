// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The rules that matched no finding (#885): one stderr note naming them and
// stats.suppression_rules_unmatched, on --file and --stdin, with the exit code unchanged.
//
// Measured on main @ 2fb4719 with this fixture (5 rules generated on customers.txt and enabled, then a
// line inserted at the top): active=5 suppressed=0 through --file and --stdin, exit 0, no line naming a
// rule and no stats key.

// customerLines is #885's fixture, one synthetic value per line after the first: an email on a reserved
// domain, a patterned Luhn VISA, an SSN, a date of birth and a patterned Luhn MASTERCARD. The card numbers
// are assembled from pieces so this source holds none of them whole.
var customerLines = []string{
	"Customer onboarding notes",
	"contact email: jordan.sample@example.com",
	"payment card on file: 4539 0123 " + "4567 8905",
	"social security number: 123-45-" + "6780",
	"date of birth: 03/17/1984",
	"alt card 5520 1234 " + "5678 9015 for refunds",
}

func customersText(prefix string, insertTop bool) string {
	var b strings.Builder
	if insertTop {
		b.WriteString(prefix + "Reviewed by the onboarding team\n")
	}
	for _, l := range customerLines {
		b.WriteString(prefix + l + "\n")
	}
	return b.String()
}

func unmatchedNoteLines(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "enabled suppression rule(s) for files scanned in this run matched no finding") {
			out = append(out, line)
		}
	}
	return out
}

// statsKey returns stats[key] from a JSON findings document, and whether it is present.
func statsKey(t *testing.T, label, doc, key string) (float64, bool) {
	t.Helper()
	var parsed struct {
		Stats map[string]any `json:"stats"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("%s: the findings document does not parse (%v):\n%s", label, err, doc)
	}
	v, ok := parsed.Stats[key]
	if !ok {
		return 0, false
	}
	n, isNum := v.(float64)
	if !isNum {
		t.Fatalf("%s: stats.%s is %T (%v), want a JSON number", label, key, v, v)
	}
	return n, true
}

// enabledRulesFor generates rules on content as name with the binary under test and enables them all.
func enabledRulesFor(t *testing.T, bin, work string, env []string, name, content string) string {
	t.Helper()
	gendir := filepath.Join(work, "gen")
	if err := os.MkdirAll(gendir, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(gendir, name), content)
	rules := filepath.Join(work, "rules-on.yaml")
	gen := filepath.Join(work, "rules.yaml")
	if r := runCLI(t, bin, gendir, env, "", "--file", name, "--config", os.DevNull, "--generate-suppressions",
		"--suppression-file", gen); r.rc != 0 {
		t.Fatalf("generating rules: rc %d\n%s", r.rc, r.stderr)
	}
	on := strings.ReplaceAll(readFileForTest(t, gen), "enabled: false", "enabled: true")
	if n := strings.Count(on, "enabled: true"); n != 5 {
		t.Fatalf("want 5 generated rules, got %d:\n%s", n, on)
	}
	writeFixture(t, rules, on)
	return rules
}

// TestARuleWhoseFindingMovedIsNamed is the acceptance case: after a line is inserted above every finding,
// the 5 rules match nothing, and both input paths name them and count them, at the exit code the same
// scan has without the rules.
func TestARuleWhoseFindingMovedIsNamed(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	rules := enabledRulesFor(t, bin, work, env, "customers.txt", customersText("", false))
	moved := customersText("", true)
	writeFixture(t, filepath.Join(work, "customers.txt"), moved)
	empty := filepath.Join(work, "no-rules.yaml")
	writeFixture(t, empty, "version: \"1.0\"\nrules: []\n")

	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"default", nil},
		{"PRE_COMMIT=1", []string{"PRE_COMMIT=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEnv := append(append([]string{}, env...), tc.env...)
			base := []string{"--format", "json", "--config", os.DevNull}
			file := runCLI(t, bin, work, runEnv, "", append([]string{"--file", "customers.txt", "--suppression-file", rules}, base...)...)
			stdin := runCLI(t, bin, work, runEnv, moved,
				append([]string{"--stdin", "--stdin-name", "customers.txt", "--suppression-file", rules}, base...)...)
			control := runCLI(t, bin, work, runEnv, "", append([]string{"--file", "customers.txt", "--suppression-file", empty}, base...)...)

			fn, sn := unmatchedNoteLines(file.stderr), unmatchedNoteLines(stdin.stderr)
			if len(fn) != 1 {
				t.Fatalf("--file printed %d unmatched-rule notes, want 1:\n%s", len(fn), file.stderr)
			}
			if len(sn) != 1 || sn[0] != fn[0] {
				t.Errorf("--stdin's note %q, want --file's %q", sn, fn[0])
			}
			want := 5.0
			if tc.env != nil {
				// The built-in precommit profile does not run DATE_OF_BIRTH, so its rule is not counted.
				want = 4
			}
			for label, doc := range map[string]string{"--file": file.stdout, "--stdin": stdin.stdout} {
				if n, ok := statsKey(t, label, doc, "suppression_rules_unmatched"); !ok || n != want {
					t.Errorf("%s: stats.suppression_rules_unmatched = %v (present %v), want %v", label, n, ok, want)
				}
			}
			if !strings.Contains(fn[0], "SUP-00000001") || !strings.Contains(fn[0], "--generate-suppressions") {
				t.Errorf("the note does not name the rules and the remedy: %q", fn[0])
			}
			if file.rc != control.rc || stdin.rc != control.rc {
				t.Errorf("rc --file %d, --stdin %d; the same scan without rules exits %d: a rule that matched "+
					"nothing hides nothing, so the exit code must not change", file.rc, stdin.rc, control.rc)
			}
		})
	}

	t.Run("gateway: stderr is the findings document", func(t *testing.T) {
		r := runCLI(t, bin, work, env, moved, "--stdin", "--stdin-name", "customers.txt", "--format", "json",
			"--config", os.DevNull, "--suppression-file", rules, "--enable-redaction")
		if len(unmatchedNoteLines(r.stderr)) != 0 {
			t.Errorf("the note was written into the findings document on stderr:\n%s", r.stderr)
		}
		if n, ok := statsKey(t, "gateway stderr", r.stderr, "suppression_rules_unmatched"); !ok || n != 5 {
			t.Errorf("the gateway's findings document: stats.suppression_rules_unmatched = %v (present %v), want 5", n, ok)
		}
	})
}

// TestRulesThatCouldNotMatchAreNotNamed holds the decoys: a rule that matched, a rule for a file the run
// did not read, and a rule of a type a narrowed run did not look for are not "unmatched".
func TestRulesThatCouldNotMatchAreNotNamed(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	rules := enabledRulesFor(t, bin, work, env, "customers.txt", customersText("", false))
	same := customersText("", false)
	writeFixture(t, filepath.Join(work, "customers.txt"), same)
	writeFixture(t, filepath.Join(work, "customers-2026.txt"), customersText("", true))

	base := []string{"--format", "json", "--config", os.DevNull, "--suppression-file", rules}
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
	}{
		{"every rule matched (--file)", "", []string{"--file", "customers.txt"}},
		{"every rule matched (--stdin)", same, []string{"--stdin", "--stdin-name", "customers.txt"}},
		{"renamed file: its basename was not scanned", "", []string{"--file", "customers-2026.txt"}},
		{"another --stdin-name", customersText("", true), []string{"--stdin", "--stdin-name", "other.txt"}},
		{"--checks SSN: the other types were not looked for", "", []string{"--file", "customers.txt", "--checks", "SSN"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runCLI(t, bin, work, env, tc.stdin, append(append([]string{}, tc.args...), base...)...)
			if notes := unmatchedNoteLines(r.stderr); len(notes) != 0 {
				t.Errorf("named rules that could not have matched: %q", notes)
			}
			if n, ok := statsKey(t, tc.name, r.stdout, "suppression_rules_unmatched"); ok {
				t.Errorf("stats.suppression_rules_unmatched = %v, want the key absent; a run with nothing "+
					"to report keeps every byte", n)
			}
		})
	}
}

// TestAGeneratingRunNamesNoRuleItRewrote: --generate-suppressions rewrites rules in the run it is asked
// in. A rule it re-anchors has its finding in the run; a rule it migrates to the current hash formula
// matched through the older one. Neither matched "nothing". testdata/suppressions-v2.5.5-indented.yaml
// holds rules v2.5.5 wrote for the indented fixture, so every one matches through the v2 formula.
func TestAGeneratingRunNamesNoRuleItRewrote(t *testing.T) {
	bin := buildScanner(t)
	_, _, env := profileWorkdir(t)
	oldRules := readFileForTest(t, filepath.Join("testdata", "suppressions-v2.5.5-indented.yaml"))
	indented := customersText("    ", false)

	for _, tc := range []struct {
		name    string
		content string
		gen     string // what the generation line must report, so the case is not vacuous
	}{
		{"migrated: v2.5.5 rules on the same file", indented, "migrated 5"},
		{"re-anchored: a line inserted above every finding", customersText("    ", true), "re-anchored 5"},
	} {
		for _, path := range []string{"--file", "--stdin"} {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				dir := t.TempDir()
				rules := filepath.Join(dir, "rules.yaml")
				writeFixture(t, rules, oldRules)
				writeFixture(t, filepath.Join(dir, "customers.txt"), tc.content)
				args := []string{"--format", "json", "--config", os.DevNull, "--suppression-file", rules, "--generate-suppressions"}
				stdin := ""
				if path == "--file" {
					args = append(args, "--file", "customers.txt")
				} else {
					args, stdin = append(args, "--stdin", "--stdin-name", "customers.txt"), tc.content
				}
				r := runCLI(t, bin, dir, env, stdin, args...)
				if !strings.Contains(r.stderr, tc.gen) {
					t.Fatalf("generation did not report %q, so this case is vacuous:\n%s", tc.gen, r.stderr)
				}
				if notes := unmatchedNoteLines(r.stderr); len(notes) != 0 {
					t.Errorf("named rules generation rewrote: %q\n%s", notes, r.stderr)
				}
				if n, ok := statsKey(t, path, r.stdout, "suppression_rules_unmatched"); ok {
					t.Errorf("stats.suppression_rules_unmatched = %v, want the key absent", n)
				}
			})
		}
	}

	t.Run("control: the v2.5.5 rules still suppress the indented file", func(t *testing.T) {
		dir := t.TempDir()
		rules := filepath.Join(dir, "rules.yaml")
		writeFixture(t, rules, oldRules)
		writeFixture(t, filepath.Join(dir, "customers.txt"), indented)
		r := runCLI(t, bin, dir, env, "", "--file", "customers.txt", "--format", "json", "--config", os.DevNull,
			"--suppression-file", rules)
		if n, _ := statsKey(t, "control", r.stdout, "suppressed"); n != 5 {
			t.Fatalf("stats.suppressed = %v, want 5: the testdata rules no longer match the fixture", n)
		}
	})
}

func TestFileRunScope(t *testing.T) {
	all := map[string]detector.Validator{}
	for _, name := range coreCheckNamesForTest() {
		all[name] = nil
	}
	scanned := []string{"a/notes.txt", "b/notes.txt", "c/report.txt", "d/clean.txt"}
	notExamined := []unscannedEntry{{Path: "b/notes.txt", Cause: causeCutShort}, {Path: "x/report.txt", Cause: causeUnreadable}}

	got := fileRunScope(scanned, false, notExamined, all, nil)
	if strings.Join(got.Files, ",") != "d/clean.txt" {
		t.Errorf("Files = %q, want only d/clean.txt: a basename leaves the scope when any file of that name "+
			"was not fully examined", got.Files)
	}
	if !got.AllChecks {
		t.Error("AllChecks = false with every check in the set and nothing disabled")
	}
	if got := fileRunScope(scanned, true, nil, all, nil); len(got.Files) != 0 {
		t.Errorf("a failed worker pool examined nothing, got Files %q", got.Files)
	}
	if got := fileRunScope(scanned, false, nil, all, map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}); got.AllChecks {
		t.Error("AllChecks = true with a sub-type disabled")
	}
	delete(all, "SSN")
	if got := fileRunScope(scanned, false, nil, all, nil); got.AllChecks {
		t.Error("AllChecks = true with a check missing from the set")
	}
}

func TestStdinRunScope(t *testing.T) {
	run, notApplicable := stdinChecksRun([]string{"all"})
	got := stdinRunScope("<stdin>", false, run, notApplicable, nil)
	if strings.Join(got.Files, ",") != "<stdin>" || !got.AllChecks {
		t.Errorf("full stdin scan: %+v, want Files [<stdin>] and AllChecks (METADATA cannot run here and is "+
			"not narrowing)", got)
	}
	if got := stdinRunScope("<stdin>", true, run, notApplicable, nil); len(got.Files) != 0 {
		t.Errorf("a cut-short scan did not look for every finding, got Files %q", got.Files)
	}
	ssnRun, ssnNA := stdinChecksRun([]string{"SSN"})
	if got := stdinRunScope("<stdin>", false, ssnRun, ssnNA, nil); got.AllChecks {
		t.Error("AllChecks = true under --checks SSN")
	}
}

// coreCheckNamesForTest is every registered check name, as the validator set of a full run has them.
func coreCheckNamesForTest() []string {
	run, notApplicable := stdinChecksRun([]string{"all"})
	return append(run, notApplicable...)
}
