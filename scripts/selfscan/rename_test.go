// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package selfscan_test runs scripts/self-scan.sh --regenerate and the ledger step of
// .github/workflows/changelog-promote.yml in a scratch git repository, the way a release does (#954):
// the promotion deletes every changelog.d/ fragment and copies its lines into CHANGELOG.md, and the
// ledger rule on a fragment must follow its value to CHANGELOG.md with its reason.
package selfscan_test

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	root       = "../.."
	ledgerPath = ".ferret-scan-suppressions.yaml"
	reason     = `fixture: the test's own reason, carried byte for byte`
	stepName   = "Carry the ledger rules the promotion moved"
	changelog0 = "# Changelog\n\n## [Unreleased]\n\n## [v0.0.1] - 2026-01-01\n\n### 🐛 Bug Fixes\n\n- an older entry\n"
	fragName   = "changelog.d/0001-form-fields.md"
)

// ssn returns a well-formed SSN made at test time, so no value is committed; the self-scan reports it
// HIGH in a .md file, which is what a release note quoting an example value looks like to the gate.
func ssn(r *rand.Rand) string {
	return fmt.Sprintf("%03d-%02d-%04d", 100+r.Intn(500), 10+r.Intn(90), 1000+r.Intn(9000))
}

type scratch struct {
	t           *testing.T
	dir, ferret string
}

func (s scratch) run(name string, args ...string) (string, error) {
	s.t.Helper()
	cmd := exec.Command(name, args...) // #nosec G204 -- literal arguments from this test
	cmd.Dir = s.dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + s.t.TempDir(),
		"TMPDIR=" + s.t.TempDir(),
		"RUNNER_TEMP=" + s.t.TempDir(),
		"FERRET_BIN=" + s.ferret,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=ferret-scan test", "GIT_AUTHOR_EMAIL=ferret-scan-test",
		"GIT_COMMITTER_NAME=ferret-scan test", "GIT_COMMITTER_EMAIL=ferret-scan-test",
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s scratch) must(name string, args ...string) string {
	s.t.Helper()
	out, err := s.run(name, args...)
	if err != nil {
		s.t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return out
}

func (s scratch) write(rel, content string) {
	s.t.Helper()
	p := filepath.Join(s.dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s scratch) read(rel string) string {
	s.t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dir, rel)) // #nosec G304 -- a path in the scratch repository
	if err != nil {
		s.t.Fatal(err)
	}
	return string(b)
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- a fixed path in this repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// emptyLedger keeps the real ledger's lines up to `rules:`, comments dropped, and no rule.
func emptyLedger(t *testing.T) string {
	t.Helper()
	var kept []string
	for _, line := range strings.SplitAfter(repoFile(t, ledgerPath), "\n") {
		if s := strings.TrimSpace(line); s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		kept = append(kept, line)
		if strings.TrimSpace(line) == "rules:" {
			return strings.Join(kept, "")
		}
	}
	t.Fatal("the ledger has no `rules:` line")
	return ""
}

// stepScript is the run: text of the workflow's ledger step.
func stepScript(t *testing.T) string {
	t.Helper()
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(repoFile(t, ".github/workflows/changelog-promote.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	for _, st := range wf.Jobs["promote"].Steps {
		if st.Name == stepName {
			return st.Run
		}
	}
	t.Fatalf("changelog-promote.yml has no step %q", stepName)
	return ""
}

// released lays out the tree a release starts from: a fragment quoting a value, and a ledger whose
// one rule covers it with a reviewed reason, committed.
func released(t *testing.T, ferret, value string) scratch {
	t.Helper()
	s := scratch{t: t, dir: t.TempDir(), ferret: ferret}
	s.write(".ferret-scan/selfscan.yaml", repoFile(t, ".ferret-scan/selfscan.yaml"))
	s.write(ledgerPath, emptyLedger(t))
	s.write("scripts/self-scan.sh", repoFile(t, "scripts/self-scan.sh"))
	if err := os.Chmod(filepath.Join(s.dir, "scripts/self-scan.sh"), 0o700); err != nil {
		t.Fatal(err)
	}
	s.write("CHANGELOG.md", changelog0)
	s.write(fragName, "### 🐛 Bug Fixes\n\n- **form**: the field SSN: "+value+" on the form is reported\n")
	s.must("git", "-c", "init.defaultBranch=main", "init", "-q")
	s.must("git", "add", "-A")
	s.must("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "base")

	cand := filepath.Join(t.TempDir(), "cand.yaml")
	s.must("bash", "scripts/self-scan.sh", "--regenerate", cand)
	b, err := os.ReadFile(cand) // #nosec G304 -- the test's own temporary file
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "- id: SUP-"); n != 1 {
		t.Fatalf("the fragment gave %d rules, want 1:\n%s", n, b)
	}
	reviewed := regexp.MustCompile(`(?m)^(\s+)reason: .*$`).ReplaceAllString(string(b), `${1}reason: "`+reason+`"`)
	reviewed = regexp.MustCompile(`(?m)^(\s+)enabled: false$`).ReplaceAllString(reviewed, "${1}enabled: true")
	s.write(ledgerPath, reviewed)
	s.must("git", "add", "-A")
	s.must("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ledger")
	if out := s.must("bash", "scripts/self-scan.sh", "--scope", "tree", "--mode", "block"); !strings.Contains(out, "HIGH 0 (not suppressed)") {
		t.Fatalf("the released tree is not green:\n%s", out)
	}
	return s
}

// promote does what scripts/promote-changelog.sh does to the tree: the fragment's lines, byte for byte,
// in a new section below [Unreleased], plus extra lines, and the fragment `git rm`ed, uncommitted.
func (s scratch) promote(extra string) {
	s.t.Helper()
	frag := s.read(fragName)
	section := "## [v0.0.2] - 2026-02-01\n\n" + frag + extra + "\n"
	s.write("CHANGELOG.md", strings.Replace(changelog0, "## [v0.0.1]", section+"## [v0.0.1]", 1))
	s.must("git", "rm", "-q", fragName)
}

// step runs the workflow step's script as the runner does, from a file outside the checkout.
func (s scratch) step(script string) (string, error) {
	s.t.Helper()
	p := filepath.Join(s.t.TempDir(), "step.sh")
	if err := os.WriteFile(p, []byte(script), 0o600); err != nil {
		s.t.Fatal(err)
	}
	return s.run("bash", "--noprofile", "--norc", "-eo", "pipefail", p)
}

func field(block, key string) string {
	m := regexp.MustCompile(`(?m)^\s+` + key + `:\s*(.*)$`).FindStringSubmatch(block)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestPromotionCarriesTheFragmentRuleToChangelog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scripts/self-scan.sh and the workflow step are bash; the release runs on ubuntu")
	}
	for _, tool := range []string{"bash", "git", "jq", "tar", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is not on PATH (%v); skipping would leave the release's ledger step untested", tool, err)
		}
	}
	ferret := filepath.Join(t.TempDir(), "ferret-scan")
	if out, err := exec.Command("go", "build", "-o", ferret, filepath.Join(root, "cmd")).CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	script := stepScript(t)
	r := rand.New(rand.NewSource(rand.Int63())) // #nosec G404 -- test values, not secrets

	t.Run("the fragment rule follows its value", func(t *testing.T) {
		s := released(t, ferret, ssn(r))
		before := s.read(ledgerPath)
		s.promote("")
		out, err := s.step(script)
		if err != nil {
			t.Fatalf("the ledger step failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "1 renamed") || !strings.Contains(out, "0 new and DISABLED") || !strings.Contains(out, "HIGH 0 (not suppressed)") {
			t.Errorf("the step did not pair the rule and leave the tree green:\n%s", out)
		}
		after := s.read(ledgerPath)
		if strings.Count(after, "- id: SUP-") != 1 {
			t.Fatalf("the ledger holds %d rules, want the one rule moved:\n%s", strings.Count(after, "- id: SUP-"), after)
		}
		for _, k := range []string{"id", "reason", "enabled", "created_at", "confidence", "finding_type"} {
			if field(before, k) != field(after, k) {
				t.Errorf("%s changed: %q -> %q", k, field(before, k), field(after, k))
			}
		}
		if field(after, "reason") != `"`+reason+`"` {
			t.Errorf("reason %s, want %q byte for byte", field(after, "reason"), reason)
		}
		if field(after, "filename") != "CHANGELOG.md" || field(after, "line_number") == field(before, "line_number") {
			t.Errorf("the rule did not move: filename %s line %s (was %s line %s)",
				field(after, "filename"), field(after, "line_number"), field(before, "filename"), field(before, "line_number"))
		}
	})

	t.Run("a new value in the promoted text fails the step", func(t *testing.T) {
		s := released(t, ferret, ssn(r))
		before := s.read(ledgerPath)
		s.promote("- **form**: a second field SSN: " + ssn(r) + " on the form is reported\n")
		out, err := s.step(script)
		if err == nil {
			t.Fatalf("the step passed with a HIGH finding no rule covered before:\n%s", out)
		}
		if !strings.Contains(out, "::error title=self-scan ledger::the promotion has 1 HIGH finding(s)") {
			t.Errorf("the step did not say why it failed:\n%s", out)
		}
		if s.read(ledgerPath) != before {
			t.Error("the step wrote the ledger although it failed")
		}
	})
}
