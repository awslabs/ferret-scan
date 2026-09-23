// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// WHY THIS FILE EXISTS.
//
// AWS Labs' automated-security-helper (ASH) ships a first-party plugin that runs THIS binary as a
// subprocess and parses its SARIF:
//
//	awslabs/automated-security-helper
//	  automated_security_helper/plugin_modules/ash_ferret_plugins/ferret_scanner.py   (the consumer)
//	  automated_security_helper/plugin_modules/ash_ferret_plugins/DEVELOPMENT.md      (its prose contract)
//	  automated_security_helper/plugin_modules/ash_ferret_plugins/ferret-config.yaml  (its bundled config)
//
// Nothing in this repository referenced ASH before this file, so every CLI-surface change shipped
// with no signal that a downstream consumer parses it. That is not hypothetical. ASH's own source
// records what it cost them (get_installation_commands docstring, ferret_scanner.py):
//
//	"CI ran ``pip install ferret-scan``, which resolves to whatever is newest [...] It added an
//	 API_KEY_OR_SECRET detector that matches ``session: Optional[Session]`` in generated Pydantic
//	 schemas at "95% HIGH" confidence, and every open PR went red with no source change."
//
// and its spec/ delta log records four more rounds of chasing us: the version window, the check
// inventory (20 -> 19 checks, KEYWORD_MATCH dropped), empty results changing from null to [], and
// narrowing its accepted exit codes from {0,1,3} to {0,3}.
//
// WHAT THIS FILE IS AND IS NOT. It is a guard on OUR side of the boundary: it fails when ferret-scan
// changes something ASH parses. It is NOT a test of ASH. It cannot fetch ASH at test time -- CI has
// no network for this, and a test that silently skips when a fetch fails is worse than no test -- so
// the contract is VENDORED below as constants, each with the ASH source that establishes it. When ASH
// changes its own expectations, these constants are what a human updates.
//
// EVERY CONSTANT BELOW WAS TAKEN FROM ASH'S CODE, NOT ITS PROSE. The two disagree in places, and the
// code is what runs. DEVELOPMENT.md, for instance, names only three flags as "hardcoded" and leaves
// four spellings unstated; the code emits 23. It also says code 1 is our error code, while this repo
// documents code 2 as "the tool failed" -- harmless, since ASH treats everything outside {0,3} as
// failure, but it is why the code is the source of truth here.
//
// Provenance: read from awslabs/automated-security-helper main on 2026-09-17. The divergences this
// found, and the two that need action on our side, are recorded in #702.

// ashEmittedFlags is every ferret-scan flag ASH's plugin can pass, extracted from the string literals
// in ferret_scanner.py rather than from its documentation.
//
// A flag removed or renamed here is an immediate, total break for ASH: Go's flag package exits
// non-zero on an unknown flag, so ASH gets no SARIF at all, for every user, on every scan.
var ashEmittedFlags = []string{
	// Always sent. format_arg/format_arg_value/output_arg/scan_path_arg in the ToolArgs constructor.
	"--format", // always with value "sarif"
	"--output",
	"--file",
	"--no-color", // "prevent ANSI escape injection in reports"
	"--quiet",    // "ASH captures stderr and renders its own progress"
	"--limit",    // always "0"; ASH sends it to stop our 200 default silently truncating

	// Sent from plugin options.
	"--checks",
	"--confidence", // only when confidence_levels != "all"
	"--config",
	"--debug",
	"--disable-ip-types",
	"--enable-preprocessors",
	"--exclude", // ONE comma-separated value, not a repeated flag
	"--explain",
	"--fail-on-incomplete",
	"--max-live-bytes",
	"--profile",
	"--recursive",
	"--respect-gitignore",
	"--show-match", // opt-in; ASH logs a warning telling operators to disable it in production
	"--validator-budget",
	"--verbose",

	// The installed-version probe.
	"--version",
}

// ashBlockedOptions are ferret-scan capabilities ASH deliberately REFUSES to expose, each with a
// reason in its own BLOCKED_OPTIONS table.
//
// This list is load-bearing in a way that is easy to miss. ASH requires exit 0 on a scan that FOUND
// sensitive data, and the only path in this binary that turns findings into a non-zero exit is
// --pre-commit-mode -- which is why ASH blocks it. If findings ever became non-zero on the ordinary
// path, ASH would report a failed scan for every user whose repository contains anything at all.
//
// Entries here that are NOT ferret-scan flags are kept deliberately: memory_scrub, extract_text and
// preprocess_only are names ASH still refuses that this binary no longer has, and one of them
// (memory_scrub) is also a dead key in ASH's bundled config. Recording them is how the drift stays
// visible instead of being rediscovered.
var ashBlockedOptions = map[string]bool{
	"format": true, "output_format": true,
	"web": true, "port": true,
	"enable_redaction": true, "redaction_output_dir": true,
	"redaction_strategy": true, "redaction_audit_log": true,
	"memory_scrub":          true, // not a ferret-scan flag
	"generate_suppressions": true,
	"show_suppressed":       true,
	"suppressions_file":     true,
	"extract_text":          true, // not a ferret-scan flag
	"debug":                 true, // blocked as a bare option; emitted as --debug instead
	"verbose":               true, // same
	"preprocess_only":       true, // not a ferret-scan flag
	"pre_commit_mode":       true, // THE load-bearing one: it makes findings a non-zero exit
	"list_profiles":         true,
}

// ASH's version window, from the module constants in ferret_scanner.py.
//
// Mismatch only warns, it never blocks -- but get_installation_commands runs `pip install
// ferret-scan>=2.4.5,<2.5.0` UNCONDITIONALLY and its docstring says the unconditional install is the
// point, because "an already-installed out-of-range build is the case that needs correcting, and pip
// will downgrade it to satisfy the constraint".
//
// So this is not a cosmetic warning. Publishing 2.5.0 does not give ASH users a newer ferret-scan; it
// makes ASH actively PIN THEM BACK to 2.4.5, and every fix we ship after that never reaches them
// until ASH's plugin range is raised.
const (
	ashMinSupportedVersion = "2.4.5"
	ashMaxSupportedVersion = "2.5.0" // exclusive
	// ashRecommendedVersion is ASH's RECOMMENDED_VERSION, and today it is also the newest version
	// inside the window -- which is what pip resolves an out-of-range build DOWN to.
	ashRecommendedVersion  = "2.4.5"
	ashSuccessExitCodesDoc = "{0, 3}"
)

// ashSuccessExitCodes is ASH's success_exit_codes ClassVar. Anything outside it is a failed scan.
var ashSuccessExitCodes = map[int]bool{0: true, 3: true}

// ashReferencedChecks are --checks values ASH names in its options documentation and bundled config.
// ASH has already had to correct this inventory once, when a check was removed upstream.
var ashReferencedChecks = []string{
	"CREDIT_CARD", "SECRETS", "SSN", "INTELLECTUAL_PROPERTY",
}

func buildForASHContract(t *testing.T) string {
	t.Helper()
	name := "ferret-scan-ash-contract"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// ashFlagProbeValue gives each flag a value valid enough to get past flag PARSING. The scan itself
// does not have to succeed: what is being tested is whether the flag is REGISTERED.
//
// An empty string means the flag takes no value.
var ashFlagProbeValue = map[string]string{
	"--format":               "sarif",
	"--output":               "", // filled in per-run with a temp path
	"--file":                 "", // filled in per-run with the fixture
	"--no-color":             "",
	"--quiet":                "",
	"--limit":                "0",
	"--checks":               "SECRETS",
	"--confidence":           "all",
	"--config":               "", // filled in per-run with os.DevNull
	"--debug":                "",
	"--disable-ip-types":     "copyright",
	"--enable-preprocessors": "",
	"--exclude":              "*.pyc",
	"--explain":              "",
	"--fail-on-incomplete":   "",
	"--max-live-bytes":       "256MB",
	"--profile":              "precommit",
	"--recursive":            "",
	"--respect-gitignore":    "",
	"--show-match":           "",
	"--validator-budget":     "all=2m",
	"--verbose":              "",
	"--version":              "",
}

// TestASHEmittedFlagsAllStillExist is the cheapest and highest-value assertion in this file.
//
// Go's flag package treats an unknown flag as a usage error and exits WITHOUT scanning, so a single
// renamed flag means ASH produces no SARIF for anybody. There is no partial degradation.
//
// WHY THIS INVOKES THE BINARY INSTEAD OF READING --help. The first version of this test grepped the
// --help text, and it was VACUOUS: this binary prints a hand-written help page from internal/help,
// so renaming the actual flag.Bool("respect-gitignore") registration to "honour-gitignore" left the
// help text untouched and the test still passed -- while the binary had stopped accepting the flag
// ASH sends. Caught by mutating the registration and watching the guard report ok.
//
// So the probe is the only thing that speaks for the real flag set: pass the flag and look for Go's
// own "flag provided but not defined" on stderr. That message is emitted by the flag package itself,
// independently of any documentation this repository writes.
func TestASHEmittedFlagsAllStillExist(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("nothing sensitive\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if len(ashEmittedFlags) < 20 {
		t.Fatalf("the vendored ASH flag list has only %d entries; ASH's plugin emits 23, so this "+
			"list has been truncated and the guard would under-check", len(ashEmittedFlags))
	}

	// Every flag must have a probe value defined, or it would be silently skipped.
	for _, f := range ashEmittedFlags {
		if _, ok := ashFlagProbeValue[f]; !ok {
			t.Fatalf("no probe value defined for %s, so it would not actually be exercised", f)
		}
	}

	const notDefined = "flag provided but not defined"

	// NON-VACUITY: a flag that genuinely does not exist MUST produce that message. If it does not --
	// a different flag package, a custom parser, an early os.Exit -- then every check below is
	// looking for a string that never appears and all of them pass regardless.
	probe := exec.Command(bin, "--this-flag-does-not-exist", "--file", in)
	sentinel, _ := probe.CombinedOutput()
	if !strings.Contains(string(sentinel), notDefined) {
		t.Fatalf("a deliberately bogus flag did NOT produce %q, so this test cannot detect a missing "+
			"flag at all. output:\n%s", notDefined, sentinel)
	}

	var missing []string
	for _, f := range ashEmittedFlags {
		args := []string{f}
		if v := ashFlagProbeValue[f]; v != "" {
			args = append(args, v)
		}
		switch f {
		case "--output":
			args = append(args, filepath.Join(dir, "probe.sarif"))
		case "--file":
			args = append(args, in)
		case "--config":
			args = append(args, os.DevNull)
		}
		// --version exits before scanning; everything else gets a minimal valid scan appended so the
		// run reaches flag parsing and then does something harmless.
		if f != "--version" && f != "--file" {
			args = append(args, "--file", in, "--config", os.DevNull, "--quiet")
		}
		out, _ := exec.Command(bin, args...).CombinedOutput()
		if strings.Contains(string(out), notDefined) {
			missing = append(missing, f)
		}
	}

	if len(missing) > 0 {
		t.Errorf("%d flag(s) ASH's plugin passes are no longer REGISTERED: %v\n\n"+
			"Go's flag package exits non-zero on an unknown flag WITHOUT scanning, so ASH gets no "+
			"SARIF at all -- for every ASH user, on every scan, not just a degraded result. If the "+
			"rename is intended, it is a BREAKING change for ASH: raise it with the plugin owners "+
			"(automated_security_helper/plugin_modules/ash_ferret_plugins/ferret_scanner.py) and "+
			"update the vendored list here in the same change.", len(missing), missing)
	}
}

// TestASHRequiresExitZeroWhenSensitiveDataIsFound pins the exit-code contract.
//
// ASH's success_exit_codes is {0, 3}. The subtle requirement is the first one: a scan that FINDS
// sensitive data must still exit 0, because "found something" is the normal, expected outcome for a
// DLP scanner and ASH reports the findings itself. If findings ever became a non-zero exit on the
// ordinary path, every ASH user with anything in their repository would see a failed scanner.
func TestASHRequiresExitZeroWhenSensitiveDataIsFound(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.txt")
	if err := os.WriteFile(dirty, []byte(
		"aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sarifPath := filepath.Join(dir, "out.sarif")
	// The exact flag set ASH sends on every scan.
	cmd := exec.Command(bin,
		"--file", dirty,
		"--config", os.DevNull,
		"--format", "sarif",
		"--output", sarifPath,
		"--no-color", "--quiet",
		"--limit", "0",
	)
	out, err := cmd.CombinedOutput()
	rc := cmd.ProcessState.ExitCode()

	// NON-VACUITY: prove the scan actually found something. Exit 0 on a scan that found NOTHING
	// would satisfy this test while proving nothing about the findings case it exists for.
	report := readSARIF(t, sarifPath)
	n := len(*report.Runs[0].Results)
	if n == 0 {
		t.Fatalf("the fixture produced 0 findings, so 'exit 0 WITH findings' is untested here.\n"+
			"stderr/stdout:\n%s", out)
	}

	if !ashSuccessExitCodes[rc] {
		t.Errorf("a scan that found %d findings exited %d, which is outside ASH's "+
			"success_exit_codes %s, so ASH reports the scanner as FAILED rather than reporting the "+
			"findings. err=%v\noutput:\n%s", n, rc, ashSuccessExitCodesDoc, err, out)
	}
	if rc != 0 {
		t.Errorf("expected exactly 0 for a complete scan with findings, got %d — 3 is reserved for "+
			"incomplete coverage under --fail-on-incomplete and must not be produced here", rc)
	}
}

// sarifDoc is the narrow view of SARIF that ASH actually parses. Deliberately not the full schema:
// pinning fields ASH never reads would make this guard fail on harmless additions.
type sarifDoc struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
		// A POINTER to a slice, so this test can tell `[]` from `null`. With a plain slice both
		// decode to a nil slice and the distinction ASH's doc calls out would be invisible here.
		Results *[]struct {
			RuleID string `json:"ruleId"`
		} `json:"results"`
	} `json:"runs"`
}

func readSARIF(t *testing.T, path string) sarifDoc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ASH reads this file unconditionally (check=False on the subprocess), so a missing "+
			"SARIF is a total break: %v", err)
	}
	var d sarifDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("ASH runs SarifReport.model_validate on this file; invalid JSON means it falls back "+
			"to a raw-dict path and loses every finding: %v\nfirst 400 bytes: %.400s", err, b)
	}
	if len(d.Runs) == 0 {
		t.Fatalf("SARIF has no runs[]; ASH indexes runs[0] directly. first 400 bytes: %.400s", b)
	}
	if d.Runs[0].Results == nil {
		t.Fatalf("runs[0].results is absent or JSON null. ASH's plugin notes that v2.3.1+ emits an "+
			"empty ARRAY rather than null; regressing to null puts ASH back on a compatibility path "+
			"it only kept for older builds. first 400 bytes: %.400s", b)
	}
	return d
}

// TestASHParsedSARIFFieldsAreStable pins only what ASH reads: the version string, results being an
// array (never null) even when empty, and a non-empty ruleId on every result.
//
// ruleId matters beyond parsing: ASH's suppressions key on the (path, rule_id) pair, so renaming a
// ruleId silently voids every ASH user's suppression for that type. Silently, because a suppression
// that matches nothing looks exactly like a suppression that was not needed.
func TestASHParsedSARIFFieldsAreStable(t *testing.T) {
	bin := buildForASHContract(t)

	for _, tc := range []struct {
		name        string
		content     string
		wantResults string // "some" or "none"
	}{
		{"with findings", "aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n", "some"},
		// The empty case is the one that exercises `[]` vs null, and it is the case a fixture with
		// findings can never reach.
		{"clean file", "the quick brown fox jumps over the lazy dog\n", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			in := filepath.Join(dir, "in.txt")
			if err := os.WriteFile(in, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			sarifPath := filepath.Join(dir, "out.sarif")
			cmd := exec.Command(bin, "--file", in, "--config", os.DevNull,
				"--format", "sarif", "--output", sarifPath, "--no-color", "--quiet", "--limit", "0")
			out, _ := cmd.CombinedOutput()

			d := readSARIF(t, sarifPath)

			if d.Version != "2.1.0" {
				t.Errorf("sarif version is %q, want \"2.1.0\" — ASH validates against the 2.1.0 "+
					"model", d.Version)
			}

			results := *d.Runs[0].Results
			switch tc.wantResults {
			case "some":
				if len(results) == 0 {
					t.Fatalf("expected findings and got none, so the ruleId check below is "+
						"vacuous.\noutput:\n%s", out)
				}
				for i, r := range results {
					if strings.TrimSpace(r.RuleID) == "" {
						t.Errorf("results[%d] has an empty ruleId. ASH's suppressions key on "+
							"(path, rule_id), so a finding without one can never be suppressed by "+
							"an ASH user", i)
					}
				}
			case "none":
				if len(results) != 0 {
					t.Fatalf("the 'clean file' fixture produced %d findings, so this subtest is "+
						"NOT exercising the empty-results path it exists for. Pick different "+
						"content.", len(results))
				}
				// Reaching here with Results != nil is the assertion: readSARIF already failed on
				// null, so an empty array is what we have.
			}
		})
	}
}

// TestASHAlwaysGetsSARIFRegardlessOfConfigOrProfile.
//
// ASH hardcodes --format sarif and ASSERTS it wins over any config-file or profile `format:`, which
// is why it ships profiles declaring text/yaml/junit unedited. If config or profile ever won, ASH
// would try to parse YAML or JUnit as SARIF and lose every finding.
func TestASHAlwaysGetsSARIFRegardlessOfConfigOrProfile(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("aws key AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A config that actively contends for the format, so this test cannot pass by there being
	// nothing to override.
	cfgPath := filepath.Join(dir, "contending.yaml")
	if err := os.WriteFile(cfgPath, []byte("format: text\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sarifPath := filepath.Join(dir, "out.sarif")
	cmd := exec.Command(bin, "--file", in, "--config", cfgPath,
		"--format", "sarif", "--output", sarifPath, "--no-color", "--quiet", "--limit", "0")
	out, _ := cmd.CombinedOutput()

	d := readSARIF(t, sarifPath)
	if d.Version != "2.1.0" {
		t.Errorf("with `format: text` in the config and --format sarif on the command line, the "+
			"output is not SARIF 2.1.0 (version=%q). ASH would parse this as SARIF and get "+
			"nothing.\noutput:\n%s", d.Version, out)
	}
	if len(*d.Runs[0].Results) == 0 {
		t.Errorf("SARIF parsed but carries no findings, so the override may have produced an empty "+
			"document rather than a real SARIF report.\noutput:\n%s", out)
	}
}

// TestASHReferencedChecksAreStillAccepted.
//
// Every --checks value ASH can pass must still be accepted. A removed check name is a hard failure:
// Go's flag parsing accepts the string, but an unknown check makes the binary exit non-zero with a
// usage error, so ASH gets no SARIF. This already happened once upstream -- ASH's spec/ delta log
// records "20 -> 19 checks, drop KEYWORD_MATCH" as something it had to chase after the fact.
func TestASHReferencedChecksAreStillAccepted(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("nothing sensitive here at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if len(ashReferencedChecks) == 0 {
		t.Fatal("the vendored check list is empty, so this test asserts nothing")
	}

	for _, check := range ashReferencedChecks {
		t.Run(check, func(t *testing.T) {
			sarifPath := filepath.Join(dir, check+".sarif")
			cmd := exec.Command(bin, "--file", in, "--config", os.DevNull,
				"--checks", check, "--format", "sarif", "--output", sarifPath,
				"--no-color", "--quiet", "--limit", "0")
			out, _ := cmd.CombinedOutput()
			rc := cmd.ProcessState.ExitCode()
			if !ashSuccessExitCodes[rc] {
				t.Errorf("--checks %s exited %d, outside ASH's success set %s. ASH passes this "+
					"check name, so if it has been renamed or removed, coordinate with the plugin "+
					"owners before shipping.\noutput:\n%s",
					check, rc, ashSuccessExitCodesDoc, out)
			}
		})
	}
}

// TestOurVersionIsInsideASHsSupportedWindow is the one assertion here that is about RELEASING rather
// than about code.
//
// ASH pins >=2.4.5,<2.5.0 and installs it UNCONDITIONALLY, so pip will DOWNGRADE an out-of-range
// build. Publishing 2.5.0 therefore does not deliver a newer ferret-scan to ASH users -- it pins them
// back to 2.4.5 and stops them receiving anything we ship afterwards, including leak fixes.
//
// WHY THIS READS THE GIT TAG AND NOT THE BINARY. The first version of this test ran the built binary's
// --version and skipped when it saw the dev default. That made it USELESS: buildForASHContract runs a
// plain `go build` with no -ldflags, so internal/version.Version is ALWAYS "0.0.0-development" in a
// test run, and the test therefore skipped 100% of the time while its own comment claimed it "fails
// only on a real release outside the window". A guard that can never fire is worse than no guard,
// because the comment stands in for coverage that does not exist.
//
// The tag is the real source of truth: releases are cut by pushing a v* tag and goreleaser derives the
// version from it (.goreleaser.yml), so the tag IS the version ASH's pip constraint will be compared
// against. Two cases, and both matter:
//
//   - HEAD is exactly tagged -> that tag is the version being released. Hard failure if out of range.
//   - otherwise -> check the most recent tag reachable from HEAD. If a release outside ASH's window
//     has ALREADY happened, every subsequent test run says so until someone raises ASH's range.
//
// KNOWN LIMITATION, STATED RATHER THAN PAPERED OVER. Neither of those fires in CI as configured today:
// .github/workflows/go-test.yml checks out with the default fetch-depth and NO tags (so git describe
// finds nothing and this test skips), and it does not run on tag pushes at all; .github/workflows/
// release.yml does check out with fetch-depth: 0 but runs goreleaser with no test job and no `needs:`
// on tests, so nothing test-shaped can gate a release. Making this effective needs a workflow change,
// not just a test change -- tracked in the ASH follow-up issue. Until then this fires for anyone
// running the suite locally on a tagged commit, which is the person cutting the release.
func TestOurVersionIsInsideASHsSupportedWindow(t *testing.T) {
	// The binary's own --version is still probed, because ASH parses that string and an unparseable
	// one makes every ASH run warn. That part is testable without a release build.
	bin := buildForASHContract(t)
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed; ASH probes it to decide compatibility: %v\n%s", err, out)
	}
	line := strings.TrimSpace(string(out))
	if extractSemverish(line) == "" {
		t.Errorf("could not find a dotted version in %q. ASH runs `ferret-scan --version` and parses "+
			"it with an unanchored (\\d+\\.\\d+\\.\\d+) search; a string with no dotted triple makes "+
			"every ASH run report a version warning.", line)
	}
	t.Logf("--version reports: %s", line)

	// The window check runs against the TAG, which is what a release actually publishes.
	exact, exactErr := exec.Command("git", "describe", "--tags", "--exact-match", "HEAD").Output()
	latest, latestErr := exec.Command("git", "describe", "--tags", "--abbrev=0").Output()

	if exactErr != nil && latestErr != nil {
		// Explicit and loud. A silent skip here is what made the first version of this test useless.
		t.Skipf("no git tags are reachable, so the release-version window cannot be checked in this " +
			"checkout. This is the NORMAL state in go-test.yml, which uses the default checkout depth " +
			"and fetches no tags -- meaning this check does NOT run in CI. It is effective only in a " +
			"full clone, e.g. locally when cutting a release. See the ASH follow-up issue.")
	}

	check := func(tag string, exactMatch bool) {
		ver := strings.TrimPrefix(strings.TrimSpace(tag), "v")
		if ver == "" {
			return
		}
		inRange := cmpSemver(ver, ashMinSupportedVersion) >= 0 &&
			cmpSemver(ver, ashMaxSupportedVersion) < 0
		if inRange {
			t.Logf("tag %s is inside ASH's window [>=%s,<%s)", ver, ashMinSupportedVersion, ashMaxSupportedVersion)
			return
		}
		which := "the most recent tag reachable from HEAD"
		if exactMatch {
			which = "the tag ON THIS COMMIT, i.e. the version being released"
		}
		t.Errorf("%s is %s, which is OUTSIDE the range ASH's plugin installs and supports "+
			"(>=%s,<%s).\n\n"+
			"This is not only a warning on ASH's side. get_installation_commands runs\n"+
			"    pip install \"ferret-scan>=%s,<%s\"\n"+
			"UNCONDITIONALLY, and its docstring says that is deliberate so pip will DOWNGRADE an "+
			"out-of-range build. So shipping this version does not give ASH users a newer "+
			"ferret-scan -- pip resolves to the newest version INSIDE that range (%s today) and they "+
			"stop receiving anything we ship after it, including leak fixes.\n\n"+
			"Before releasing: raise MIN_SUPPORTED_VERSION, MAX_SUPPORTED_VERSION and "+
			"DEFAULT_VERSION_CONSTRAINT in ash_ferret_plugins/ferret_scanner.py, then update the "+
			"constants in this file in the same change.",
			which, ver, ashMinSupportedVersion, ashMaxSupportedVersion,
			ashMinSupportedVersion, ashMaxSupportedVersion, ashRecommendedVersion)
	}

	if exactErr == nil {
		check(string(exact), true)
		return
	}
	check(string(latest), false)
}

// TestASHBundledConfigProducesNoNewUnknownKeyWarnings.
//
// ASH ships a ~46 KB ferret-config.yaml. This binary accepts an unknown config key with a warning on
// stderr rather than an error -- and ASH passes --quiet and captures stderr into its own progress
// rendering, so those warnings are not where an ASH user will look. The practical effect is that an
// ASH setting can be silently inert.
//
// This is already true of four keys ASH ships today, at these exact paths in its bundled config:
//
//	preprocessors.text_extraction.types   (line 34)  -- the one that MATTERS: ASH lists "pdf" and
//	                                                    "office" here to choose which extractors run,
//	                                                    and the setting has no effect
//	redaction.memory_scrub                (line 92)
//	redaction.audit_trail                 (line 93)
//	redaction.strategies                  (line 96)
//
// The three under redaction. are doubly inert, since ASH also blocks every redaction option outright
// (see ashBlockedOptions), so nothing there was ever going to take effect. preprocessors.types is the
// live problem and is not something this repository can fix unilaterally.
//
// What this CAN do is stop the number growing: renaming a config key here adds a fifth, and an ASH
// user's setting stops taking effect with no error anywhere. So the assertion is on the SET of unknown
// keys, not on there being none.
//
// The fixture reproduces those four paths rather than vendoring 46 KB of someone else's config, which
// would rot faster than it would help.
func TestASHBundledConfigProducesNoNewUnknownKeyWarnings(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("aws key AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The four top-level sections ASH's bundled config sets that this binary does not know, plus one
	// it DOES know so the fixture cannot pass by being rejected wholesale.
	// The four dead paths, at the nesting ASH actually uses -- a flat `types:` at the top level would
	// be unknown for a different reason and would not reproduce ASH's situation.
	//
	// redaction.output_dir is a REAL key and is the control: if the fixture were rejected wholesale, or
	// the resolver stopped recognising real keys, it would be reported unknown too and the assertion
	// below would catch that rather than pass quietly.
	// Reproduced at ASH's exact nesting. text_extraction.enabled and redaction.output_dir/strategy are
	// real keys sitting right beside the dead ones, which is what makes this faithful: the dead keys are
	// not dead because their section is unrecognised.
	cfg := "preprocessors:\n  text_extraction:\n    enabled: true\n    types:\n      - pdf\n      - office\n" +
		"redaction:\n  output_dir: \"./redacted\"\n  strategy: \"format_preserving\"\n" +
		"  memory_scrub: true\n  audit_trail: true\n" +
		"  strategies:\n    simple:\n      replacement: \"[HIDDEN]\"\n"
	cfgPath := filepath.Join(dir, "ash-like.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	sarifPath := filepath.Join(dir, "out.sarif")
	cmd := exec.Command(bin, "--file", in, "--config", cfgPath,
		"--format", "sarif", "--output", sarifPath, "--no-color", "--quiet", "--limit", "0")
	combined, _ := cmd.CombinedOutput()
	rc := cmd.ProcessState.ExitCode()

	if !ashSuccessExitCodes[rc] {
		t.Fatalf("an ASH-shaped config made the binary exit %d, outside ASH's success set %s. ASH "+
			"users would get a failed scanner from a config ASH itself ships.\noutput:\n%s",
			rc, ashSuccessExitCodesDoc, combined)
	}

	got := unknownConfigKeys(string(combined))
	want := map[string]bool{"types": true, "memory_scrub": true, "audit_trail": true, "strategies": true}

	// NON-VACUITY, the control half: redaction.output_dir is a real key. If it shows up as unknown,
	// the resolver is not resolving anything and every "unknown" below is noise rather than signal.
	if got["output_dir"] {
		t.Fatalf("the control key redaction.output_dir was reported UNKNOWN, so the unknown-key "+
			"resolver is not working and the set comparison below would be meaningless.\noutput:\n%s",
			combined)
	}

	// NON-VACUITY, the other half: if the binary stopped warning about unknown keys entirely, this
	// test would pass an emptiness check and we would lose the only signal that a key went dead.
	if len(got) == 0 {
		t.Fatalf("no unknown-key warnings at all, but the fixture deliberately contains four keys "+
			"this binary does not define. Either the warning was removed -- which is worse than the "+
			"problem, since a dead config key becomes completely silent -- or the keys were "+
			"adopted.\noutput:\n%s", combined)
	}

	var unexpected []string
	for k := range got {
		if !want[k] {
			unexpected = append(unexpected, k)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Errorf("config key(s) %v are now unknown to this binary but were not before.\n\n"+
			"ASH ships a bundled ferret-config.yaml and passes --quiet, and this binary only WARNS "+
			"on an unknown key. So a renamed or removed config key does not fail anything: the ASH "+
			"user's setting simply stops taking effect, and the warning goes into stderr that ASH "+
			"captures for its own progress rendering. If a rename is intended, coordinate it with "+
			"ash_ferret_plugins/ferret-config.yaml.\nfull output:\n%s", unexpected, combined)
	}

	// Record the known-inert set so the number is visible in test output rather than only in a
	// comment that can go stale.
	var known []string
	for k := range got {
		if want[k] {
			known = append(known, k)
		}
	}
	sort.Strings(known)
	t.Logf("known-inert keys ASH's bundled config still sets: %v (each is an ASH setting with no effect)", known)
}

// TestASHBlockedOptionsThatMakeFindingsFatalStillRequireAnOptIn.
//
// ASH needs exit 0 on a scan that found data. --pre-commit-mode is the one mode in this binary that
// turns findings into a non-zero exit, and ASH blocks it for exactly that reason. This asserts the
// mode is still OPT-IN: if its behaviour ever became the default, ASH would report a failed scanner
// for every user with anything in their repository, and nothing else in this file would catch it.
func TestASHBlockedOptionsThatMakeFindingsFatalStillRequireAnOptIn(t *testing.T) {
	if !ashBlockedOptions["pre_commit_mode"] {
		t.Fatal("the vendored block list no longer contains pre_commit_mode; this test's premise is gone")
	}
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(
		"aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(extra ...string) (int, string) {
		sarifPath := filepath.Join(dir, fmt.Sprintf("o%d.sarif", len(extra)))
		args := append([]string{"--file", in, "--config", os.DevNull,
			"--format", "sarif", "--output", sarifPath, "--no-color", "--quiet", "--limit", "0"}, extra...)
		c := exec.Command(bin, args...)
		out, _ := c.CombinedOutput()
		return c.ProcessState.ExitCode(), string(out)
	}

	rcDefault, outDefault := run()
	rcPrecommit, _ := run("--pre-commit-mode")

	if rcDefault != 0 {
		t.Errorf("the DEFAULT invocation on a file with findings exited %d, not 0. ASH requires 0 "+
			"here; findings are the expected outcome, not an error.\noutput:\n%s", rcDefault, outDefault)
	}
	// Non-vacuity for the pairing: if --pre-commit-mode ALSO exits 0, this test is not distinguishing
	// the two modes and would keep passing if the default adopted pre-commit behaviour.
	if rcPrecommit == rcDefault {
		t.Errorf("--pre-commit-mode and the default both exit %d, so this test cannot tell them "+
			"apart. Either pre-commit no longer escalates findings, or the default now does -- the "+
			"second would break every ASH scan that finds anything.", rcDefault)
	}
}

// --- small helpers, kept unexported and local to this file ---

// unknownConfigKeys pulls the key names out of this binary's unknown-config-key warnings.
func unknownConfigKeys(output string) map[string]bool {
	const marker = `unknown config key "`
	found := map[string]bool{}
	rest := output
	for {
		i := strings.Index(rest, marker)
		if i < 0 {
			return found
		}
		rest = rest[i+len(marker):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			return found
		}
		found[rest[:j]] = true
		rest = rest[j:]
	}
}

// extractSemverish finds the first dotted numeric run in a --version line.
func extractSemverish(line string) string {
	for _, field := range strings.Fields(line) {
		f := strings.TrimPrefix(field, "v")
		if len(f) == 0 || f[0] < '0' || f[0] > '9' {
			continue
		}
		if strings.Count(f, ".") >= 2 {
			return f
		}
	}
	return ""
}

// cmpSemver compares two dotted version strings numerically, ignoring any pre-release suffix. It
// deliberately does not implement full semver ordering: ASH's own compare_versions is a numeric
// component comparison, and matching what the consumer does matters more here than being correct
// about pre-release precedence.
func cmpSemver(a, b string) int {
	split := func(s string) []int {
		if i := strings.IndexAny(s, "-+"); i >= 0 {
			s = s[:i]
		}
		parts := strings.Split(s, ".")
		nums := make([]int, 0, len(parts))
		for _, p := range parts {
			n := 0
			for _, c := range p {
				if c < '0' || c > '9' {
					break
				}
				n = n*10 + int(c-'0')
			}
			nums = append(nums, n)
		}
		return nums
	}
	x, y := split(a), split(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var xi, yi int
		if i < len(x) {
			xi = x[i]
		}
		if i < len(y) {
			yi = y[i]
		}
		if xi != yi {
			if xi < yi {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ashPrecommitSignals are the environment variables that switch this binary into pre-commit
// behaviour, from internal/precommit/detector.go's detectEnvironment. Detection is from the
// ENVIRONMENT ALONE -- it takes no flag and no argument.
var ashPrecommitSignals = []string{
	"PRE_COMMIT=1",
	"_PRE_COMMIT_RUNNING=1",
	"PRE_COMMIT_HOME=/tmp/pch",
	"PRE_COMMIT_HOOK=1",
	"GIT_HOOK_TYPE=pre-commit",
}

// ashInvocation is the flag set ASH sends on every scan, so these two tests cannot drift from what
// ASH actually does.
func ashInvocation(in, sarifPath string) []string {
	return []string{
		"--file", in,
		"--config", os.DevNull,
		"--format", "sarif",
		"--output", sarifPath,
		"--no-color", "--quiet",
		"--limit", "0",
	}
}

// runASHScan runs ASH's invocation under an explicit, minimal environment and returns the exit code
// and the sorted ruleId set.
//
// The environment is built from scratch rather than inherited, because a developer machine with
// pre-commit installed exports PRE_COMMIT_HOME, which would make the control run behave like the
// hijacked one and the whole comparison would read as "no difference".
func runASHScan(t *testing.T, bin, in, sarifPath string, env []string) (int, []string) {
	t.Helper()
	cmd := exec.Command(bin, ashInvocation(in, sarifPath)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}, env...)
	_ = os.Remove(sarifPath)
	out, _ := cmd.CombinedOutput()
	rc := cmd.ProcessState.ExitCode()

	b, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("no SARIF written under env %v (rc=%d): %v\noutput:\n%s", env, rc, err, out)
	}
	var d sarifDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("unparseable SARIF under env %v (rc=%d): %v", env, rc, err)
	}
	if len(d.Runs) == 0 || d.Runs[0].Results == nil {
		t.Fatalf("SARIF under env %v has no runs[0].results array (rc=%d)", env, rc)
	}
	ids := make([]string, 0, len(*d.Runs[0].Results))
	for _, r := range *d.Runs[0].Results {
		ids = append(ids, r.RuleID)
	}
	sort.Strings(ids)
	return rc, ids
}

// ashHijackFixture is one HIGH finding plus one LOW finding. Both matter: the exit code changes
// because findings exist, and the result SET changes because pre-commit mode applies a confidence
// filter. A fixture with only HIGH findings would show the exit-code change and hide the filtering.
const ashHijackFixture = "aws key AKIAIOSFODNN7EXAMPLE\ncard 4532015112830366\n"

// TestPrecommitEnvVarsHijackASHsInvocation is a CHARACTERISATION test: it records the exact shape of
// a live break rather than asserting the break is absent.
//
// Measured, with ASH's flag set byte-identical and ONLY the environment changing:
//
//	environment                  exit   ruleIds in the SARIF
//	(none)                        0     AWS_ACCESS_KEY, VISA
//	PRE_COMMIT=1                  1     VISA
//	_PRE_COMMIT_RUNNING=1         1     VISA
//	PRE_COMMIT_HOME=...           1     VISA
//	PRE_COMMIT_HOOK=1             1     VISA
//	GIT_HOOK_TYPE=pre-commit      1     VISA
//
// Two independent consequences for ASH, from one variable it does not set and cannot see:
//
//  1. exit 1 is OUTSIDE ASH's success_exit_codes {0, 3}, so ASH reports the scanner as FAILED
//     instead of reporting findings. Total, not partial.
//  2. the result set shrinks, because detection also switches the active profile
//     (generateOptimizedConfig sets ProfileName "precommit" and ExitOnFindings "high"). The dropped
//     finding here is AWS_ACCESS_KEY at confidence 15, so this is a confidence filter rather than a
//     HIGH-finding leak -- but it means ASH's results depend on ambient environment.
//
// PRE_COMMIT_HOME is the one most likely to bite: `pre-commit` sets it, so any CI image or developer
// shell where pre-commit is installed can carry it into an unrelated ASH run.
//
// This is asserted as the CURRENT behaviour on purpose. If a future change makes ASH's invocation
// immune, this test fails -- which is the correct outcome, because at that point ASH's workaround
// (see the next test) is no longer needed and its docs should say so.
func TestPrecommitEnvVarsHijackASHsInvocation(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(ashHijackFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	baseRC, baseIDs := runASHScan(t, bin, in, filepath.Join(dir, "base.sarif"), nil)

	// NON-VACUITY: the control must be the good case, with MORE THAN ONE finding, or "the set shrank"
	// is unobservable and "exit 0" is not being contrasted with anything.
	if baseRC != 0 {
		t.Fatalf("control run exited %d, not 0; the comparison below has no clean baseline", baseRC)
	}
	if len(baseIDs) < 2 {
		t.Fatalf("control run produced %d finding(s) (%v); this test needs at least two, one of them "+
			"below HIGH, or the result-set change cannot be seen", len(baseIDs), baseIDs)
	}

	for i, sig := range ashPrecommitSignals {
		t.Run(strings.SplitN(sig, "=", 2)[0], func(t *testing.T) {
			rc, ids := runASHScan(t, bin, in, filepath.Join(dir, fmt.Sprintf("h%d.sarif", i)), []string{sig})

			if ashSuccessExitCodes[rc] {
				t.Errorf("%s no longer changes the exit code (rc=%d is inside ASH's success set %s).\n"+
					"That is an IMPROVEMENT, not a regression: ASH's invocation is now immune to this "+
					"signal. Update this characterisation test and tell the ASH plugin owners that the "+
					"FERRET_PRECOMMIT=0 workaround is no longer required for it.",
					sig, rc, ashSuccessExitCodesDoc)
			}
			if len(ids) == len(baseIDs) {
				t.Logf("%s changed the exit code but NOT the result set (%v) — the confidence "+
					"filtering half of this break appears to be gone", sig, ids)
			}
			t.Logf("%-28s rc=%d ruleIds=%v   (control: rc=%d %v)", sig, rc, ids, baseRC, baseIDs)
		})
	}
}

// TestFerretPrecommitOptOutNeutralisesEveryPrecommitSignal is the guard that protects ASH's remedy.
//
// FERRET_PRECOMMIT=0 exists precisely so a caller can decline pre-commit behaviour (#353: "there was
// no way to decline it"). Measured, it fully restores ASH's contract -- exit 0 and the complete result
// set -- for every one of the five signals. So the fix on ASH's side is one line: put
// FERRET_PRECOMMIT=0 in the subprocess environment.
//
// This test exists because that remedy is invisible from ASH's side. If a change here stopped the
// opt-out neutralising one of the five signals, ASH would keep setting the variable, keep believing it
// was protected, and silently start reporting failed scans again. Nothing else in this repository ties
// the opt-out to the five signals it has to cover.
func TestFerretPrecommitOptOutNeutralisesEveryPrecommitSignal(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(ashHijackFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	baseRC, baseIDs := runASHScan(t, bin, in, filepath.Join(dir, "base.sarif"), nil)
	if baseRC != 0 || len(baseIDs) < 2 {
		t.Fatalf("control run is rc=%d with %d finding(s) %v; this test compares against a clean "+
			"multi-finding baseline and does not have one", baseRC, len(baseIDs), baseIDs)
	}

	if len(ashPrecommitSignals) < 5 {
		t.Fatalf("only %d pre-commit signals listed; detectEnvironment checks five, so this guard "+
			"would leave some uncovered", len(ashPrecommitSignals))
	}

	for i, sig := range ashPrecommitSignals {
		name := strings.SplitN(sig, "=", 2)[0]
		t.Run(name, func(t *testing.T) {
			// NON-VACUITY, per signal: prove THIS signal actually hijacks the run before checking that
			// the opt-out undoes it. Otherwise a signal that silently stopped working would make the
			// opt-out look effective when there was nothing to opt out of.
			hijackRC, hijackIDs := runASHScan(t, bin, in,
				filepath.Join(dir, fmt.Sprintf("j%d.sarif", i)), []string{sig})
			if hijackRC == baseRC && len(hijackIDs) == len(baseIDs) {
				t.Skipf("%s no longer changes anything (rc=%d, ids=%v), so there is nothing for the "+
					"opt-out to neutralise here", sig, hijackRC, hijackIDs)
			}

			rc, ids := runASHScan(t, bin, in,
				filepath.Join(dir, fmt.Sprintf("o%d.sarif", i)), []string{sig, "FERRET_PRECOMMIT=0"})

			if rc != baseRC {
				t.Errorf("with %s set, FERRET_PRECOMMIT=0 left the exit code at %d instead of "+
					"restoring %d.\n\nASH's only way to decline pre-commit behaviour is this variable. "+
					"If it stops covering %s, ASH keeps setting it, keeps believing it is protected, "+
					"and silently reports a FAILED scanner for every user whose environment carries "+
					"that variable. See internal/precommit/detector.go precommitOptOut and #353.",
					sig, rc, baseRC, sig)
			}
			if strings.Join(ids, ",") != strings.Join(baseIDs, ",") {
				t.Errorf("with %s set, FERRET_PRECOMMIT=0 produced ruleIds %v instead of restoring "+
					"%v. ASH's SARIF would be missing findings it gets in a clean environment, with "+
					"nothing anywhere saying so.", sig, ids, baseIDs)
			}
		})
	}
}

// TestASHFoldedExcludeFailureModes pins the two ways ASH's --exclude folding can go wrong.
//
// ASH concatenates EVERY exclude_patterns entry plus every global_ignore_paths entry into ONE
// comma-separated --exclude value. That makes the whole list share a fate, which is why both of these
// matter more for ASH than they would for a human typing one pattern:
//
//  1. A malformed pattern -- an unmatched '[' is the realistic case -- makes this binary exit 1 with
//     NO SARIF WRITTEN AT ALL. Measured: rc=1, no output file, the reason only on stderr, which ASH
//     captures into its own progress rendering. So one typo in one entry of a user's ASH config costs
//     the entire ferret-scan run, and the explanation is not where they will look.
//
//     Failing loudly here is the RIGHT behaviour and this test defends it: silently ignoring a bad
//     pattern would mean an exclusion the user asked for is not applied, and they would never know.
//     The finding is for ASH's side -- it should validate patterns before folding them.
//
//  2. A globstar pattern CONTAINING A SEPARATOR, like '**/*.pyc' or '**/node_modules/**', is accepted
//     and does nothing: rc=0, no warning, full result set. Patterns go through Go's filepath.Match,
//     which has no '**' and whose '*' has no authority over '/'. For a scanner, scanning MORE than
//     intended is the safe direction, so this is not a leak -- but an ASH user writing globstar syntax
//     gets silence rather than an exclusion, and silence reads as success.
//
//     The separator is the operative part, and BARE '**' is the opposite case: it matches everything
//     at one level, excludes the entire tree, and DOES warn. So this is not "globstar is ignored", it
//     is "a relative pattern containing a path separator cannot match", which also catches ordinary
//     patterns like 'build/out' -- the scan path is absolutised (cmd/main.go) before filepath.Match
//     sees it, so only an ABSOLUTE multi-segment pattern can match.
func TestASHFoldedExcludeFailureModes(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"),
		[]byte("aws key AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runExclude := func(pattern string) (int, string, bool) {
		sarifPath := filepath.Join(t.TempDir(), "out.sarif")
		cmd := exec.Command(bin, "--file", dir, "--recursive", "--config", os.DevNull,
			"--exclude", pattern, "--format", "sarif", "--output", sarifPath,
			"--no-color", "--quiet", "--limit", "0")
		out, _ := cmd.CombinedOutput()
		_, statErr := os.Stat(sarifPath)
		return cmd.ProcessState.ExitCode(), string(out), statErr == nil
	}

	// NON-VACUITY: the well-formed ASH-shaped value must succeed and produce a SARIF, or "the bad
	// pattern failed" tells us nothing about the pattern.
	rcGood, outGood, wroteGood := runExclude(".venv,.git,*.pyc")
	if rcGood != 0 || !wroteGood {
		t.Fatalf("the well-formed ASH-shaped --exclude value failed (rc=%d, sarif written=%v); the "+
			"comparisons below have no working baseline.\noutput:\n%s", rcGood, wroteGood, outGood)
	}

	t.Run("malformed pattern aborts with no SARIF", func(t *testing.T) {
		// An unmatched '[' is the realistic typo: it is legal in a filename and is filepath.Match's
		// only syntax error.
		rc, out, wrote := runExclude("foo[")

		if rc == 0 {
			t.Errorf("a malformed --exclude pattern was ACCEPTED (rc=0). That is worse than the "+
				"current behaviour, not better: the user's exclusion silently does not apply and "+
				"nothing says so.\noutput:\n%s", out)
		}
		if ashSuccessExitCodes[rc] {
			t.Errorf("rc=%d is inside ASH's success set %s, so ASH would treat a run that produced "+
				"nothing as a SUCCESSFUL scan — a clean bill of health for a file that was never "+
				"examined.\noutput:\n%s", rc, ashSuccessExitCodesDoc, out)
		}
		if wrote {
			t.Logf("a SARIF WAS written despite the rejected pattern; ASH reads the file regardless " +
				"of exit status (check=False), so its contents now matter here")
		}
		if !strings.Contains(out, "--exclude") {
			t.Errorf("the error text does not mention --exclude, so an ASH user digging it out of "+
				"captured stderr cannot tell which of their folded patterns was at fault.\n"+
				"output:\n%s", out)
		}
	})

	t.Run("globstar excludes at every depth and a zero-hit pattern is reported", func(t *testing.T) {
		// This subtest used to pin the OPPOSITE: '**/*.txt' as a silent no-op, with an
		// instruction to update it when that improved. #729 improved it: relative patterns are
		// matched against the scan-root-relative path with real '**' support, and a pattern that
		// matched nothing by scan end is reported on stderr. Both halves matter to ASH, which
		// folds user exclude_patterns verbatim into one --exclude value.
		rc, out, wrote := runExclude("**/*.txt")
		if rc != 0 || !wrote {
			t.Fatalf("globstar exclusion should still be a successful run, got rc=%d written=%v.\n%s",
				rc, wrote, out)
		}
		if strings.Contains(out, "matched nothing") {
			t.Errorf("'**/*.txt' matched the fixture; the zero-hit note must not fire.\n%s", out)
		}
		rc2, out2, _ := runExclude("**/*.nomatch")
		if rc2 != 0 {
			t.Fatalf("a zero-hit pattern must not fail the run (scanning MORE is the safe "+
				"direction), got rc=%d.\n%s", rc2, out2)
		}
		if !strings.Contains(out2, "matched nothing") {
			t.Errorf("a pattern that matched nothing must be reported, and was not.\n%s", out2)
		}
	})
}

// TestOnlyShowMatchPutsMatchedValuesIntoASHsSARIF.
//
// ASH aggregates the SARIF it gets from here into a report that is typically archived as a CI artifact
// for a whole organisation. So "which flags cause a raw matched value to appear in that file" is a
// disclosure boundary, not a formatting preference.
//
// ASH treats it as exactly one flag: it emits --show-match only when explicitly enabled and logs a
// warning telling operators to "Disable this option in production environments". It attaches no such
// warning to --explain, which it also emits, and which adds per-finding rationale text -- a plausible
// place for a value to end up.
//
// Measured, with ASH's flag set and a fixture carrying an SSN, a card and an AWS key:
//
//	flags                       matched values in the SARIF
//	(none)                      none
//	--explain                   none
//	--show-match                all three
//	--explain --show-match      all three
//
// So ASH's warning is on the right flag and only that flag. This pins it: if --explain (or any of
// ASH's other flags) started carrying values, an organisation's aggregated ASH report would begin
// accumulating cleartext PII with no warning anywhere, because ASH's operators were told the risk was
// --show-match.
func TestOnlyShowMatchPutsMatchedValuesIntoASHsSARIF(t *testing.T) {
	bin := buildForASHContract(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")

	// Values chosen to be findable and distinctive. They are test vectors, not real data.
	values := []string{"456-78-9012", "4532015112830366", "AKIAIOSFODNN7EXAMPLE"}
	content := "ssn " + values[0] + "\nvisa " + values[1] + "\naws " + values[2] + "\n"
	if err := os.WriteFile(in, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	leaked := func(extra ...string) (int, []string) {
		sarifPath := filepath.Join(t.TempDir(), "out.sarif")
		args := append(ashInvocation(in, sarifPath), extra...)
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		out, _ := cmd.CombinedOutput()
		b, err := os.ReadFile(sarifPath)
		if err != nil {
			t.Fatalf("no SARIF for flags %v: %v\noutput:\n%s", extra, err, out)
		}
		var found []string
		for _, v := range values {
			if strings.Contains(string(b), v) {
				found = append(found, v)
			}
		}
		// Count findings so a run that detected nothing cannot read as "no leak".
		var d sarifDoc
		if err := json.Unmarshal(b, &d); err != nil {
			t.Fatalf("unparseable SARIF for flags %v: %v", extra, err)
		}
		n := 0
		if len(d.Runs) > 0 && d.Runs[0].Results != nil {
			n = len(*d.Runs[0].Results)
		}
		return n, found
	}

	// NON-VACUITY, and it is the whole test. A fixture that produced no findings would leak nothing
	// under every flag combination and this test would pass against a binary that had stopped
	// detecting. --show-match is also the positive control: if it does NOT reveal, then the grep is
	// not capable of finding a value here and every "no leak" below is meaningless.
	nShow, leakShow := leaked("--show-match")
	if nShow < len(values) {
		t.Fatalf("--show-match run found only %d finding(s), want >= %d; the leak checks below would "+
			"be searching a SARIF that never described these values", nShow, len(values))
	}
	if len(leakShow) != len(values) {
		t.Fatalf("--show-match revealed %d of %d values (%v). It is the positive control: if it does "+
			"not reveal them, this test cannot detect a leak at all", len(leakShow), len(values), leakShow)
	}

	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"ASH default flag set", nil},
		{"--explain", []string{"--explain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, found := leaked(tc.extra...)
			if n < len(values) {
				t.Fatalf("only %d finding(s) with %v, want >= %d — a run that detected less than the "+
					"control cannot be compared against it for disclosure", n, tc.extra, len(values))
			}
			if len(found) > 0 {
				t.Errorf("matched value(s) reached the SARIF WITHOUT --show-match, with flags %v: %d "+
					"of %d values present.\n\nASH aggregates this file into a report that is commonly "+
					"archived as a CI artifact for a whole organisation, and it warns operators about "+
					"--show-match ONLY. If another flag reveals values, that report starts "+
					"accumulating cleartext with no warning anywhere. Values are not printed here on "+
					"purpose.", tc.extra, len(found), len(values))
			}
		})
	}
}
