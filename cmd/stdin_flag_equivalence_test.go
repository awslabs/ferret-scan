// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The gate for #887: every flag the binary registers either behaves on --stdin as it does on --file, or
// is classified here with the reason it cannot.
//
// The class it closes is "a main() step that runs after the stdin dispatch, or a configFlags field the
// stdin copy lacks". Measured before the fix, five flags did nothing on --stdin and said nothing
// (--disable-ip-types, --suppression-expires, --list-profiles, --debug, --redaction-output-dir) and an
// unknown --profile scanned with the defaults at rc 0. cmd/checks_parity_test.go covered --checks only,
// which is how #295 fixed one member and left the rest.
//
// The flag list comes from realFlags (the registrations in cmd/*.go), not from --help, so a flag added
// later fails TestEveryFlagHasAStdinClass until someone decides which class it is in.

type stdinClass int

const (
	// sameAsFile: a row in stdinParityRows runs it through both paths and compares the results.
	sameAsFile stdinClass = iota
	// beforeDispatch: answered before the input split, so --stdin does not change it.
	beforeDispatch
	// refusedOnStdin: --stdin refuses it, rc 1, naming the flag.
	refusedOnStdin
	// noticeOnStdin: --stdin cannot use it and says so on stderr.
	noticeOnStdin
	// notApplicable: nothing to compare, for the stated reason.
	notApplicable
)

type stdinFlagClass struct {
	class  stdinClass
	reason string
}

var stdinFlagClasses = map[string]stdinFlagClass{
	"checks":                {class: sameAsFile},
	"confidence":            {class: sameAsFile},
	"config":                {class: sameAsFile},
	"debug":                 {class: sameAsFile},
	"disable-ip-types":      {class: sameAsFile},
	"enable-redaction":      {class: sameAsFile},
	"explain":               {class: sameAsFile},
	"fail-on-incomplete":    {class: sameAsFile},
	"format":                {class: sameAsFile},
	"generate-suppressions": {class: sameAsFile},
	"limit":                 {class: sameAsFile},
	"output":                {class: sameAsFile},
	"p":                     {class: sameAsFile},
	"pre-commit-mode":       {class: sameAsFile},
	"preprocess-only":       {class: sameAsFile},
	"profile":               {class: sameAsFile},
	"redaction-strategy":    {class: sameAsFile},
	"show-match":            {class: sameAsFile},
	"show-suppressed":       {class: sameAsFile},
	"suppression-expires":   {class: sameAsFile},
	"suppression-file":      {class: sameAsFile},
	"validator-budget":      {class: sameAsFile},
	"verbose":               {class: sameAsFile},

	"help":          {class: beforeDispatch, reason: "main() skips the stdin hand-off for --help"},
	"version":       {class: beforeDispatch, reason: "main() skips the stdin hand-off for --version"},
	"list-profiles": {class: beforeDispatch, reason: "answered before the hand-off, so stdin is never read (#887)"},
	"web":           {class: beforeDispatch, reason: "the web hand-off runs before the stdin one"},
	"stdin":         {class: beforeDispatch, reason: "it is the dispatch"},

	"recursive": {class: refusedOnStdin, reason: "there is no directory to walk"},
	"file":      {class: refusedOnStdin, reason: "a path and stdin are two inputs; `--file -` is the stdin alias (its own row)"},

	"redaction-audit-log":  {class: noticeOnStdin, reason: "the audit log needs the on-disk index manager"},
	"redaction-output-dir": {class: noticeOnStdin, reason: "the redacted content is the stream on stdout (#887)"},

	"exclude":              {class: notApplicable, reason: "filters the directory walk, which stdin does not have"},
	"respect-gitignore":    {class: notApplicable, reason: "filters the directory walk, which stdin does not have"},
	"enable-preprocessors": {class: notApplicable, reason: "stdin is plain text and never reaches a document preprocessor"},
	"max-live-bytes":       {class: notApplicable, reason: "bounds the worker pool, which ScanContent does not use"},
	"port":                 {class: notApplicable, reason: "web mode only"},
	"bind":                 {class: notApplicable, reason: "web mode only"},
	"stdin-name":           {class: notApplicable, reason: "names the input on --stdin, as the path does on --file; the rows below use it to give both paths one name"},
	"no-color":             {class: notApplicable, reason: "colour is only written to a terminal: with stdout piped both paths write 0 ESC bytes with and without the flag (measured)"},
	"quiet": {class: notApplicable, reason: "--file writes no progress prose when stderr is not a terminal, so there is no file result to match; " +
		"disclosures ignore it on both paths (the --quiet row). Found here, not fixed: --stdin --quiet also withholds the unknown-config-key warning, which --file prints"},
}

func TestEveryFlagHasAStdinClass(t *testing.T) {
	real := realFlags(t)
	for name := range real {
		if _, ok := stdinFlagClasses[name]; !ok {
			t.Errorf("flag --%s has no entry in stdinFlagClasses. Decide how it behaves on --stdin and add it: "+
				"a flag that silently does nothing there is the defect class of #887", name)
		}
	}
	for name, c := range stdinFlagClasses {
		if !real[name] {
			t.Errorf("stdinFlagClasses lists --%s, which cmd/*.go does not register; remove the stale entry", name)
		}
		if c.class != sameAsFile && c.reason == "" {
			t.Errorf("--%s is not compared but carries no reason", name)
		}
	}
}

// parityFixtures are written into the work directory of every row. All values are synthetic: a patent
// number of zeros, a URL on the reserved .test TLD, an SSN outside the issued ranges.
var parityFixtures = map[string]string{
	"cp.txt": "Copyright (c) 2024 Example Corp. All rights reserved.\nMeeting notes: nothing else.\n",
	"ip.txt": "Copyright (c) 2024 Example Corp. All rights reserved.\n" +
		"This design is covered by patent US 000,000,000 filed by Example Corp.\n" +
		"ExampleWidget(TM) is a product name used in this sample.\n" +
		"Company Confidential - trade secret material, internal use only.\n",
	"pii.txt": "Customer record (synthetic test data)\nContact email: jane.doe@example.com\n" +
		"SSN: 345-67-8901\nCopyright (c) 2024 Example Corp. All rights reserved.\n",
	"iu.txt":     "See the runbook at https://docs.example.test/runbooks/deploy for details.\n",
	"ipoff.yaml": "validators:\n  intellectual_property:\n    disabled_types: [copyright]\n",
	"iu.yaml":    "validators:\n  intellectual_property:\n    internal_urls: ['https?://[a-z0-9.-]+\\.example\\.test']\n",
	"ipscan.yaml": "profiles:\n  ipscan:\n    description: adds the internal URL pattern\n    validators:\n" +
		"      intellectual_property:\n        internal_urls: ['https?://[a-z0-9.-]+\\.example\\.test']\n",
	"nopat.yaml": "profiles:\n  nopatent:\n    description: no patents\n    validators:\n      intellectual_property:\n" +
		"        disabled_types: [patent]\n",
	"exp.yaml": "suppressions:\n  expires_in: 30d\n",
	// budget.txt is the cut-short fixture the budget rows scan: ten addresses and about 1 MB of
	// neutral filler, cutShortBudgetParas. A 1ns budget is a timer, not an already-expired deadline,
	// on a clock as coarse as Windows's (ticks of 0.5-15.6 ms), so a validator over four short
	// lines finishes before the timer fires and the budget never shows; the rows then compared two
	// uncut scans and failed as "proves nothing" on windows-latest while passing on the other two
	// runners. Over this filler PHONE is still polling its context when the timer fires on any
	// clock (#797 measured its pass at 400-600 ms), so the cut is deterministic. Same fixture and
	// reasoning as TestCutShortRedactionFollowsTheFileRule.
	"budget.txt": strings.Join(cutShortBudgetParas(), "\n") + "\n",
}

// paritySide is one input path of one row, with a scratch directory for what it writes.
type paritySide struct {
	stdin bool
	dir   string
}

// parityRow runs args through --file and --stdin and compares project() of the two; it also runs base
// through --file and requires a different projection, so a row cannot pass because its flag did nothing.
type parityRow struct {
	name    string
	flag    string // the sameAsFile flag the row covers; "" for an extra row
	fixture string
	args    []string
	base    []string
	project func(t *testing.T, r cliRun, s paritySide, fixture string) string
	// redacts adds --redaction-output-dir to the --file side, whose redacted copy project compares with
	// the --stdin side's stdout.
	redacts bool
	// fileArgs replaces "--file <fixture>" on the file side; the `--file -` row uses it.
	fileArgs []string
}

// placeholders in args, replaced per side so the two runs never share an output.
const (
	phOut   = "@OUT@"
	phRules = "@RULES@"
)

func stdinParityRows() []parityRow {
	common := []string{"--format", "json", "--confidence", "all", "--limit", "0"}
	with := func(extra ...string) []string { return append(append([]string{}, common...), extra...) }
	return []parityRow{
		{name: "checks", flag: "checks", fixture: "pii.txt", args: with("--checks", "SSN"), base: with(), project: projectReport},
		{name: "confidence", flag: "confidence", fixture: "pii.txt", args: with("--confidence", "high"), base: with(), project: projectReport},
		{name: "limit", flag: "limit", fixture: "pii.txt", args: with("--limit", "1"), base: with(), project: projectReport},
		{name: "show-match", flag: "show-match", fixture: "pii.txt", args: with("--show-match"), base: with(), project: projectReport},
		{name: "explain", flag: "explain", fixture: "pii.txt", args: with("--explain"), base: with(), project: projectReport},
		{name: "config", flag: "config", fixture: "cp.txt", args: with("--config", "ipoff.yaml"), base: with(), project: projectReport},
		{name: "profile", flag: "profile", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "nopat.yaml", "--profile", "nopatent"),
			base: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "nopat.yaml"), project: projectReport},
		// Row 8 of #887: --stdin scanned with the defaults at rc 0.
		{name: "profile, unknown name", fixture: "cp.txt", args: with("--profile", "nosuch"), base: with(), project: projectReport},
		// The gateway with a mistyped profile that adds a URL pattern: --stdin used to pass the URL through in clear.
		{name: "profile, mistyped in the gateway", fixture: "iu.txt", redacts: true,
			args: []string{"--enable-redaction", "--config", "ipscan.yaml", "--profile", "ipscna"},
			base: []string{"--enable-redaction", "--config", "ipscan.yaml", "--profile", "ipscan"}, project: projectRedacted},
		{name: "disable-ip-types", flag: "disable-ip-types", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--disable-ip-types", "trademark"),
			base: with("--checks", "INTELLECTUAL_PROPERTY"), project: projectReport},
		{name: "disable-ip-types, trade-secret marking (no ip_type)", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--disable-ip-types", "trade_secret"),
			base: with("--checks", "INTELLECTUAL_PROPERTY"), project: projectReport},
		{name: "disable-ip-types, the Note survives --quiet", fixture: "cp.txt",
			args: with("--quiet", "--disable-ip-types", "copyright"), base: with("--quiet"), project: projectReport},
		{name: "disable-ip-types, a name that matches nothing is warned", fixture: "cp.txt",
			args: with("--disable-ip-types", "copyrite"), base: with(), project: projectReport},
		// Row 3: the flag outranks the config's set, and the gateway masks what the flag left on.
		{name: "disable-ip-types beats the config's set", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "ipoff.yaml", "--disable-ip-types", "patent"),
			base: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "ipoff.yaml"), project: projectReport},
		{name: "disable-ip-types beats the config's set, gateway", fixture: "ip.txt", redacts: true,
			args: []string{"--enable-redaction", "--checks", "INTELLECTUAL_PROPERTY", "--config", "ipoff.yaml", "--disable-ip-types", "patent"},
			base: []string{"--enable-redaction", "--checks", "INTELLECTUAL_PROPERTY", "--config", "ipoff.yaml"}, project: projectRedacted},
		// Row 10, the file-mode half of the defect: a profile's disabled_types used to beat the flag.
		{name: "disable-ip-types beats the profile's set", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "nopat.yaml", "--profile", "nopatent", "--disable-ip-types", "copyright"),
			base: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "nopat.yaml", "--profile", "nopatent"), project: projectReport},
		{name: "disable-ip-types keeps the config's internal_urls", fixture: "iu.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "iu.yaml", "--disable-ip-types", "copyright"),
			base: with("--checks", "INTELLECTUAL_PROPERTY", "--config", "iu.yaml", "--disable-ip-types", "internal_url"), project: projectReport},
		{name: "--file - is the stdin alias", fixture: "cp.txt", fileArgs: []string{"--file", "-", "--stdin-name", "cp.txt"},
			args: with("--disable-ip-types", "copyright"), base: with(), project: projectReport},
		{name: "pre-commit-mode", flag: "pre-commit-mode", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--pre-commit-mode"), base: with("--checks", "INTELLECTUAL_PROPERTY"), project: projectReport},
		// Row 6: a disabled sub-type no longer blocks the commit on --stdin.
		{name: "pre-commit-mode with a disabled sub-type", fixture: "ip.txt",
			args: with("--checks", "INTELLECTUAL_PROPERTY", "--pre-commit-mode", "--disable-ip-types", "trade_secret"),
			base: with("--checks", "INTELLECTUAL_PROPERTY", "--pre-commit-mode"), project: projectReport},
		// Both budget rows scan budget.txt with --checks EMAIL,PHONE and budget PHONE only: the cut has
		// to come from a validator whose pass outlasts the clock tick (see the fixture's comment), and
		// EMAIL's ten findings are what the two paths are compared on once PHONE is cut.
		{name: "validator-budget", flag: "validator-budget", fixture: "budget.txt",
			args: with("--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns"),
			base: with("--checks", "EMAIL,PHONE"), project: projectCutShort},
		{name: "fail-on-incomplete", flag: "fail-on-incomplete", fixture: "budget.txt",
			args: with("--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns", "--fail-on-incomplete"),
			base: with("--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns"), project: projectCutShort},
		{name: "format", flag: "format", fixture: "pii.txt", args: with("--format", "yaml"), base: with(), project: projectFormat},
		{name: "output", flag: "output", fixture: "pii.txt", args: with("--output", phOut), base: with(), project: projectOutputFile},
		{name: "verbose", flag: "verbose", fixture: "pii.txt", args: []string{"--format", "text", "--verbose"},
			base: []string{"--format", "text"}, project: projectText},
		{name: "debug", flag: "debug", fixture: "cp.txt", args: with("--debug", "--disable-ip-types", "copyright"),
			base: with("--disable-ip-types", "copyright"), project: projectDebug},
		{name: "preprocess-only", flag: "preprocess-only", fixture: "cp.txt", args: []string{"--preprocess-only"}, base: with(), project: projectPreprocess},
		{name: "p", flag: "p", fixture: "cp.txt", args: []string{"-p"}, base: with(), project: projectPreprocess},
		{name: "enable-redaction", flag: "enable-redaction", fixture: "ip.txt", redacts: true,
			args: []string{"--enable-redaction", "--checks", "INTELLECTUAL_PROPERTY"}, base: []string{"--checks", "INTELLECTUAL_PROPERTY"}, project: projectRedacted},
		{name: "redaction-strategy", flag: "redaction-strategy", fixture: "ip.txt", redacts: true,
			args: []string{"--enable-redaction", "--checks", "INTELLECTUAL_PROPERTY", "--redaction-strategy", "simple"},
			base: []string{"--enable-redaction", "--checks", "INTELLECTUAL_PROPERTY"}, project: projectRedacted},
		{name: "generate-suppressions", flag: "generate-suppressions", fixture: "cp.txt",
			args: with("--generate-suppressions", "--suppression-file", phRules), base: with("--suppression-file", phRules), project: projectRules},
		// Row 7: generated rules carry expires_at from the flag and from the config key.
		{name: "suppression-expires", flag: "suppression-expires", fixture: "cp.txt",
			args: with("--generate-suppressions", "--suppression-file", phRules, "--suppression-expires", "30d"),
			base: with("--generate-suppressions", "--suppression-file", phRules), project: projectRules},
		{name: "suppressions.expires_in", fixture: "cp.txt",
			args: with("--config", "exp.yaml", "--generate-suppressions", "--suppression-file", phRules),
			base: with("--generate-suppressions", "--suppression-file", phRules), project: projectRules},
		{name: "suppression-expires, a spelling that does not parse", fixture: "cp.txt",
			args: with("--generate-suppressions", "--suppression-file", phRules, "--suppression-expires", "bogus"),
			base: with("--generate-suppressions", "--suppression-file", phRules), project: projectRules},
		{name: "suppression-file", flag: "suppression-file", fixture: "cp.txt",
			args: with("--suppression-file", "enabled.yaml"), base: with(), project: projectReport},
		{name: "show-suppressed", flag: "show-suppressed", fixture: "cp.txt",
			args: with("--suppression-file", "enabled.yaml", "--show-suppressed"), base: with("--suppression-file", "enabled.yaml"), project: projectReport},
		// #866: --stdin printed no EXPIRED warning at all.
		{name: "suppression-file, an expired rule", fixture: "cp.txt",
			args: with("--suppression-file", "expired.yaml"), base: with("--suppression-file", "enabled.yaml"), project: projectReport},
	}
}

func TestStdinBehavesAsFileForEveryComparedFlag(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	for name, body := range parityFixtures {
		writeFixture(t, filepath.Join(work, name), body)
	}
	writeParitySuppressionFiles(t, bin, work, env)

	rows := stdinParityRows()
	covered := map[string]bool{}
	for _, row := range rows {
		if row.flag == "" {
			continue
		}
		if c, ok := stdinFlagClasses[row.flag]; !ok || c.class != sameAsFile {
			t.Errorf("row %q covers --%s, which is not classified sameAsFile", row.name, row.flag)
		}
		covered[row.flag] = true
	}
	for name, c := range stdinFlagClasses {
		if c.class == sameAsFile && !covered[name] {
			t.Errorf("--%s is classified sameAsFile but no row compares it", name)
		}
	}

	for _, row := range rows {
		row := row
		t.Run(row.name, func(t *testing.T) {
			file := runParitySide(t, bin, work, env, row, row.args, false)
			stdin := runParitySide(t, bin, work, env, row, row.args, true)
			base := runParitySide(t, bin, work, env, row, row.base, false)
			if file.view != stdin.view {
				t.Errorf("--stdin differs from --file for %v\n--file:\n%s\n--stdin:\n%s\n--stdin stderr:\n%s",
					row.args, file.view, stdin.view, stdin.run.stderr)
			}
			if file.view == base.view {
				t.Errorf("the row proves nothing: --file gives the same result with and without its flag (%v vs %v):\n%s",
					row.args, row.base, file.view)
			}
		})
	}
}

type paritySideResult struct {
	run  cliRun
	view string
}

func runParitySide(t *testing.T, bin, work string, env []string, row parityRow, args []string, stdin bool) paritySideResult {
	t.Helper()
	side := paritySide{stdin: stdin, dir: t.TempDir()}
	var argv []string
	input := ""
	switch {
	case stdin:
		argv = []string{"--stdin", "--stdin-name", row.fixture}
		input = parityFixtures[row.fixture]
	case row.fileArgs != nil:
		argv = append([]string{}, row.fileArgs...)
		input = parityFixtures[row.fixture]
	default:
		argv = []string{"--file", row.fixture}
	}
	for _, a := range args {
		a = strings.ReplaceAll(a, phOut, filepath.Join(side.dir, "out.json"))
		a = strings.ReplaceAll(a, phRules, filepath.Join(side.dir, "rules.yaml"))
		argv = append(argv, a)
	}
	if row.redacts && !stdin {
		argv = append(argv, "--redaction-output-dir", filepath.Join(side.dir, "redacted"))
	}
	r := runCLI(t, bin, work, env, input, argv...)
	return paritySideResult{run: r, view: row.project(t, r, side, row.fixture)}
}

// writeParitySuppressionFiles generates the rules for cp.txt with the binary under test and writes them
// enabled (enabled.yaml) and enabled with a lapsed expiry (expired.yaml). Generated on --file; the
// --stdin rows name their input cp.txt too, so the same rules match there.
func writeParitySuppressionFiles(t *testing.T, bin, work string, env []string) {
	t.Helper()
	gen := filepath.Join(work, "gen.yaml")
	if r := runCLI(t, bin, work, env, "", "--file", "cp.txt", "--generate-suppressions", "--suppression-file", gen); r.rc != 0 {
		t.Fatalf("generating rules: rc %d\n%s", r.rc, r.stderr)
	}
	raw, err := os.ReadFile(gen) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	enabled := strings.ReplaceAll(string(raw), "enabled: false", "enabled: true")
	if enabled == string(raw) {
		t.Fatalf("the generated rules have no `enabled: false` to switch on:\n%s", raw)
	}
	writeFixture(t, filepath.Join(work, "enabled.yaml"), enabled)
	writeFixture(t, filepath.Join(work, "expired.yaml"),
		strings.ReplaceAll(enabled, "enabled: true\n", "enabled: true\n      expires_at: 2020-01-01T00:00:00Z\n"))
}

// disclosurePrefixes start the stderr lines that say something about what governed or limited the run,
// as opposed to progress prose ("Scan complete: …"), which the two paths word differently by design.
var disclosurePrefixes = []string{"Note:", "Warning:", "WARNING:", "Error:", "ferret-scan:", "Resolution:"}

func disclosures(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		for _, p := range disclosurePrefixes {
			if strings.HasPrefix(line, p) {
				out = append(out, line)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// reportView is the rc, the results and suppressed entries as canonical JSON, and the disclosure lines.
// The stats block is left out: --stdin does not write one yet, which is the part of #887 left open.
func reportView(t *testing.T, r cliRun, withDisclosures bool) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "rc=%d\n", r.rc)
	var doc map[string]any
	if strings.TrimSpace(r.stdout) == "" {
		b.WriteString("no report\n")
	} else if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		fmt.Fprintf(&b, "stdout is not JSON: %q\n", firstLine(r.stdout))
	} else {
		// A suppressed entry embeds the raw match, and --stdin stamps every match with source_kind
		// "virtual" (core.ScanContent), by design. Nothing else in the entry may differ.
		if sup, ok := doc["suppressed"].([]any); ok {
			for _, e := range sup {
				if entry, ok := e.(map[string]any); ok {
					if finding, ok := entry["finding"].(map[string]any); ok {
						delete(finding, "source_kind")
					}
				}
			}
		}
		for _, key := range []string{"results", "suppressed"} {
			v, _ := json.Marshal(doc[key])
			fmt.Fprintf(&b, "%s=%s\n", key, v)
		}
	}
	if withDisclosures {
		for _, l := range disclosures(r.stderr) {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func projectReport(t *testing.T, r cliRun, _ paritySide, _ string) string {
	return reportView(t, r, true)
}

// projectCutShort leaves the disclosure lines out: the two paths word the cut-short disclosure
// differently (--file's NOT FULLY EXAMINED report, --stdin's coverage WARNING). It still requires one.
func projectCutShort(t *testing.T, r cliRun, _ paritySide, _ string) string {
	view := reportView(t, r, false)
	if strings.Contains(r.stderr, "NOT FULLY EXAMINED") || strings.Contains(r.stderr, "coverage incomplete") {
		view += "cut short, disclosed\n"
	}
	return view
}

// projectFormat names the document's shape and compares its results, parsed as YAML, which reads JSON too.
func projectFormat(t *testing.T, r cliRun, _ paritySide, _ string) string {
	var doc map[string]any
	shape := "yaml"
	if json.Valid([]byte(r.stdout)) {
		shape = "json"
	}
	if err := yaml.Unmarshal([]byte(r.stdout), &doc); err != nil {
		return fmt.Sprintf("rc=%d unparseable %s: %v", r.rc, shape, err)
	}
	results, _ := json.Marshal(doc["results"])
	return fmt.Sprintf("rc=%d shape=%s results=%s", r.rc, shape, results)
}

func projectOutputFile(t *testing.T, r cliRun, s paritySide, _ string) string {
	raw, err := os.ReadFile(filepath.Join(s.dir, "out.json")) // #nosec G304 -- test temp dir
	if err != nil {
		return fmt.Sprintf("rc=%d no output file; stdout %d bytes", r.rc, len(r.stdout))
	}
	return reportView(t, cliRun{rc: r.rc, stdout: string(raw)}, false) + fmt.Sprintf("stdout %d bytes\n", len(strings.TrimSpace(r.stdout)))
}

// projectText compares the text report with the input's name spelled one way and --file's summary
// block (which --stdin does not write) removed.
func projectText(t *testing.T, r cliRun, _ paritySide, fixture string) string {
	var keep []string
	inSummary := false
	for _, line := range strings.Split(r.stdout, "\n") {
		switch {
		case strings.Contains(line, "Scan Summary"):
			inSummary = true
			continue
		case inSummary && strings.HasPrefix(line, "═"):
			inSummary = false
			continue
		case inSummary:
			continue
		}
		if i := strings.Index(line, "Match found in "); i >= 0 {
			rest := line[i+len("Match found in "):]
			if j := strings.Index(rest, " on line "); j >= 0 && filepath.Base(rest[:j]) == fixture {
				line = line[:i] + "Match found in " + fixture + rest[j:]
			}
		}
		keep = append(keep, line)
	}
	return fmt.Sprintf("rc=%d\n%s", r.rc, strings.TrimRight(strings.Join(keep, "\n"), "\n"))
}

// projectDebug: the --debug records both paths write before the scan, and the validators' own lines,
// which they print only when FERRET_DEBUG is exported.
func projectDebug(t *testing.T, r cliRun, _ paritySide, _ string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rc=%d\n", r.rc)
	for _, marker := range []string{
		"profile: no profile active",
		"config: CLI --disable-ip-types: [copyright]",
		"[DEBUG] Intellectual Property Validator: Disabled types: map[copyright:true]",
		"[INFO] Intellectual Property Validator: No internal URL patterns configured",
	} {
		fmt.Fprintf(&b, "%v %s\n", strings.Contains(r.stderr, marker), marker)
	}
	return b.String()
}

func projectPreprocess(t *testing.T, r cliRun, _ paritySide, fixture string) string {
	return fmt.Sprintf("rc=%d echoes the input=%v json=%v", r.rc,
		strings.Contains(r.stdout, strings.TrimSpace(parityFixtures[fixture])), json.Valid([]byte(r.stdout)))
}

// projectRedacted is the redacted bytes: --file's copy, --stdin's stdout.
func projectRedacted(t *testing.T, r cliRun, s paritySide, fixture string) string {
	if s.stdin {
		return fmt.Sprintf("rc=%d\n%s", r.rc, r.stdout)
	}
	return fmt.Sprintf("rc=%d\n%s", r.rc, redactedCopy(t, filepath.Join(s.dir, "redacted"), fixture))
}

// projectRules is the rules file the run wrote: per rule its hash, whether it is enabled, and whether it
// expires. Timestamps differ between runs and are left out.
func projectRules(t *testing.T, r cliRun, s paritySide, _ string) string {
	raw, err := os.ReadFile(filepath.Join(s.dir, "rules.yaml")) // #nosec G304 -- test temp dir
	if err != nil {
		return fmt.Sprintf("rc=%d no rules file\n%s", r.rc, strings.Join(disclosures(r.stderr), "\n"))
	}
	var doc struct {
		Rules []struct {
			Hash      string  `yaml:"hash"`
			Enabled   bool    `yaml:"enabled"`
			ExpiresAt *string `yaml:"expires_at"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the rules file does not parse: %v\n%s", err, raw)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "rc=%d rules=%d\n", r.rc, len(doc.Rules))
	for _, rule := range doc.Rules {
		fmt.Fprintf(&b, "%s enabled=%v expires=%v\n", rule.Hash, rule.Enabled, rule.ExpiresAt != nil)
	}
	return b.String()
}

// TestStdinAnswersBeforeDispatchFlagsAsFileDoes: --help, --version and --list-profiles print the same
// bytes with --stdin as without it, and read nothing from stdin. --list-profiles is the one that used to
// differ: it scanned the input instead (row 9 of #887).
func TestStdinAnswersBeforeDispatchFlagsAsFileDoes(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	for name, body := range parityFixtures {
		writeFixture(t, filepath.Join(work, name), body)
	}
	for _, args := range [][]string{
		{"--help"},
		{"--version"},
		{"--list-profiles", "--config", "nopat.yaml"},
		{"--web", "--output", "x.json"},
	} {
		plain := runCLI(t, bin, work, env, "", args...)
		piped := runCLI(t, bin, work, env, parityFixtures["cp.txt"], append([]string{"--stdin"}, args...)...)
		if plain.rc != piped.rc || plain.stdout != piped.stdout || plain.stderr != piped.stderr {
			t.Errorf("%v: --stdin changed the answer\nwithout: rc=%d stdout=%q stderr=%q\nwith:    rc=%d stdout=%q stderr=%q",
				args, plain.rc, plain.stdout, plain.stderr, piped.rc, piped.stdout, piped.stderr)
		}
	}
	r := runCLI(t, bin, work, env, parityFixtures["cp.txt"], "--stdin", "--list-profiles", "--config", "nopat.yaml")
	if !strings.Contains(r.stdout, "nopatent") || strings.Contains(r.stdout, "COPYRIGHT") {
		t.Errorf("--stdin --list-profiles: want the profile list and no findings, got rc=%d:\n%s", r.rc, r.stdout)
	}
}

// TestStdinRefusesOrNamesTheFlagsItCannotUse covers the refused and notice classes, and the control that
// only the FLAG draws the output-dir notice: a config file's redaction.output_dir is written for --file
// runs and must not make every gateway run print a line.
func TestStdinRefusesOrNamesTheFlagsItCannotUse(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	for name, body := range parityFixtures {
		writeFixture(t, filepath.Join(work, name), body)
	}
	in := parityFixtures["cp.txt"]

	for flagName, args := range map[string][]string{
		"recursive": {"--stdin", "--recursive"},
		"file":      {"--stdin", "--file", "cp.txt"},
	} {
		r := runCLI(t, bin, work, env, in, args...)
		if r.rc != 1 || !strings.Contains(r.stderr, "--"+flagName) || r.stdout != "" {
			t.Errorf("%v: want rc 1, an error naming --%s and nothing on stdout; got rc=%d stdout=%q stderr=%q",
				args, flagName, r.rc, r.stdout, r.stderr)
		}
	}

	auditLog := filepath.Join(t.TempDir(), "audit.json")
	outDir := filepath.Join(t.TempDir(), "redacted")
	for flagName, path := range map[string]string{"redaction-audit-log": auditLog, "redaction-output-dir": outDir} {
		r := runCLI(t, bin, work, env, in, "--stdin", "--enable-redaction", "--"+flagName, path)
		if r.rc != 0 || !strings.Contains(r.stderr, "Note: --"+flagName+" is not supported with --stdin") {
			t.Errorf("--stdin --%s: want rc 0 and a notice naming the flag; got rc=%d stderr=%q", flagName, r.rc, r.stderr)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("--stdin --%s wrote %s; it is not supported on this path", flagName, path)
		}
		if !strings.Contains(r.stdout, "Copyright") {
			t.Errorf("--stdin --%s: the redacted stream is missing from stdout: %q", flagName, r.stdout)
		}
	}

	writeFixture(t, filepath.Join(work, "outdir.yaml"), "redaction:\n  output_dir: "+filepath.ToSlash(outDir)+"\n")
	r := runCLI(t, bin, work, env, in, "--stdin", "--enable-redaction", "--config", "outdir.yaml")
	if strings.Contains(r.stderr, "redaction-output-dir") {
		t.Errorf("redaction.output_dir in a config file drew the flag's notice on every gateway run: %q", r.stderr)
	}
}
