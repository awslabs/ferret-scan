// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// The scope block of a NARROWED run (#904), across every registered format.
//
// The golden corpus cannot gate this: its harness builds FormatterOptions without a scope, which is
// exactly why the corpus proves the other half, that a nil scope leaves every snapshot unchanged. The
// narrowed shape is pinned here instead.

// scopeChecks stands in for core.CheckNames. PASSPORT is the one check that does not run: it appears
// in no fixture finding, so finding the word in a report means the scope put it there.
var scopeChecks = []string{"EMAIL", "METADATA", "PASSPORT", "SSN"}

var everyBand = map[string]bool{"high": true, "medium": true, "low": true}

func narrowedScope(t *testing.T) *formatters.ScanScope {
	t.Helper()
	s := formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun:       []string{"EMAIL", "METADATA", "SSN"},
		AllChecks:       scopeChecks,
		ConfidenceLevel: everyBand,
		Config:          formatters.ScanConfigSource{Source: formatters.ConfigSourceBuiltin},
	})
	if s == nil {
		t.Fatal("a run that did not run PASSPORT got no scope")
	}
	return s
}

func scopeMatches() []detector.Match {
	return []detector.Match{{
		Text: "jane.example@example.com", LineNumber: 2, Type: "BUSINESS", Confidence: 53,
		Filename: "doc.txt", Validator: "email",
	}}
}

func scopeOpts(scope *formatters.ScanScope) formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: everyBand,
		NoColor:         true,
		Stats:           &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, TotalFindings: 1, Low: 1},
		Scan:            scope,
	}
}

// TestEveryFormatButCSVRendersANarrowedScope is the invariant over formatters.List(): a format added
// later that ignores FormatterOptions.Scan fails here, as a narrowed run would again read like a clean
// one. csv is the one documented residual: it is a table of findings with no slot for run metadata.
func TestEveryFormatButCSVRendersANarrowedScope(t *testing.T) {
	residual := map[string]bool{"csv": true}
	for _, name := range formatters.List() {
		for _, matches := range [][]detector.Match{scopeMatches(), nil} {
			base, err := formatters.Export(name, matches, nil, scopeOpts(nil))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			narrowed, err := formatters.Export(name, matches, nil, scopeOpts(narrowedScope(t)))
			if err != nil {
				t.Fatalf("%s narrowed: %v", name, err)
			}
			if strings.Contains(base, "PASSPORT") {
				t.Fatalf("%s: the fixture already mentions PASSPORT, so this test proves nothing:\n%s", name, base)
			}
			if residual[name] {
				if narrowed != base {
					t.Errorf("%s now renders the scope; document it in docs/COVERAGE_DISCLOSURE.md and remove it "+
						"from the residual list here", name)
				}
				continue
			}
			if !strings.Contains(narrowed, "PASSPORT") {
				t.Errorf("%s with %d match(es): a narrowed report does not name the check that did not run, "+
					"so it reads like a clean full scan:\n%s", name, len(matches), narrowed)
			}
		}
	}
}

func TestJSONAndYAMLCarryTheSameScanBlock(t *testing.T) {
	scope := narrowedScope(t)
	jsonOut, err := formatters.Export("json", scopeMatches(), nil, scopeOpts(scope))
	if err != nil {
		t.Fatal(err)
	}
	yamlOut, err := formatters.Export("yaml", scopeMatches(), nil, scopeOpts(scope))
	if err != nil {
		t.Fatal(err)
	}
	var j map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &j); err != nil {
		t.Fatal(err)
	}
	var y map[string]any
	if err := yaml.Unmarshal([]byte(yamlOut), &y); err != nil {
		t.Fatal(err)
	}
	js, ok := j["scan"].(map[string]any)
	if !ok {
		t.Fatalf("json has no scan object:\n%s", jsonOut)
	}
	ys, ok := y["scan"].(map[string]any)
	if !ok {
		t.Fatalf("yaml has no scan object:\n%s", yamlOut)
	}
	// One schema, two serialisations: the yaml keys must be the json keys.
	if !reflect.DeepEqual(sortedKeys(js), sortedKeys(ys)) {
		t.Errorf("json scan keys %v, yaml scan keys %v", sortedKeys(js), sortedKeys(ys))
	}
	if !reflect.DeepEqual(js["checks_not_run"], []any{"PASSPORT"}) {
		t.Errorf("checks_not_run = %v", js["checks_not_run"])
	}
	// Beside stats, ahead of results, so a reader sees it before the empty list.
	if si, ri := strings.Index(jsonOut, `"scan"`), strings.Index(jsonOut, `"results"`); si < 0 || si > ri {
		t.Errorf("scan is not ahead of results:\n%s", jsonOut)
	}

	plain, err := formatters.Export("json", scopeMatches(), nil, scopeOpts(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, `"scan"`) {
		t.Errorf("a nil scope rendered a scan key:\n%s", plain)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func TestTextScopeLineAppearsOnceOnEveryPath(t *testing.T) {
	scope := narrowedScope(t)
	want := "Scope: ran 3 of 4 checks (not run: PASSPORT)"

	withStats := scopeOpts(scope)
	withoutStats := scopeOpts(scope)
	withoutStats.Stats = nil
	withFooter := scopeOpts(scope)
	withFooter.NotExaminedFooter = "NOT FULLY EXAMINED: 1 of 2 files\n"
	suppressed := []detector.SuppressedMatch{{Match: scopeMatches()[0], SuppressedBy: "rule-1"}}

	cases := []struct {
		name       string
		matches    []detector.Match
		suppressed []detector.SuppressedMatch
		opts       formatters.FormatterOptions
	}{
		{"findings, summary block", scopeMatches(), nil, withStats},
		{"findings, no stats (--stdin text)", scopeMatches(), nil, withoutStats},
		{"no findings", nil, nil, withStats},
		{"no findings, not-examined footer", nil, nil, withFooter},
		{"suppressed only", nil, suppressed, withStats},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := formatters.Export("text", tc.matches, tc.suppressed, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(out, "Scope:"); n != 1 {
				t.Fatalf("%d Scope lines, want 1:\n%s", n, out)
			}
			if !strings.Contains(out, want) {
				t.Errorf("missing %q:\n%s", want, out)
			}
		})
	}

	t.Run("streamed to a writer", func(t *testing.T) {
		var b strings.Builder
		o := scopeOpts(scope)
		o.StreamWriter = &b
		if _, err := formatters.Export("text", scopeMatches(), nil, o); err != nil {
			t.Fatal(err)
		}
		if strings.Count(b.String(), want) != 1 {
			t.Errorf("the streamed report lost the scope line:\n%s", b.String())
		}
	})

	t.Run("never in pre-commit text", func(t *testing.T) {
		o := scopeOpts(scope)
		o.PrecommitMode = true
		o.PrecommitBlockMessage = "blocked"
		out, err := formatters.Export("text", scopeMatches(), nil, o)
		if err != nil {
			t.Fatal(err)
		}
		if out == "" || strings.Contains(out, "Scope:") {
			t.Errorf("pre-commit text must report the finding and carry no scope line:\n%q", out)
		}
	})

	t.Run("a hostile profile name is escaped", func(t *testing.T) {
		s := formatters.NewScanScope(formatters.ScopeInputs{
			ChecksRun: []string{"SSN"}, AllChecks: scopeChecks, ConfidenceLevel: everyBand,
			Profile: &formatters.ScanProfile{Name: "ci\x1b[2J", SelectedBy: formatters.ProfileSelectedByFlag},
		})
		out, err := formatters.Export("text", nil, nil, scopeOpts(s))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "\x1b") {
			t.Errorf("a config-supplied profile name reached the terminal raw: %q", out)
		}
	})
}

func TestJUnitScopePropertiesComeFirstInTheSecuritySuite(t *testing.T) {
	scope := formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun: []string{"EMAIL", "METADATA", "SSN"}, AllChecks: scopeChecks, ConfidenceLevel: map[string]bool{"high": true},
		DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}},
		Profile:                &formatters.ScanProfile{Name: "ci", SelectedBy: formatters.ProfileSelectedByFlag},
		Config:                 formatters.ScanConfigSource{Source: formatters.ConfigSourceWorkingDirectory, Name: "config.yaml"},
	})
	opts := scopeOpts(scope)
	opts.Stats.Suppressed = 2
	out, err := formatters.Export("junit", scopeMatches(), nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	type property struct {
		Name  string `xml:"name,attr"`
		Value string `xml:"value,attr"`
	}
	var doc struct {
		Suites []struct {
			Name       string     `xml:"name,attr"`
			Properties []property `xml:"properties>property"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not XML: %v\n%s", err, out)
	}
	// The XSD's sequence is properties, testcase*, system-out, system-err: properties must be the
	// first element inside the security-scan suite.
	if first := firstChildOf(t, out, "security-scan"); first != "properties" {
		t.Errorf("the first child of the security-scan suite is <%s>, want <properties>:\n%s", first, out)
	}
	var found bool
	for _, s := range doc.Suites {
		if s.Name != "security-scan" {
			if len(s.Properties) != 0 {
				t.Errorf("suite %s carries scope properties; only security-scan should", s.Name)
			}
			continue
		}
		found = true
		got := map[string]string{}
		for _, p := range s.Properties {
			got[p.Name] = p.Value
		}
		want := map[string]string{
			"ferret-scan.checks_run":                "EMAIL,METADATA,SSN",
			"ferret-scan.checks_not_run":            "PASSPORT",
			"ferret-scan.confidence_levels":         "high",
			"ferret-scan.profile":                   "ci",
			"ferret-scan.profile_selected_by":       "--profile",
			"ferret-scan.config_source":             "working-directory",
			"ferret-scan.config_name":               "config.yaml",
			"ferret-scan.suppression_rules_enabled": "0",
			"ferret-scan.suppressed":                "2",
			"ferret-scan.disabled_detection_types":  "INTELLECTUAL_PROPERTY:copyright",
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("property %s = %q, want %q", k, got[k], v)
			}
		}
		if _, ok := got["ferret-scan.commit"]; !ok {
			t.Error("no ferret-scan.commit property")
		}
	}
	if !found {
		t.Fatalf("no security-scan suite:\n%s", out)
	}

	plain, err := formatters.Export("junit", scopeMatches(), nil, scopeOpts(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, "<properties>") {
		t.Errorf("a nil scope rendered properties:\n%s", plain)
	}
}

// firstChildOf returns the local name of the first element inside the <testsuite name=suite>.
func firstChildOf(t *testing.T, doc, suite string) string {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	inSuite := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if inSuite {
			return start.Name.Local
		}
		if start.Name.Local == "testsuite" {
			for _, a := range start.Attr {
				if a.Name.Local == "name" && a.Value == suite {
					inSuite = true
				}
			}
		}
	}
}

func TestSARIFScopeIsOneNotificationAndMergedProperties(t *testing.T) {
	opts := scopeOpts(narrowedScope(t))
	opts.Limit = 1 // the truncation keys must survive the merge
	opts.Stats.DisabledDetectionTypes = map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}}
	matches := append(scopeMatches(), detector.Match{
		Text: "123-45-6789", LineNumber: 3, Type: "SSN", Confidence: 95, Filename: "doc.txt", Validator: "ssn",
	})
	out, err := formatters.Export("sarif", matches, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Version       string         `json:"version"`
					Properties    map[string]any `json:"properties"`
					Notifications []struct {
						ID string `json:"id"`
					} `json:"notifications"`
				} `json:"driver"`
			} `json:"tool"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				Notifications       []struct {
					Descriptor struct{ ID string }   `json:"descriptor"`
					Level      string                `json:"level"`
					Message    struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	run := doc.Runs[0]
	for _, k := range []string{"ferretScanChecksRun", "ferretScanChecksNotRun", "ferretScanConfidenceLevels",
		"ferretScanConfigSource", "ferretScanSuppressionRulesEnabled", "ferretScanSuppressed",
		"ferretScanTruncated", "ferretScanTotalFindings", "ferretScanResultsShown"} {
		if _, ok := run.Properties[k]; !ok {
			t.Errorf("run.properties lacks %s: %v", k, run.Properties)
		}
	}
	if _, ok := run.Tool.Driver.Properties["ferretScanCommit"]; !ok {
		t.Errorf("tool.driver.properties lacks ferretScanCommit: %v", run.Tool.Driver.Properties)
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Fatalf("want one successful invocation, got %+v", run.Invocations)
	}
	checksNotes := 0
	for _, n := range run.Invocations[0].Notifications {
		if n.Descriptor.ID != "ferret-scan/detection-disabled-by-config" || n.Level != "warning" {
			t.Errorf("notification %+v: want the detection-disabled-by-config descriptor at level warning", n)
		}
		if strings.Contains(n.Message.Text, "Checks not run") {
			checksNotes++
			if !strings.Contains(n.Message.Text, "PASSPORT") {
				t.Errorf("the checks notification does not name PASSPORT: %q", n.Message.Text)
			}
		}
	}
	if checksNotes != 1 {
		t.Errorf("%d checks-not-run notifications, want exactly 1", checksNotes)
	}
	if got := len(run.Tool.Driver.Notifications); got != 1 {
		t.Errorf("%d descriptors declared, want 1: tool.driver.notifications is uniqueItems", got)
	}

	// Narrowed by the confidence filter alone: the properties say so, and no notification claims a
	// check did not run.
	confOnly := formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun: scopeChecks, AllChecks: scopeChecks, ConfidenceLevel: map[string]bool{"high": true},
	})
	out, err = formatters.Export("sarif", scopeMatches(), nil, scopeOpts(confOnly))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Checks not run") || !strings.Contains(out, "ferretScanConfidenceLevels") {
		t.Errorf("confidence-only narrowing: want the properties and no checks notification:\n%s", out)
	}
}

func TestGitLabSASTScopeMessages(t *testing.T) {
	scope := formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun: []string{"EMAIL", "METADATA", "SSN"}, AllChecks: scopeChecks,
		ConfidenceLevel:        map[string]bool{"high": true, "medium": true},
		DisabledDetectionTypes: map[string][]string{"INTELLECTUAL_PROPERTY": {"copyright"}},
	})
	opts := scopeOpts(scope)
	opts.Stats.Suppressed = 3
	out, err := formatters.Export("gitlab-sast", nil, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Scan struct {
			Status   string `json:"status"`
			Messages []struct {
				Level string `json:"level"`
				Value string `json:"value"`
			} `json:"messages"`
		} `json:"scan"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Scan.Status != "success" {
		t.Errorf("status = %q; a narrowed scan succeeded", doc.Scan.Status)
	}
	want := []struct{ level, contains string }{
		{"warn", "checks not run for this scan (1 of 4): PASSPORT"},
		{"warn", "config disabled 1 INTELLECTUAL_PROPERTY detection sub-type(s) for this scan: copyright"},
		{"info", "the confidence filter hid low findings"},
		{"info", "3 finding(s) were suppressed"},
	}
	if len(doc.Scan.Messages) != len(want) {
		t.Fatalf("%d messages, want %d:\n%s", len(doc.Scan.Messages), len(want), out)
	}
	for i, w := range want {
		m := doc.Scan.Messages[i]
		if m.Level != w.level || !strings.Contains(m.Value, w.contains) {
			t.Errorf("message %d = {%s %q}, want level %s containing %q", i, m.Level, m.Value, w.level, w.contains)
		}
	}

	plain, err := formatters.Export("gitlab-sast", nil, nil, scopeOpts(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain, `"messages"`) {
		t.Errorf("a nil scope rendered messages:\n%s", plain)
	}
}
