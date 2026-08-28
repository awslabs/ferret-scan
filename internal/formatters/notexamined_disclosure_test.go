// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	csvfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	gitlabsast "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
)

// A file the tool could not read must never read as a file with no findings.
//
// Measured before this change, on a directory with one findings-bearing file and two
// unexaminable ones — the in-band signal on STDOUT was:
//
//	json         stats.files_not_examined = 2   PRESENT
//	yaml         filesnotexamined: 2            PRESENT
//	csv          NONE
//	junit        NONE
//	sarif        NONE
//	gitlab-sast  NONE
//
// The human report was produced for all of them, on STDERR, which pipelines
// discard. A CI job parsing stdout concluded those files were clean.
//
// These tests live in one file, across all four formats, because the property is
// cross-cutting: adding a format without the disclosure is the regression to catch,
// and a per-package test would not notice.
//
// NOTE the golden corpus CANNOT gate any of this: its harness constructs
// FormatterOptions without Stats or NotExamined, so every golden passes whether the
// feature works or not. All coverage is here.

// twoUnexamined is the standard fixture: one unreadable file, one whose body could
// not be extracted.
func twoUnexamined() []formatters.NotExaminedFile {
	return []formatters.NotExaminedFile{
		{Path: "/scan/noperm.txt", Cause: formatters.NotExaminedUnreadable, Detail: "permission denied"},
		{Path: "/scan/broken.docx", Cause: formatters.NotExaminedNoText, Detail: "no document body part"},
	}
}

func optsWith(files []formatters.NotExaminedFile) formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NotExamined:     files,
	}
}

func oneMatch() []detector.Match {
	return []detector.Match{{
		Text: "130-07-5728", Type: "SSN", Confidence: 100,
		Filename: "good.txt", LineNumber: 1, Validator: "ssn",
	}}
}

// TestZeroFindingsStillDisclosesNotExamined is the single most important test here.
//
// A scan that finds nothing AND could not read some files is the most dangerous
// report this tool can emit: an empty findings list that looks like a clean bill of
// health. It is also the path that returns EARLY in two of these formatters, so a
// disclosure attached next to the truncation logic (which runs only when there are
// matches) would vanish in exactly the case it exists for.
func TestZeroFindingsStillDisclosesNotExamined(t *testing.T) {
	opts := optsWith(twoUnexamined())

	for _, tc := range []struct {
		name string
		out  func() (string, error)
	}{
		{"gitlab-sast", func() (string, error) {
			return gitlabsast.NewFormatter().Format(nil, nil, opts)
		}},
		{"sarif", func() (string, error) {
			return sarif.NewFormatter().Format(nil, nil, opts)
		}},
		{"junit", func() (string, error) {
			return junit.NewFormatter().Format(nil, nil, opts)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.out()
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if !strings.Contains(out, "NOT EXAMINED") && !strings.Contains(out, "NOT FULLY EXAMINED") {
				t.Errorf("a scan with ZERO findings and 2 unexaminable files produced no "+
					"in-band disclosure. This output is indistinguishable from a clean "+
					"scan, which is the worst report this tool can emit:\n%s", out)
			}
		})
	}
}

// TestGitLabDisclosesViaScanMessages pins the slot and the schema constraints.
func TestGitLabDisclosesViaScanMessages(t *testing.T) {
	out, err := gitlabsast.NewFormatter().Format(oneMatch(), nil, optsWith(twoUnexamined()))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var doc struct {
		Scan struct {
			Status   string `json:"status"`
			Messages []struct {
				Level string `json:"level"`
				Value string `json:"value"`
			} `json:"messages"`
		} `json:"scan"`
		Vulnerabilities []map[string]any `json:"vulnerabilities"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(doc.Scan.Messages) == 0 {
		t.Fatal("scan.messages is empty; the disclosure is missing")
	}
	for i, m := range doc.Scan.Messages {
		// The v15.0.4 enum is [info, warn, fatal]. "warning" is SARIF's spelling and
		// is INVALID here — GitLab rejects an invalid report in full, losing every
		// finding, so this assertion protects the findings, not the disclosure.
		if m.Level != "warn" {
			t.Errorf("messages[%d].level = %q, want %q (the schema enum is info/warn/fatal; "+
				"%q is SARIF's spelling and invalid here)", i, m.Level, "warn", "warning")
		}
		// value has minLength 1 in the schema.
		if m.Value == "" {
			t.Errorf("messages[%d].value is empty, but the schema requires minLength 1", i)
		}
	}

	// The scan SUCCEEDED; only its coverage was partial. The enum is success|failure,
	// so "failure" would claim the analyzer broke.
	if doc.Scan.Status != "success" {
		t.Errorf("scan.status = %q, want \"success\": incomplete COVERAGE is not a failed "+
			"scan, and the exit code carries the verdict", doc.Scan.Status)
	}

	// Never fabricate findings to report a gap.
	if len(doc.Vulnerabilities) != 1 {
		t.Errorf("vulnerabilities has %d entries, want exactly the 1 real finding: "+
			"unexamined files must NOT be injected as synthetic vulnerabilities, which "+
			"would put fake findings on a security dashboard", len(doc.Vulnerabilities))
	}
}

// TestSARIFDisclosesViaToolExecutionNotifications pins the slot and its schema rules.
func TestSARIFDisclosesViaToolExecutionNotifications(t *testing.T) {
	out, err := sarif.NewFormatter().Format(oneMatch(), nil, optsWith(twoUnexamined()))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	run := doc["runs"].([]any)[0].(map[string]any)

	// run.additionalProperties is FALSE in SARIF 2.1.0, so a bespoke run-level key
	// is not merely unconventional — it invalidates the document, and GitLab rejects
	// an invalid SARIF report whole.
	for _, forbidden := range []string{"notExamined", "unscanned", "filesNotExamined"} {
		if _, present := run[forbidden]; present {
			t.Errorf("run has a non-standard key %q; run.additionalProperties is false, "+
				"so this makes the whole document schema-invalid", forbidden)
		}
	}

	invs, ok := run["invocations"].([]any)
	if !ok || len(invs) == 0 {
		t.Fatalf("run.invocations is missing; the disclosure has nowhere to live: %v", run["invocations"])
	}
	inv := invs[0].(map[string]any)

	// executionSuccessful is the object's only required member, and false tells
	// consumers the analysis failed — grounds to discard the results.
	if inv["executionSuccessful"] != true {
		t.Errorf("invocations[0].executionSuccessful = %v, want true: the run succeeded, "+
			"its coverage was partial, and false may make a consumer discard the results",
			inv["executionSuccessful"])
	}

	notes, ok := inv["toolExecutionNotifications"].([]any)
	if !ok || len(notes) == 0 {
		t.Fatal("toolExecutionNotifications is empty; the disclosure is missing")
	}
	for i, raw := range notes {
		n := raw.(map[string]any)
		// The SARIF enum is none/note/warning/error. "warn" is GitLab's spelling.
		if n["level"] != "warning" {
			t.Errorf("notification[%d].level = %v, want \"warning\" (the SARIF enum is "+
				"none/note/warning/error; \"warn\" is GitLab's and invalid here)", i, n["level"])
		}
		// notification.additionalProperties IS false here — the opposite of GitLab's
		// messages — so only the spec's own members may appear.
		for k := range n {
			switch k {
			case "descriptor", "level", "message", "locations", "properties",
				"associatedRule", "exception", "threadId", "timeUtc":
			default:
				t.Errorf("notification[%d] has key %q, which is not a spec member; "+
					"notification.additionalProperties is false", i, k)
			}
		}
	}

	// The descriptor must be declared exactly once: driver.notifications has
	// uniqueItems:true, so a per-file descriptor would duplicate and invalidate.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	descs, _ := driver["notifications"].([]any)
	if len(descs) != 1 {
		t.Errorf("driver.notifications has %d entries, want exactly 1 shared descriptor "+
			"(the array is uniqueItems:true)", len(descs))
	}

	// Unexamined files must not become results: GitHub renders results as
	// dismissable code-scanning alerts, so this would fabricate PII alerts.
	if got := len(run["results"].([]any)); got != 1 {
		t.Errorf("results has %d entries, want exactly the 1 real finding: an unexamined "+
			"file must never be reported as a finding", got)
	}
}

// TestJUnitDisclosureIsNonFailingByDefault is the CI-safety half.
func TestJUnitDisclosureIsNonFailingByDefault(t *testing.T) {
	out, err := junit.NewFormatter().Format(oneMatch(), nil, optsWith(twoUnexamined()))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var suites struct {
		Errors   int `xml:"errors,attr"`
		Failures int `xml:"failures,attr"`
		Tests    int `xml:"tests,attr"`
		Suites   []struct {
			Name    string `xml:"name,attr"`
			Errors  int    `xml:"errors,attr"`
			Skipped int    `xml:"skipped,attr"`
			Cases   []struct {
				Name    string `xml:"name,attr"`
				Skipped *struct {
					Message string `xml:"message,attr"`
				} `xml:"skipped"`
				Error *struct {
					Message string `xml:"message,attr"`
				} `xml:"error"`
				Failure *struct {
					Message string `xml:"message,attr"`
				} `xml:"failure"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal([]byte(out), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}

	// Without --fail-on-incomplete the report must not turn a green pipeline red.
	if suites.Errors != 0 {
		t.Errorf("testsuites errors=%d without --fail-on-incomplete. A disclosure must "+
			"not change a build's verdict unless asked: that is a behaviour change "+
			"dressed as a disclosure.", suites.Errors)
	}

	var found bool
	for _, s := range suites.Suites {
		if s.Name != "not-examined" {
			continue
		}
		found = true
		if len(s.Cases) != 2 {
			t.Errorf("not-examined suite has %d cases, want one PER FILE (2)", len(s.Cases))
		}
		for _, c := range s.Cases {
			if c.Skipped == nil {
				t.Errorf("case %q has no <skipped>; that is the standard non-failing element", c.Name)
			}
			if c.Failure != nil {
				t.Errorf("case %q reports <failure>: an unexamined file is not a PII "+
					"finding, and reporting it as one fabricates a finding", c.Name)
			}
		}
	}
	if !found {
		t.Error("no 'not-examined' suite. A separate suite keeps the security suite's " +
			"tests= attribute meaning 'files examined'.")
	}

	// The JUnit 10 XSD declares no `skipped` attribute on <testsuites> (only on
	// <testsuite>). Jenkins' xunit-plugin validates against that XSD and rejects the
	// WHOLE file, so this would lose the entire report.
	if strings.Contains(out, "<testsuites") {
		head := out[strings.Index(out, "<testsuites"):]
		head = head[:strings.Index(head, ">")]
		if strings.Contains(head, "skipped=") {
			t.Errorf("<testsuites> carries a skipped attribute: the JUnit 10 XSD does not "+
				"declare one there, and Jenkins rejects the whole file. Got: %s", head)
		}
	}
}

// TestJUnitDisclosureFailsUnderFailOnIncomplete is the flag half.
//
// When the operator declares incomplete coverage a failure, every channel must agree
// with the exit code rather than contradict it.
func TestJUnitDisclosureFailsUnderFailOnIncomplete(t *testing.T) {
	opts := optsWith(twoUnexamined())
	opts.FailOnIncomplete = true

	out, err := junit.NewFormatter().Format(oneMatch(), nil, opts)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(out, "<error ") {
		t.Error("--fail-on-incomplete produced no <error> element: the XML verdict would " +
			"say the run was fine while the process exits 3")
	}
	if strings.Contains(out, "<skipped ") {
		t.Error("--fail-on-incomplete still emits <skipped>; the valence must switch, not double up")
	}

	var suites struct {
		Errors int `xml:"errors,attr"`
	}
	if err := xml.Unmarshal([]byte(out), &suites); err != nil {
		t.Fatalf("invalid XML: %v", err)
	}
	if suites.Errors != 2 {
		t.Errorf("testsuites errors=%d, want 2: the roll-up must count the errored cases, "+
			"or a consumer reading only the top-level attributes sees a clean run", suites.Errors)
	}
}

// TestCompleteScanIsByteIdentical — the disclosure must be purely additive.
func TestCompleteScanIsByteIdentical(t *testing.T) {
	for _, tc := range []struct {
		name string
		fn   func(formatters.FormatterOptions) (string, error)
	}{
		{"gitlab-sast", func(o formatters.FormatterOptions) (string, error) {
			return gitlabsast.NewFormatter().Format(oneMatch(), nil, o)
		}},
		{"sarif", func(o formatters.FormatterOptions) (string, error) {
			return sarif.NewFormatter().Format(oneMatch(), nil, o)
		}},
		{"junit", func(o formatters.FormatterOptions) (string, error) {
			return junit.NewFormatter().Format(oneMatch(), nil, o)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// nil and empty must both mean "nothing to disclose".
			withNil, err := tc.fn(optsWith(nil))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			withEmpty, err := tc.fn(optsWith([]formatters.NotExaminedFile{}))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			// Compared with the scan timestamps normalised, because gitlab-sast embeds
			// start_time and end_time at ONE-SECOND resolution and this test formats twice.
			// Two consecutive calls that happen to straddle a second boundary differ in exactly
			// those two lines, which failed on ubuntu-latest CI against correct code. Proved by
			// forcing the straddle: the diff was
			//
			//	-   "start_time": "2026-08-28T08:22:10",
			//	+   "start_time": "2026-08-28T08:22:11",
			//	-   "end_time":   "2026-08-28T08:22:10",
			//	+   "end_time":   "2026-08-28T08:22:11",
			//
			// and nothing else. The formatter is right to carry a real timestamp — the GitLab
			// schema requires one — and this test's claim is that the NotExamined disclosure is
			// ADDITIVE, which a clock has no bearing on. So the clock is normalised rather than
			// the formatter changed.
			//
			// gitlab-sast is the only formatter that embeds a time field; json, yaml, csv, sarif
			// and junit emit none, so the other byte-comparison tests in this package are not
			// exposed to this.
			if normaliseScanTimes(withNil) != normaliseScanTimes(withEmpty) {
				t.Error("a nil and an empty NotExamined produced different output; both mean " +
					"every file was examined")
			}
			for _, marker := range []string{"NOT EXAMINED", "not-examined", "notifications", "messages"} {
				if strings.Contains(withNil, marker) {
					t.Errorf("a complete scan's output mentions %q; the disclosure must be "+
						"omitted entirely so existing consumers see no change", marker)
				}
			}
		})
	}
}

// TestCapIsDisclosedNotSilent — truncation must never hide the scale.
func TestCapIsDisclosedNotSilent(t *testing.T) {
	many := make([]formatters.NotExaminedFile, formatters.MaxNotExaminedEntries+25)
	for i := range many {
		many[i] = formatters.NotExaminedFile{
			Path:   "/scan/f.txt",
			Cause:  formatters.NotExaminedUnreadable,
			Detail: "permission denied",
		}
	}
	shown, total := formatters.CapNotExamined(many)
	if len(shown) != formatters.MaxNotExaminedEntries {
		t.Errorf("cap returned %d entries, want %d", len(shown), formatters.MaxNotExaminedEntries)
	}
	if total != len(many) {
		t.Errorf("total = %d, want %d: the cap must report the true total", total, len(many))
	}

	summary := formatters.NotExaminedSummary(len(shown), total)
	if !strings.Contains(summary, "omitted") {
		t.Errorf("the summary does not say anything was omitted, so a capped list reads as "+
			"complete: %q", summary)
	}

	out, err := gitlabsast.NewFormatter().Format(nil, nil, optsWith(many))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(out, "omitted") {
		t.Error("the emitted report does not disclose that the list was capped")
	}
}

// TestMessageIsNeverEmpty guards the minLength-1 schema constraint at its source.
func TestMessageIsNeverEmpty(t *testing.T) {
	// A zero-valued entry is the worst case: empty path, empty detail, zero cause.
	var zero formatters.NotExaminedFile
	if zero.Message() == "" {
		t.Error("a zero-valued NotExaminedFile renders an empty message, which violates " +
			"the GitLab schema's minLength:1 and would invalidate the whole report")
	}
	// The int zero value must be a real cause, not "unknown": that is why the enum
	// is an int rather than a string.
	if got := zero.Cause.String(); got == "unknown" || got == "" {
		t.Errorf("the zero cause renders %q; the int zero must be a valid cause", got)
	}
}

// TestCSVStaysOutOfBand records a deliberate LIMITATION, not an omission.
//
// csv is a fixed-grammar row format. Every in-band option corrupts something:
//
//   - a leading "# NOT EXAMINED" comment makes Go's encoding/csv fail the document
//     (wrong field count) and makes Python's DictReader adopt the comment as the
//     sole fieldname, so all real rows parse as garbage;
//   - a synthetic row with Type="NOT_EXAMINED" is indistinguishable from a finding
//     to every consumer, and inflates the row counts two committed tests assert.
//
// So csv keeps its disclosure on STDERR, exactly as PR #274 decided for the --limit
// note on the same grounds ("csv cannot carry metadata"). This test pins that
// decision so a future change cannot quietly corrupt the grammar in the name of
// completeness — and documents the residual gap: a --output x.csv artifact, read
// away from the terminal, cannot self-describe. Callers who need machine-readable
// coverage data should use json, yaml, sarif or gitlab-sast.
func TestCSVStaysOutOfBand(t *testing.T) {
	out, err := csvfmt.NewFormatter().Format(oneMatch(), nil, optsWith(twoUnexamined()))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	// Header + exactly one finding row. Nothing else.
	if len(lines) != 2 {
		t.Errorf("csv emitted %d lines, want 2 (header + 1 finding). Extra rows for "+
			"unexamined files are indistinguishable from findings:\n%s", len(lines), out)
	}
	if strings.HasPrefix(lines[0], "#") {
		t.Error("csv output starts with a # comment: encoding/csv fails such a document " +
			"and DictReader adopts the comment as the only fieldname")
	}
	for _, marker := range []string{"NOT EXAMINED", "NOT_EXAMINED", "not-examined"} {
		if strings.Contains(out, marker) {
			t.Errorf("csv output contains %q. The disclosure belongs on stderr for this "+
				"format; in band it corrupts the grammar or fakes a finding.", marker)
		}
	}
}

// scanTimeField matches the gitlab-sast scan timestamps, which are the only clock-derived values
// any formatter emits.
var scanTimeField = regexp.MustCompile(`"(start_time|end_time)":\s*"[^"]*"`)

// normaliseScanTimes replaces those timestamps with a placeholder so two formats of the same input
// can be compared for equality. See the note in TestCompleteScanIsByteIdentical.
func normaliseScanTimes(s string) string {
	return scanTimeField.ReplaceAllString(s, `"$1": "<normalised>"`)
}
