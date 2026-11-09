// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	formatterShared "github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
)

// reExportSelect captures the export-format <select> in the embedded template, and reOptionValue each
// <option value="..."> inside it.
var (
	reExportSelect = regexp.MustCompile(`(?s)<select id="exportFormat"[^>]*>(.*?)</select>`)
	reOptionValue  = regexp.MustCompile(`<option value="([^"]*)"`)
)

// TestWebUI_ExportOptionsMatchFormatterRegistry holds the export menu to the formatter registry.
//
// /export serves any name in formatters.List(), but the <option> list the operator picks from is
// hand-written in template.html, so a new formatter would be reachable by API and invisible in the UI,
// and a removed one would stay in the menu and fail on click (#907). Same class as
// TestWebUI_ChecksMatchCoreRegistry, which found seven validators the check list had lost.
func TestWebUI_ExportOptionsMatchFormatterRegistry(t *testing.T) {
	m := reExportSelect.FindStringSubmatch(embeddedTemplate)
	if m == nil {
		t.Fatal(`no <select id="exportFormat"> in the embedded template: the extraction regex or the template broke`)
	}
	ui := map[string]bool{}
	for _, o := range reOptionValue.FindAllStringSubmatch(m[1], -1) {
		ui[o[1]] = true
	}
	if len(ui) == 0 {
		t.Fatal("the export <select> has no <option value=...>: the extraction regex or the template broke")
	}
	registry := formatters.List()
	for _, name := range registry {
		if !ui[name] {
			t.Errorf("format %q is in formatters.List() (so /export serves it) but missing from the export menu in template.html", name)
		}
		delete(ui, name)
	}
	for name := range ui {
		t.Errorf("the export menu offers %q, which is not in formatters.List(): /export answers it with an error", name)
	}
}

// exportFixtureCases are the golden cases whose findings make the fixed match set: plain text with
// five types across all three bands, and an Office document whose findings carry extractor metadata.
var exportFixtureCases = []string{"file_txt_mixed_pii", "file_docx_body_and_metadata"}

// exportFixture returns the fixed match set: the golden fixtures scanned through core.ScanFile with
// preprocessors on, then given what runFullCLIScan gives every web finding, the upload name as Filename
// and an explanation (the web annotates every finding; the CLI does with --explain).
func exportFixture(t *testing.T) []detector.Match {
	t.Helper()
	byName := map[string]goldencorpus.FileCase{}
	for _, fc := range goldencorpus.FileCases {
		byName[fc.Name] = fc
	}
	var all []detector.Match
	for _, name := range exportFixtureCases {
		fc, ok := byName[name]
		if !ok {
			t.Fatalf("golden file case %q is gone; pick another fixture for the export parity test", name)
		}
		native := filepath.Join(t.TempDir(), filepath.Base(fc.Filename))
		if err := os.WriteFile(native, fc.Content, 0o644); err != nil {
			t.Fatal(err)
		}
		res, err := core.ScanFile(core.ScanConfig{
			FilePath:            filepath.ToSlash(native),
			Checks:              fc.Checks,
			EnablePreprocessors: true,
			LogWriter:           io.Discard,
		})
		if err != nil {
			t.Fatalf("ScanFile(%s): %v", name, err)
		}
		for i := range res.Matches {
			res.Matches[i].Filename = filepath.Base(fc.Filename)
		}
		all = append(all, res.Matches...)
	}
	explain.Annotate(all, explain.NewSignalSynthesizer())
	all = goldencorpus.CanonicalSort(all)
	if len(all) < 5 {
		t.Fatalf("the export fixture produced %d findings; it needs several types to mean anything", len(all))
	}
	return all
}

// asScanResults renders matches the way handleScan delivers them to the browser (the JSON formatter
// with Verbose and ShowMatch on), which is what the UI posts back to /export.
func asScanResults(t *testing.T, ms []detector.Match) []formatterShared.JSONMatch {
	t.Helper()
	out, err := formatters.Export("json", ms, nil, formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		Verbose:         true,
		ShowMatch:       true,
	})
	if err != nil {
		t.Fatalf("render /scan JSON: %v", err)
	}
	var resp formatterShared.JSONResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("parse /scan JSON: %v", err)
	}
	return resp.Results
}

func postExport(t *testing.T, h http.Handler, format string, results []formatterShared.JSONMatch, showMatch, verbose bool) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"format": format, "results": results, "show_match": showMatch, "verbose": verbose})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/export", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/export %s: HTTP %d: %s", format, rec.Code, truncate(rec.Body.String(), 300))
	}
	return rec.Body.String()
}

// reJUnitTime matches the JUnit duration attributes, which measure the formatting call itself.
var reJUnitTime = regexp.MustCompile(`\btime="[0-9.]+"`)

// normalizeExportBody strips what differs between two renders of the same matches: the wall-clock
// timestamps goldencorpus.NormalizeOutput already replaces (gitlab-sast scan.start_time and
// scan.end_time, the INTELLECTUAL_PROPERTY reconstruction_timestamp metadata value), JUnit time="..."
// durations, and JSON key order (NormalizeOutput canonicalises json, sarif and gitlab-sast).
func normalizeExportBody(format, s string) string {
	return reJUnitTime.ReplaceAllString(goldencorpus.NormalizeOutput(format, s), `time="<DURATION>"`)
}

// exportLoss is one part of a finding that /export cannot reproduce. /export rebuilds every
// detector.Match from the JSON the browser posts back (handleExport), so whatever that JSON does not
// carry, or carries as another Go type, is missing from the exported report although the CLI's report
// of the same finding has it. Each loss strips exactly that part from the CLI side before the
// comparison, so every OTHER difference still fails; TestWebExportLossesAreLive fails for a loss that
// no longer changes any body.
type exportLoss struct {
	name   string
	reason string
	strip  func([]detector.Match) []detector.Match
}

var exportLosses = []exportLoss{
	{
		name: "explanation",
		reason: "the web annotates every finding (explain.Annotate in runFullCLIScan) and /scan sends the explanation as " +
			"JSONMatch.Explanation, but handleExport builds detector.Match from Text, LineNumber, Type, Confidence, Filename, " +
			"Validator, Metadata and three context strings only, so no exported json, yaml, sarif or gitlab-sast report holds " +
			"the explanation the CLI's --explain report holds (#907)",
		strip: func(ms []detector.Match) []detector.Match {
			for i := range ms {
				delete(ms[i].Metadata, explain.MetadataKey)
			}
			return ms
		},
	},
	{
		name: "context-keywords",
		reason: "JSONMatch carries full_line, before_text and after_text of detector.ContextInfo and nothing else, so " +
			"/export loses PositiveKeywords, NegativeKeywords and ConfidenceImpact; SARIF's verbose message renders " +
			"PositiveKeywords as 'Positive indicators' (#907)",
		strip: func(ms []detector.Match) []detector.Match {
			for i := range ms {
				ms[i].Context = detector.ContextInfo{
					BeforeText: ms[i].Context.BeforeText,
					AfterText:  ms[i].Context.AfterText,
					FullLine:   ms[i].Context.FullLine,
				}
			}
			return ms
		},
	},
	{
		name: "metadata-types",
		reason: "metadata crosses /scan and /export as JSON, so a typed value comes back as its JSON shape: " +
			"validation_checks leaves as map[string]bool and returns as map[string]any, and the text formatter's " +
			"type assertion then skips its verbose 'Validation results' block (#907)",
		// The explanation key is left typed: it is the "explanation" loss above, and a JSON round trip
		// here would remove it too (explain.FromMatch asserts the Explanation type), making the two
		// entries overlap so that neither could be shown to be live on its own.
		strip: func(ms []detector.Match) []detector.Match {
			for i := range ms {
				ex, hasEx := ms[i].Metadata[explain.MetadataKey]
				rest := map[string]any{}
				for k, v := range ms[i].Metadata {
					if k != explain.MetadataKey {
						rest[k] = v
					}
				}
				raw, err := json.Marshal(rest)
				if err != nil {
					continue
				}
				var back map[string]any
				if json.Unmarshal(raw, &back) != nil {
					continue
				}
				if hasEx {
					back[explain.MetadataKey] = ex
				}
				ms[i].Metadata = back
			}
			return ms
		},
	},
}

// exportOptions are the four combinations of the two switches /export takes.
var exportOptions = []struct{ showMatch, verbose bool }{{false, false}, {true, false}, {false, true}, {true, true}}

// cliExport renders the fixture with formatters.Export and handleExport's FormatterOptions, after the
// given losses are stripped from a private copy of the matches.
func cliExport(t *testing.T, format string, showMatch, verbose bool, losses []exportLoss) string {
	t.Helper()
	ms := exportFixture(t)
	for _, l := range losses {
		ms = l.strip(ms)
	}
	out, err := formatters.Export(format, ms, []detector.SuppressedMatch{}, formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		Verbose:         verbose,
		NoColor:         true,
		ShowMatch:       showMatch,
	})
	if err != nil {
		t.Fatalf("formatters.Export(%s): %v", format, err)
	}
	return normalizeExportBody(format, out)
}

func registryFormats(t *testing.T) []string {
	t.Helper()
	formats := formatters.List()
	sort.Strings(formats)
	if len(formats) < 7 {
		t.Fatalf("formatters.List() has %d entries; the registry imports broke", len(formats))
	}
	return formats
}

// TestWebExportMatchesCLIFormatter holds /export to the CLI's formatters. For every format the
// registry serves, the body /export returns for a fixed set of findings, posted the way the UI posts
// them (the /scan JSON it received), must equal formatters.Export for the same findings with the
// FormatterOptions handleExport uses: all three bands, NoColor, and the request's show_match and
// verbose, under each of their four combinations. Timestamps are normalised; the parts listed in
// exportLosses are stripped from the CLI side; nothing else.
func TestWebExportMatchesCLIFormatter(t *testing.T) {
	h := parityServer(t)
	posted := asScanResults(t, exportFixture(t))
	for _, format := range registryFormats(t) {
		for _, opt := range exportOptions {
			got := normalizeExportBody(format, postExport(t, h, format, posted, opt.showMatch, opt.verbose))
			want := cliExport(t, format, opt.showMatch, opt.verbose, exportLosses)
			if got != want {
				t.Errorf("/export %s (show_match=%v verbose=%v) differs from formatters.Export for the same %d findings:\n%s",
					format, opt.showMatch, opt.verbose, len(posted), firstDifference(want, got))
			}
		}
	}
	for _, l := range exportLosses {
		t.Logf("allowed loss %q: %s", l.name, l.reason)
	}
}

// TestWebExportLossesAreLive fails for an exportLosses entry that no longer changes any exported body,
// so a fixed loss cannot keep hiding a difference.
func TestWebExportLossesAreLive(t *testing.T) {
	h := parityServer(t)
	posted := asScanResults(t, exportFixture(t))
	for i, l := range exportLosses {
		others := append(append([]exportLoss{}, exportLosses[:i]...), exportLosses[i+1:]...)
		live := 0
		for _, format := range registryFormats(t) {
			for _, opt := range exportOptions {
				got := normalizeExportBody(format, postExport(t, h, format, posted, opt.showMatch, opt.verbose))
				if got != cliExport(t, format, opt.showMatch, opt.verbose, others) {
					live++
				}
			}
		}
		if live == 0 {
			t.Errorf("exportLosses %q changes no exported body any more; remove it", l.name)
			continue
		}
		t.Logf("loss %q changes %d of %d (format, switches) bodies", l.name, live, len(registryFormats(t))*len(exportOptions))
	}
}

// firstDifference shows the first differing line of two bodies, the CLI's first.
func firstDifference(cli, web string) string {
	a, b := strings.Split(cli, "\n"), strings.Split(web, "\n")
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y string
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return "  line " + strconv.Itoa(i+1) + "\n  cli:     " + truncate(x, 400) + "\n  /export: " + truncate(y, 400)
		}
	}
	return "  (no line differs; the bodies differ in length only)"
}
