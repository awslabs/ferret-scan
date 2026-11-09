// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	formatterShared "github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
)

// webSurfaceAllowed lists the golden-corpus cases whose /scan result may differ from the corpus's own
// scan of the same bytes, in the idiom of checksUnsupportedInMemory. The key is a case name (every
// difference in that case) or "case/TYPE" (differences of that finding type in that case; the type
// "<incomplete>" stands for the scan's Incomplete flag). The value is the mechanism, verified in the
// code, and the issue that records it.
//
// An entry here is a recorded decision, so it must stay true: TestWebSurfaceAllowlistIsLive fails for
// an entry whose case no longer differs, which is what keeps this list from outliving the reason.
var webSurfaceAllowed = map[string]string{
	// The corpus scans these three with a 1ns PHONE budget (FileCase.ValidatorBudgets, the golden
	// corpus's stand-in for --validator-budget, #771), so its scan is Incomplete by construction. /scan
	// takes no budget: runFullCLIScan builds its core.ScanConfig without ValidatorBudgets, and
	// cmd/main.go validateWebModeFlags refuses --validator-budget with --web. The findings agree; only
	// the Incomplete flag differs. Whether the web should take a budget is in webUndecided.
	"file_docx_cut_short_without_metadata/<incomplete>": "web applies no validator budget: runFullCLIScan sets no ValidatorBudgets and validateWebModeFlags refuses --validator-budget, so the case's 1ns PHONE budget never cuts /scan short (#907)",
	"file_docx_cut_short_with_metadata/<incomplete>":    "web applies no validator budget: runFullCLIScan sets no ValidatorBudgets and validateWebModeFlags refuses --validator-budget, so the case's 1ns PHONE budget never cuts /scan short (#907)",
	"file_txt_cut_short_twin/<incomplete>":              "web applies no validator budget: runFullCLIScan sets no ValidatorBudgets and validateWebModeFlags refuses --validator-budget, so the case's 1ns PHONE budget never cuts /scan short (#907)",
}

// parityServer builds a WebServer the way `ferret-scan --web --config <empty file>` does: Start()
// strict-loads the operator's config and caches it, then installs the routes behind the security
// middleware. Nothing listens; requests are served in-process through httptest. The suppression file
// does not exist, so no rule in the developer's own config directory can suppress a finding here.
func parityServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := NewWebServerWithOptions("0", "127.0.0.1", cfgPath, filepath.Join(dir, "no-such-suppressions.yaml"), nil)
	cfg, err := config.LoadConfigStrict(cfgPath)
	if err != nil {
		t.Fatalf("load empty config: %v", err)
	}
	ws.cachedConfig = cfg
	if err := ws.setupRoutesWithValidation(); err != nil {
		t.Fatalf("setup routes: %v", err)
	}
	return ws.createSecureServer("0").Handler
}

// scanUpload posts one file to /scan the way the front-end's scanSingleFile does: the file under
// "files", the folder-relative path under "relative_path", and the scan options as form fields.
func scanUpload(t *testing.T, h http.Handler, relPath string, content []byte, checks []string) ScanResponse {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	w, err := mw.CreateFormFile("files", path.Base(relPath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	checkField := "all"
	if len(checks) > 0 {
		checkField = strings.Join(checks, ",")
	}
	for k, v := range map[string]string{
		"relative_path": relPath,
		"checks":        checkField,
		"confidence":    "all",
		"verbose":       "false",
		"recursive":     "false",
	} {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/scan", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/scan %s: HTTP %d: %s", relPath, rec.Code, truncate(rec.Body.String(), 300))
	}
	var resp ScanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("/scan %s: response is not JSON (%v): %s", relPath, err, truncate(rec.Body.String(), 300))
	}
	if !resp.Success {
		t.Fatalf("/scan %s: success=false: %s", relPath, resp.Error)
	}
	return resp
}

// parityFinding is the identity both sides are compared on: what was found, where, and how sure.
// The value is hashed so a failure message never prints a matched value.
type parityFinding struct {
	typ  string
	line int
	sha  string
	conf string
}

func (f parityFinding) String() string {
	return fmt.Sprintf("type=%s line=%d conf=%s value-sha256=%s", f.typ, f.line, f.conf, f.sha)
}

func valueHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func confKey(c float64) string { return strconv.FormatFloat(c, 'f', 2, 64) }

func sortFindings(fs []parityFinding) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].String() < fs[j].String() })
}

func fromMatches(ms []detector.Match) []parityFinding {
	out := make([]parityFinding, 0, len(ms))
	for _, m := range ms {
		out = append(out, parityFinding{typ: m.Type, line: m.LineNumber, sha: valueHash(m.Text), conf: confKey(m.Confidence)})
	}
	sortFindings(out)
	return out
}

func fromWeb(t *testing.T, caseName string, rs []formatterShared.JSONMatch) []parityFinding {
	t.Helper()
	out := make([]parityFinding, 0, len(rs))
	for _, r := range rs {
		// The band the web shows must be the band the CLI derives from the same score.
		if want := formatterShared.GetConfidenceLevel(r.Confidence); r.ConfidenceLevel != want {
			t.Errorf("case %s: /scan reports %s at confidence %s as %q; the CLI's band for that score is %q",
				caseName, r.Type, confKey(r.Confidence), r.ConfidenceLevel, want)
		}
		out = append(out, parityFinding{typ: r.Type, line: r.LineNumber, sha: valueHash(r.Text), conf: confKey(r.Confidence)})
	}
	sortFindings(out)
	return out
}

// bandStats is the stats block both sides are compared on. /scan carries no stats object (ScanResponse
// keeps only results and suppressed from the JSON formatter's output), so the counts are derived from
// the findings on both sides with the formatter's own band function.
type bandStats struct{ total, high, medium, low, suppressed int }

func statsOf(fs []parityFinding, suppressed int) bandStats {
	s := bandStats{total: len(fs), suppressed: suppressed}
	for _, f := range fs {
		c, _ := strconv.ParseFloat(f.conf, 64)
		switch formatterShared.GetConfidenceLevel(c) {
		case "HIGH":
			s.high++
		case "MEDIUM":
			s.medium++
		default:
			s.low++
		}
	}
	return s
}

// multisetDiff returns the findings only in a and only in b, duplicates counted.
func multisetDiff(a, b []parityFinding) (onlyA, onlyB []parityFinding) {
	count := map[parityFinding]int{}
	for _, f := range a {
		count[f]++
	}
	for _, f := range b {
		count[f]--
	}
	for f, n := range count {
		for ; n > 0; n-- {
			onlyA = append(onlyA, f)
		}
		for ; n < 0; n++ {
			onlyB = append(onlyB, f)
		}
	}
	sortFindings(onlyA)
	sortFindings(onlyB)
	return onlyA, onlyB
}

// surfaceCase is one golden-corpus input, scanned the way the corpus scans it and the way the web does.
type surfaceCase struct {
	name    string
	relPath string // where the front-end and scripts/surface-parity.sh put it
	content []byte
	checks  []string
	corpus  func(t *testing.T) *core.ScanResult
}

// surfaceCases mirrors the two corpus scan paths exactly: internal/goldencorpus golden_test.go
// scanCase (core.ScanContent, virtual path "<golden:NAME>", the case's checks) and
// golden_file_test.go TestGoldenFileScanFormats (core.ScanFile on the fixture, the case's checks,
// preprocessors and budgets). The relPath is TestDumpInputs's layout, so a difference found here can
// be reproduced by the surface-parity script on the same path.
func surfaceCases() []surfaceCase {
	var out []surfaceCase
	for _, c := range goldencorpus.Cases {
		c := c
		out = append(out, surfaceCase{
			name: c.Name, relPath: "content/" + c.Name + ".txt", content: []byte(c.Input), checks: c.Checks,
			corpus: func(t *testing.T) *core.ScanResult {
				t.Helper()
				res, err := core.ScanContent(c.Input, core.ContentScanConfig{
					VirtualPath: "<golden:" + c.Name + ">",
					Checks:      c.Checks,
					LogWriter:   io.Discard,
				})
				if err != nil {
					t.Fatalf("ScanContent: %v", err)
				}
				return res
			},
		})
	}
	for _, fc := range goldencorpus.FileCases {
		fc := fc
		out = append(out, surfaceCase{
			name: fc.Name, relPath: "file/" + fc.Name + "/" + filepath.ToSlash(fc.Filename), content: fc.Content, checks: fc.Checks,
			corpus: func(t *testing.T) *core.ScanResult {
				t.Helper()
				native := filepath.Join(t.TempDir(), fc.Filename)
				if err := os.MkdirAll(filepath.Dir(native), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(native, fc.Content, 0o644); err != nil {
					t.Fatal(err)
				}
				res, err := core.ScanFile(core.ScanConfig{
					FilePath:            filepath.ToSlash(native),
					Checks:              fc.Checks,
					EnablePreprocessors: fc.EnablePreprocessors,
					ValidatorBudgets:    fc.ValidatorBudgets,
					LogWriter:           io.Discard,
				})
				if err != nil {
					t.Fatalf("ScanFile: %v", err)
				}
				return res
			},
		})
	}
	return out
}

// caseDifferences scans one case both ways and returns every difference, keyed by finding type
// ("<incomplete>" and "<stats>" for the scan-level fields), as human-readable lines.
func caseDifferences(t *testing.T, h http.Handler, c surfaceCase) map[string][]string {
	t.Helper()
	res := c.corpus(t)
	resp := scanUpload(t, h, c.relPath, c.content, c.checks)

	corpus := fromMatches(res.Matches)
	web := fromWeb(t, c.name, resp.Results)
	diffs := map[string][]string{}
	onlyCorpus, onlyWeb := multisetDiff(corpus, web)
	for _, f := range onlyCorpus {
		diffs[f.typ] = append(diffs[f.typ], "only in the corpus scan: "+f.String())
	}
	for _, f := range onlyWeb {
		diffs[f.typ] = append(diffs[f.typ], "only in the web /scan:   "+f.String())
	}
	if res.Incomplete != resp.Incomplete {
		diffs["<incomplete>"] = append(diffs["<incomplete>"], fmt.Sprintf(
			"incomplete: corpus=%v (%s) web=%v (%s)", res.Incomplete, res.IncompleteReason, resp.Incomplete, resp.IncompleteReason))
	}
	if a, b := statsOf(corpus, res.SuppressedCount), statsOf(web, len(resp.Suppressed)); a != b {
		diffs["<stats>"] = append(diffs["<stats>"], fmt.Sprintf("stats: corpus=%+v web=%+v", a, b))
	}
	return diffs
}

func allowedReason(caseName, typ string) (string, bool) {
	if r, ok := webSurfaceAllowed[caseName+"/"+typ]; ok {
		return r, true
	}
	r, ok := webSurfaceAllowed[caseName]
	return r, ok
}

// TestWebScanMatchesCorpusScan is the web half of the CLI's contract: every golden-corpus input,
// uploaded to /scan with the case's checks at every confidence level, must yield the findings the
// corpus's own scan of the same bytes yields, compared as (type, line, sha256 of the value, confidence)
// plus the band counts and the Incomplete flag. A difference fails naming the case, the type and both
// sides, unless webSurfaceAllowed records why it is expected.
//
// Before this test the only standing parity check was TestWebUI_ChecksMatchCoreRegistry, which
// compares check NAMES; nothing asserted that a file posted to /scan is scanned like the same file on
// the command line (#907).
func TestWebScanMatchesCorpusScan(t *testing.T) {
	h := parityServer(t)
	cases := surfaceCases()
	if len(cases) < 50 {
		t.Fatalf("only %d golden cases found; the corpus import broke", len(cases))
	}
	compared, allowed := 0, 0
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			diffs := caseDifferences(t, h, c)
			types := make([]string, 0, len(diffs))
			for typ := range diffs {
				types = append(types, typ)
			}
			sort.Strings(types)
			for _, typ := range types {
				if reason, ok := allowedReason(c.name, typ); ok {
					allowed++
					t.Logf("allowed (%s): %s", reason, strings.Join(diffs[typ], "; "))
					continue
				}
				t.Errorf("case %s, type %s: the web /scan and the corpus scan disagree:\n  %s\n"+
					"Fix the divergence, or record the mechanism in webSurfaceAllowed with an issue.",
					c.name, typ, strings.Join(diffs[typ], "\n  "))
			}
			compared++
		})
	}
	t.Logf("compared %d golden cases through /scan; %d allowlisted difference group(s)", compared, allowed)
}

// TestWebSurfaceAllowlistIsLive fails for a webSurfaceAllowed entry whose case no longer differs, or
// that names no case, so a fixed divergence cannot keep an exemption alive.
func TestWebSurfaceAllowlistIsLive(t *testing.T) {
	h := parityServer(t)
	byName := map[string]surfaceCase{}
	for _, c := range surfaceCases() {
		byName[c.name] = c
	}
	for key, reason := range webSurfaceAllowed {
		if !strings.Contains(reason, "#") {
			t.Errorf("webSurfaceAllowed[%q] names no issue: %q", key, reason)
		}
		name, typ, _ := strings.Cut(key, "/")
		c, ok := byName[name]
		if !ok {
			t.Errorf("webSurfaceAllowed names %q, which is not a golden-corpus case", key)
			continue
		}
		diffs := caseDifferences(t, h, c)
		if typ != "" && len(diffs[typ]) == 0 {
			t.Errorf("webSurfaceAllowed[%q]: no %s difference any more; remove the entry", key, typ)
		}
		if typ == "" && len(diffs) == 0 {
			t.Errorf("webSurfaceAllowed[%q]: the case no longer differs; remove the entry", key)
		}
	}
}
