// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/pkg/redact"

	csvfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	gitlabfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	jsonfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	junitfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	sariffmt "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	textfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	yamlfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// formatFresh renders matches using a FRESH formatter instance for the given
// format, rather than the process-global formatters.DefaultRegistry singleton.
//
// This matters because the SARIF formatter's RuleManager ACCUMULATES rules
// across Format() calls (formatter.go: ruleManager is never reset), so the
// singleton's output for one input depends on everything formatted before it in
// the same process — a real latent cross-invocation contamination bug (benign
// for the CLI, which formats once per process; noted for the v2 work). The
// golden net must be order-independent, so each case gets a clean formatter.
func formatFresh(t *testing.T, format string, matches []detector.Match, opts formatters.FormatterOptions) (string, error) {
	t.Helper()
	var f formatters.Formatter
	switch format {
	case "text":
		f = textfmt.NewFormatter()
	case "json":
		f = jsonfmt.NewFormatter()
	case "csv":
		f = csvfmt.NewFormatter()
	case "yaml":
		f = yamlfmt.NewFormatter()
	case "junit":
		f = junitfmt.NewFormatter()
	case "gitlab-sast":
		f = gitlabfmt.NewFormatter()
	case "sarif":
		f = sariffmt.NewFormatter()
	default:
		t.Fatalf("unknown format %q", format)
	}
	return f.Format(matches, nil, opts)
}

// goldenFormats is the set of output formats snapshotted per corpus case. This
// is the contract the v2 work must not break: the audit explicitly lists
// text/json/csv/yaml/junit/gitlab-sast (plus sarif) as core functions.
var goldenFormats = []string{"text", "json", "csv", "yaml", "junit", "gitlab-sast", "sarif"}

// goldenDir is where committed snapshots live.
const goldenDir = "testdata/golden"

// updateGolden reports whether to (re)write golden files instead of comparing.
// Set UPDATE_GOLDEN=1 to regenerate after an INTENTIONAL behavior change.
func updateGolden() bool { return os.Getenv("UPDATE_GOLDEN") == "1" }

// TestGoldenScanFormats locks the scan->format output for every corpus case
// across every supported format. This is the primary behavior-preservation gate
// for the v2 consolidation.
func TestGoldenScanFormats(t *testing.T) {
	for _, c := range Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			matches, _ := scanCase(t, c)
			matches = CanonicalSort(matches)

			opts := formatters.FormatterOptions{
				ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
				Verbose:         false,
				NoColor:         true, // deterministic: no ANSI escapes
				ShowMatch:       true, // lock the actual matched substrings
			}

			for _, format := range goldenFormats {
				out, err := formatFresh(t, format, matches, opts)
				if err != nil {
					t.Fatalf("format(%s) for case %q: %v", format, c.Name, err)
				}
				got := NormalizeOutput(format, out)
				checkGolden(t, c.Name+"."+formatExt(format), got)
			}
		})
	}
}

// TestGoldenRedact locks the redaction output (redacted text + findings summary)
// for every strategy. simple and format_preserving are deterministic and run
// through pkg/redact's Engine. synthetic draws its values at random, so it runs
// through core.RedactFile with a seeded scope (#886): RedactConfig.SyntheticScope
// is the seed hook, its type is internal, and only test code seeds a scope
// (TestNoProductionCodeSeedsTheSyntheticScope), so no flag, environment variable
// or config key can make a shipped run's synthetic values a function of a constant.
func TestGoldenRedact(t *testing.T) {
	strategies := []struct {
		name string
		s    redact.Strategy
	}{
		{"simple", redact.Simple},
		{"format_preserving", redact.FormatPreserving},
	}

	for _, c := range Cases {
		c := c
		// Redaction only makes sense where there is content to redact; the
		// negative case has no findings but is still a useful "redaction is a
		// no-op" lock.
		t.Run(c.Name, func(t *testing.T) {
			for _, st := range strategies {
				eng, err := redact.NewEngine(redact.EngineOptions{
					Checks:   c.Checks,
					Strategy: st.s,
				})
				if err != nil {
					t.Fatalf("NewEngine for case %q: %v", c.Name, err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				res, err := eng.Redact(ctx, redact.Request{Text: c.Input, Label: "<golden>"})
				cancel()
				_ = eng.Close()
				if err != nil {
					t.Fatalf("Redact for case %q (%s): %v", c.Name, st.name, err)
				}

				got := renderRedactSnapshot(res)
				checkGolden(t, c.Name+".redact_"+st.name+".txt", got)
			}

			got, copied, found := redactSyntheticSeeded(t, c, redactors.NewSeededSyntheticScope(goldenSyntheticSeed))
			switch _, withheld := syntheticSnapshotWithheld[c.Name]; {
			case found == 0:
				// Nothing to replace: the copy is the input, asserted here rather than
				// by a snapshot, so a decoy-only case needs no synthetic file.
				if copied != c.Input {
					t.Errorf("case %q: no findings, but the synthetic copy differs from the input", c.Name)
				}
			case !withheld:
				checkGolden(t, c.Name+".redact_synthetic.txt", got)
			}
		})
	}
}

// scanCase runs the real in-memory scan path for a corpus case.
func scanCase(t *testing.T, c Case) ([]detector.Match, *core.ScanResult) {
	t.Helper()
	res, err := core.ScanContent(c.Input, core.ContentScanConfig{
		VirtualPath: "<golden:" + c.Name + ">",
		Checks:      c.Checks,
	})
	if err != nil {
		t.Fatalf("ScanContent for case %q: %v", c.Name, err)
	}
	if res.Incomplete {
		// A golden corpus case must complete; an incomplete scan would make the
		// snapshot meaningless (partial, order-dependent results).
		t.Fatalf("case %q reported Incomplete scan (%s) — corpus cases must complete deterministically", c.Name, res.IncompleteReason)
	}
	return res.Matches, res
}

// goldenSyntheticSeed seeds the synthetic snapshots. Changing it moves every
// *.redact_synthetic.txt file.
var goldenSyntheticSeed = []byte("ferret-scan golden corpus #886")

// A case gets a *.redact_synthetic.txt snapshot when it has findings. A case with
// none is checked to copy its input unchanged, so a decoy-only case adds no file.
//
// syntheticSnapshotWithheld names the cases with findings whose synthetic copy is
// redacted and checked (TestGoldenRedact still runs them, and the repeatability
// test compares them) but not committed as a snapshot, with the reason.
var syntheticSnapshotWithheld = map[string]string{
	// The synthetic GITLAB_TOKEN replacement (glpat- plus 20 characters) is read as a
	// live GitLab token by GitHub push protection, which refuses the push.
	"secrets_provider_token_lengths": "GitHub push protection blocks the synthetic glpat- token",
}

// redactSyntheticSeeded writes the case to a file, redacts it with the synthetic
// strategy drawing from scope, and renders the copy and the findings the way
// renderRedactSnapshot does. The file path is temporary, so it is left out. It
// returns the snapshot, the copy and the number of findings.
func redactSyntheticSeeded(t *testing.T, c Case, scope redactors.SyntheticScope) (snapshot, copied string, found int) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in", c.Name+".txt")
	if err := os.MkdirAll(filepath.Dir(in), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in, []byte(c.Input), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := core.RedactFile(core.RedactConfig{
		FilePath:       in,
		OutputDir:      filepath.Join(dir, "out"),
		Strategy:       "synthetic",
		Checks:         c.Checks,
		SyntheticScope: scope,
	})
	if err != nil {
		t.Fatalf("RedactFile synthetic for case %q: %v", c.Name, err)
	}
	raw, err := os.ReadFile(res.RedactedFilePath)
	if err != nil {
		t.Fatalf("read synthetic copy for case %q: %v", c.Name, err)
	}

	var b strings.Builder
	b.WriteString("=== REDACTED ===\n")
	b.Write(raw)
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		b.WriteString("\n")
	}
	b.WriteString("=== FINDINGS (sorted) ===\n")
	ms := append([]detector.Match(nil), res.Matches...)
	sort.SliceStable(ms, func(i, j int) bool {
		a, z := ms[i], ms[j]
		if a.Type != z.Type {
			return a.Type < z.Type
		}
		if a.LineNumber != z.LineNumber {
			return a.LineNumber < z.LineNumber
		}
		if a.Confidence != z.Confidence {
			return a.Confidence < z.Confidence
		}
		return a.Text < z.Text
	})
	for _, m := range ms {
		b.WriteString("type=" + m.Type + " line=" + itoa(m.LineNumber) +
			" conf=" + formatConf(m.Confidence) + " match=" + m.Text + "\n")
	}
	return b.String(), string(raw), len(ms)
}

// A seeded synthetic run over every case, sharing one scope the way a multi-file
// CLI run shares its manager's, is byte-identical when repeated with the same seed
// and differs under another seed (#886): the seed decides the values, nothing else.
func TestGoldenRedactSyntheticSeededRunIsRepeatable(t *testing.T) {
	run := func(seed string) map[string]string {
		scope := redactors.NewSeededSyntheticScope([]byte(seed))
		out := make(map[string]string, len(Cases))
		for _, c := range Cases {
			out[c.Name], _, _ = redactSyntheticSeeded(t, c, scope)
		}
		return out
	}
	first, second, other := run("repeat-a"), run("repeat-a"), run("repeat-b")
	moved := 0
	for _, c := range Cases {
		if first[c.Name] != second[c.Name] {
			t.Errorf("case %q: two runs with one seed wrote different synthetic copies", c.Name)
		}
		if first[c.Name] != other[c.Name] {
			moved++
		}
	}
	if moved == 0 {
		t.Error("another seed changed no case: the seed does not reach the synthetic values")
	}
	t.Logf("%d cases, %d differ under another seed", len(Cases), moved)
}

// renderRedactSnapshot produces a stable, payload-bearing textual view of a
// redaction result: the redacted text plus a sorted findings summary. The
// matched substrings ARE included here (this is test fixture data for a local,
// never-pushed corpus) so a change in WHAT gets redacted is caught.
func renderRedactSnapshot(res *redact.Result) string {
	var b strings.Builder
	b.WriteString("=== REDACTED ===\n")
	b.WriteString(res.Redacted)
	if !strings.HasSuffix(res.Redacted, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("=== FINDINGS (sorted) ===\n")

	fwts := res.FindingsWithMatchText()
	// Sort findings into a deterministic order (type, line, confidence, text).
	sortFindings(fwts)
	for _, f := range fwts {
		suppressed := ""
		if f.SuppressedBy != "" {
			suppressed = " suppressed_by=" + f.SuppressedBy
		}
		b.WriteString(
			"type=" + f.Type +
				" line=" + itoa(f.LineNumber) +
				" conf=" + string(f.Confidence) +
				" match=" + f.MatchText +
				suppressed + "\n")
	}
	return b.String()
}

// checkGolden compares got against the committed golden file, or rewrites it
// when UPDATE_GOLDEN=1.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(goldenDir, name)

	if updateGolden() {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\n(hint: run `UPDATE_GOLDEN=1 go test ./internal/goldencorpus/...` to create it)", name, err)
	}
	// CRLF-tolerant comparison. The fixtures are LF-committed and pinned to LF
	// via .gitattributes, but defensively strip CR so a stray CRLF checkout (or a
	// formatter emitting CRLF on Windows) cannot make every snapshot diverge on
	// line endings alone. We lock detection/format content, not EOL bytes.
	if stripCR(string(want)) != stripCR(got) {
		t.Errorf("golden mismatch for %s\n--- want (committed) ---\n%s\n--- got (current) ---\n%s\n(if this change is intentional, regenerate with UPDATE_GOLDEN=1)",
			name, truncate(string(want)), truncate(got))
	}
}

// stripCR removes carriage returns so comparisons are line-ending-agnostic.
func stripCR(s string) string { return strings.ReplaceAll(s, "\r", "") }

// formatExt maps a format name to the golden file extension.
func formatExt(format string) string {
	switch format {
	case "json", "sarif":
		return format + ".json"
	case "gitlab-sast":
		return "gitlab-sast.json"
	case "junit":
		return "junit.xml"
	case "csv":
		return "csv"
	case "yaml":
		return "yaml"
	default:
		return "txt"
	}
}

// truncate keeps test failure output readable for large snapshots.
func truncate(s string) string {
	const max = 4000
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...(truncated for display; full diff in golden file)..."
}
