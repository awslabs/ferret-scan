// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Command spreport reads the raw outputs scripts/surface-parity.sh collected from the four surfaces
// (host CLI, host --web, container CLI, container --web), normalises them, diffs them, checks the
// redacted copies the container wrote, and prints the report. It exits 1 on any unexplained
// difference, any surviving value or any failed runtime fact, and 2 when it cannot read its input.
//
// It is a separate program rather than more shell because the comparisons need JSON parsing,
// SHA-256, zip reading and canonical ordering, which bash with jq cannot all do. The shell script
// owns the surfaces (building, starting, uploading, copying); this program owns the verdict.
//
// Usage (the script is the only intended caller):
//
//	spreport -work DIR -surfaces cli,web,container-cli,container-web -allowlist FILE
//
// The layout under DIR is documented in scripts/surface-parity.sh.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// containerRoot is where the script copies every input set inside the container.
const containerRoot = "/home/ferret/in"

// ratioWarn is the container/host wall-clock ratio above which the report prints a WARNING.
const ratioWarn = 2.0

// minValueBytes is the shortest matched value the redaction check looks for. A value of one to three
// bytes occurs by chance in almost any document, so finding it in a redacted copy says nothing about
// whether the redactor removed THAT occurrence. Values skipped this way are counted in the report.
const minValueBytes = 4

var surfaceNames = []string{"cli", "web", "container-cli", "container-web"}

type set struct {
	name      string
	hostRoot  string
	aggregate bool // private: counts and timings only, never a name or a value
}

type report struct {
	work      string
	surfaces  map[string]bool
	allowlist []allowEntry
	failures  []string
	warnings  []string
	out       *bufio.Writer
}

type allowEntry struct {
	pair    string
	pattern *regexp.Regexp
	raw     string
	reason  string
	used    int
}

func main() {
	work := flag.String("work", "", "work directory the script wrote")
	surfaces := flag.String("surfaces", strings.Join(surfaceNames, ","), "surfaces that ran")
	allow := flag.String("allowlist", "", "allowlist TSV: pair<TAB>pattern<TAB>reason")
	flag.Parse()
	if *work == "" {
		fmt.Fprintln(os.Stderr, "spreport: -work is required")
		os.Exit(2)
	}

	r := &report{work: *work, surfaces: map[string]bool{}, out: bufio.NewWriter(os.Stdout)}
	defer r.out.Flush()
	for _, s := range strings.Split(*surfaces, ",") {
		if s = strings.TrimSpace(s); s != "" {
			r.surfaces[s] = true
		}
	}
	if *allow != "" {
		entries, err := loadAllowlist(*allow)
		if err != nil {
			fmt.Fprintf(os.Stderr, "spreport: %v\n", err)
			os.Exit(2)
		}
		r.allowlist = entries
	}

	sets, err := loadSets(filepath.Join(*work, "sets.tsv"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "spreport: %v\n", err)
		os.Exit(2)
	}

	r.facts()
	for _, s := range sets {
		r.set(s)
	}
	r.printAllowlist()

	r.printf("\n=== verdict ===\n")
	for _, w := range r.warnings {
		r.printf("WARNING: %s\n", w)
	}
	if len(r.failures) == 0 {
		r.printf("PASS: every comparison held (%d warning(s))\n", len(r.warnings))
		r.out.Flush()
		return
	}
	for _, f := range r.failures {
		r.printf("FAIL: %s\n", f)
	}
	r.out.Flush()
	os.Exit(1)
}

func (r *report) printf(format string, a ...any) { fmt.Fprintf(r.out, format, a...) }
func (r *report) fail(format string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, a...))
}
func (r *report) warn(format string, a ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, a...))
}
func (r *report) has(s string) bool { return r.surfaces[s] }

// ---------------------------------------------------------------------------------------------
// inputs

func loadSets(path string) ([]set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []set
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("%s: malformed line %q", path, line)
		}
		out = append(out, set{name: f[0], hostRoot: f[1], aggregate: f[2] == "1"})
	}
	return out, nil
}

// loadAllowlist reads pair<TAB>pattern<TAB>reason lines. Blank lines and # comments are skipped. The
// reason is mandatory: an entry is a recorded decision, and a bare pattern records nothing.
func loadAllowlist(path string) ([]allowEntry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist %s: %w", path, err)
	}
	var out []allowEntry
	for i, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.SplitN(line, "\t", 3)
		if len(f) != 3 || strings.TrimSpace(f[2]) == "" {
			return nil, fmt.Errorf("%s:%d: want pair<TAB>pattern<TAB>reason, got %q", path, i+1, line)
		}
		if f[0] != "cli-web" {
			return nil, fmt.Errorf("%s:%d: pair %q: only cli-web differences are allowlistable; "+
				"cli==container-cli and web==container-web must hold exactly", path, i+1, f[0])
		}
		if !regexp.MustCompile(`#[0-9]+`).MatchString(f[2]) {
			return nil, fmt.Errorf("%s:%d: the reason must name an issue (#NNN): %q", path, i+1, f[2])
		}
		re, err := regexp.Compile(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: pattern %q: %v", path, i+1, f[1], err)
		}
		out = append(out, allowEntry{pair: f[0], pattern: re, raw: f[1], reason: f[2]})
	}
	return out, nil
}

// readMeta reads the key=value lines the script writes next to each surface's output.
func readMeta(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// fileIndex maps the script's NNNNN upload index to the input's path relative to the set root.
func fileIndex(path string) ([][2]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][2]string
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		id, rel, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("%s: malformed line %q", path, line)
		}
		out = append(out, [2]string{id, rel})
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// normalisation

// decode parses JSON keeping numbers as written, so re-encoding cannot change a confidence's
// spelling.
func decode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// canonical encodes v with sorted object keys (encoding/json sorts map keys) and no HTML escaping.
func canonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return buf.Bytes()
}

// rootRewriter returns a function stripping every spelling of the set's root from a string, so a
// path is the same on every surface: the host CLI reports paths under the set directory, the
// container CLI under /home/ferret/in, and the web surfaces the relative path the script uploaded.
func rootRewriter(roots ...string) func(string) string {
	var forms []string
	for _, r := range roots {
		r = strings.TrimSuffix(filepath.ToSlash(r), "/")
		if r == "" {
			continue
		}
		forms = append(forms, r+"/", strings.TrimPrefix(r, "/")+"/")
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return func(s string) string {
		for _, f := range forms {
			s = strings.ReplaceAll(s, f, "")
		}
		return s
	}
}

// clockKeys are metadata keys whose value is the wall clock at scan time, so two runs of one binary
// differ there and nowhere else: INTELLECTUAL_PROPERTY stamps reconstruction_timestamp, a Unix
// epoch, when it rebuilds a legal notice. The golden corpus normalises the same key.
var clockKeys = map[string]bool{"reconstruction_timestamp": true}

// dropClocks replaces every clockKeys value in a decoded JSON value with a sentinel.
func dropClocks(v any) any {
	switch t := v.(type) {
	case []any:
		for i := range t {
			t[i] = dropClocks(t[i])
		}
	case map[string]any:
		for k, x := range t {
			if clockKeys[k] {
				t[k] = "<TIMESTAMP>"
				continue
			}
			t[k] = dropClocks(x)
		}
	}
	return v
}

// walkStrings applies fn to every string in a decoded JSON value.
func walkStrings(v any, fn func(string) string) any {
	switch t := v.(type) {
	case string:
		return fn(t)
	case []any:
		for i := range t {
			t[i] = walkStrings(t[i], fn)
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = walkStrings(x, fn)
		}
		return t
	}
	return v
}

func str(m map[string]any, k string) string {
	if s, ok := m[k].(string); ok {
		return s
	}
	if n, ok := m[k].(json.Number); ok {
		return n.String()
	}
	return ""
}

// sortResults orders findings by (filename, line, type, text, confidence), the order every surface
// can reproduce. The CLI emits them in goroutine-completion order within a confidence band, so the
// raw order is not an output contract and comparing it would only measure the scheduler.
func sortResults(results []any) {
	key := func(x any) string {
		m, _ := x.(map[string]any)
		line, _ := strconv.Atoi(str(m, "line_number"))
		return fmt.Sprintf("%s\x00%09d\x00%s\x00%s\x00%s", str(m, "filename"), line, str(m, "type"), str(m, "text"), str(m, "confidence"))
	}
	sort.SliceStable(results, func(i, j int) bool { return key(results[i]) < key(results[j]) })
}

// normalizeCLI rewrites one CLI JSON report into its comparable form. Changed, and only these:
// every string loses the set root (paths become relative), stats.duration_seconds is dropped and
// clockKeys values are replaced (wall clock), and results are put in sortResults order.
func normalizeCLI(raw []byte, roots ...string) ([]byte, map[string]any, error) {
	v, err := decode(raw)
	if err != nil {
		return nil, nil, err
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("CLI JSON is not an object")
	}
	walkStrings(doc, rootRewriter(roots...))
	dropClocks(doc)
	if st, ok := doc["stats"].(map[string]any); ok {
		delete(st, "duration_seconds")
	}
	if res, ok := doc["results"].([]any); ok {
		sortResults(res)
	}
	return canonical(doc), doc, nil
}

// normalizeWeb merges one surface's per-file /scan responses into a single document keyed by the
// input's relative path. Only clockKeys values are replaced: /scan carries no other clock or version
// field.
func normalizeWeb(dir string, files [][2]string) ([]byte, map[string]any, error) {
	doc := map[string]any{}
	for _, f := range files {
		raw, err := os.ReadFile(filepath.Join(dir, f[0]+".json"))
		if err != nil {
			doc[f[1]] = map[string]any{"missing_response": true}
			continue
		}
		v, err := decode(raw)
		if err != nil {
			doc[f[1]] = map[string]any{"unparseable_response": string(raw)}
			continue
		}
		dropClocks(v)
		if m, ok := v.(map[string]any); ok {
			if res, ok := m["results"].([]any); ok {
				sortResults(res)
			}
		}
		doc[f[1]] = v
	}
	return canonical(doc), doc, nil
}

var (
	isoTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`)
	junitTime    = regexp.MustCompile(`\btime="[0-9.]+"`)
	reconStamp   = regexp.MustCompile(`(reconstruction_timestamp[^0-9]*)\d+`)
)

// normalizeExport removes the clock from an /export body: ISO-8601 times (gitlab-sast scan
// start_time and end_time), JUnit time="…" attributes, and the INTELLECTUAL_PROPERTY
// reconstruction_timestamp metadata value. JSON bodies are re-encoded with sorted keys.
func normalizeExport(format string, raw []byte) []byte {
	s := isoTimestamp.ReplaceAllString(string(raw), "<TIMESTAMP>")
	s = junitTime.ReplaceAllString(s, `time="<DURATION>"`)
	s = reconStamp.ReplaceAllString(s, "${1}<TIMESTAMP>")
	switch format {
	case "json", "sarif", "gitlab-sast":
		if v, err := decode([]byte(s)); err == nil {
			return canonical(v)
		}
	}
	return []byte(s)
}

// ---------------------------------------------------------------------------------------------
// findings

type finding struct {
	rel, typ, line, conf, sha string
}

func (f finding) key() string {
	return f.rel + "\t" + f.typ + "\t" + f.line + "\t" + f.conf + "\t" + f.sha
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

func confString(m map[string]any) string {
	c, err := strconv.ParseFloat(str(m, "confidence"), 64)
	if err != nil {
		return str(m, "confidence")
	}
	return strconv.FormatFloat(c, 'f', 2, 64)
}

func findingsOf(results []any, relOf func(map[string]any) string) []finding {
	var out []finding
	for _, x := range results {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, finding{rel: relOf(m), typ: str(m, "type"), line: str(m, "line_number"), conf: confString(m), sha: shortHash(str(m, "text"))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func cliFindings(doc map[string]any) []finding {
	res, _ := doc["results"].([]any)
	return findingsOf(res, func(m map[string]any) string { return str(m, "filename") })
}

func webFindings(doc map[string]any) []finding {
	var out []finding
	for rel, v := range doc {
		m, _ := v.(map[string]any)
		res, _ := m["results"].([]any)
		out = append(out, findingsOf(res, func(map[string]any) string { return rel })...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// multisetDiff returns the keys only in a and only in b, counting duplicates.
func multisetDiff(a, b []finding) (onlyA, onlyB []finding) {
	count := map[string]int{}
	byKey := map[string]finding{}
	for _, f := range a {
		count[f.key()]++
		byKey[f.key()] = f
	}
	for _, f := range b {
		count[f.key()]--
		byKey[f.key()] = f
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for n := count[k]; n > 0; n-- {
			onlyA = append(onlyA, byKey[k])
		}
		for n := count[k]; n < 0; n++ {
			onlyB = append(onlyB, byKey[k])
		}
	}
	return onlyA, onlyB
}

func bandCounts(fs []finding) (high, medium, low int) {
	for _, f := range fs {
		c, _ := strconv.ParseFloat(f.conf, 64)
		switch {
		case c >= 90:
			high++
		case c >= 60:
			medium++
		default:
			low++
		}
	}
	return
}

func typeCounts(fs []finding) string {
	m := map[string]int{}
	for _, f := range fs {
		m[f.typ]++
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------------------------
// per-set comparison

type surfaceRun struct {
	ran      bool
	findings []finding
	files    int
	notExam  int
	exit     string
	seconds  float64
	perFile  []float64
	failures int // non-200 /scan responses
}

func (r *report) set(s set) {
	base := filepath.Join(r.work, "raw", s.name)
	r.printf("\n=== input set: %s%s ===\n", s.name, map[bool]string{true: " (aggregates only)", false: ""}[s.aggregate])

	files, err := fileIndex(filepath.Join(base, "files.tsv"))
	if err != nil {
		r.fail("%s: cannot read the file index: %v", s.name, err)
		return
	}
	runs := map[string]*surfaceRun{}
	docs := map[string][]byte{}
	parsed := map[string]map[string]any{}

	for _, sf := range []string{"cli", "container-cli"} {
		if !r.has(sf) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(base, sf+".json"))
		meta := readMeta(filepath.Join(base, sf+".meta"))
		run := &surfaceRun{ran: true, files: len(files), exit: meta["exit"]}
		run.seconds, _ = strconv.ParseFloat(meta["seconds"], 64)
		runs[sf] = run
		if err != nil {
			r.fail("%s/%s: no output (%v)", s.name, sf, err)
			continue
		}
		roots := []string{s.hostRoot}
		if sf == "container-cli" {
			roots = []string{containerRoot}
		}
		norm, doc, err := normalizeCLI(raw, roots...)
		if err != nil {
			r.fail("%s/%s: output is not a JSON report: %v", s.name, sf, err)
			continue
		}
		docs[sf], parsed[sf] = norm, doc
		_ = os.WriteFile(filepath.Join(base, sf+".normalized.json"), norm, 0o644)
		run.findings = cliFindings(doc)
		if st, ok := doc["stats"].(map[string]any); ok {
			run.notExam, _ = strconv.Atoi(str(st, "files_not_examined"))
		}
	}
	for _, sf := range []string{"web", "container-web"} {
		if !r.has(sf) {
			continue
		}
		norm, doc, _ := normalizeWeb(filepath.Join(base, sf), files)
		docs[sf], parsed[sf] = norm, doc
		_ = os.WriteFile(filepath.Join(base, sf+".normalized.json"), norm, 0o644)
		run := &surfaceRun{ran: true, files: len(files), findings: webFindings(doc)}
		for _, v := range doc {
			if m, ok := v.(map[string]any); ok && m["incomplete"] == true {
				run.notExam++
			}
		}
		run.perFile, run.failures = readTimes(filepath.Join(base, sf+".times.tsv"))
		meta := readMeta(filepath.Join(base, sf+".meta"))
		run.seconds, _ = strconv.ParseFloat(meta["seconds"], 64)
		run.exit = "-"
		runs[sf] = run
		if run.failures > 0 {
			r.fail("%s/%s: %d of %d /scan requests did not answer 200", s.name, sf, run.failures, len(files))
		}
	}

	r.table(s, runs)

	if a, b := runs["cli"], runs["container-cli"]; a != nil && b != nil && a.exit != b.exit {
		r.fail("%s: cli exited %s, container-cli exited %s", s.name, a.exit, b.exit)
	}
	for _, sf := range []string{"cli", "container-cli"} {
		if st, ok := parsed[sf]["stats"].(map[string]any); ok {
			if walked := str(st, "total_files"); walked != strconv.Itoa(len(files)) {
				r.printf("note: %s walked %s file(s); the set lists %d (the web surfaces post all %d)\n", sf, walked, len(files), len(files))
			}
		}
	}

	// 1 == 3 and 2 == 4, byte for byte after normalisation.
	for _, p := range [][2]string{{"cli", "container-cli"}, {"web", "container-web"}} {
		if docs[p[0]] == nil || docs[p[1]] == nil {
			continue
		}
		if bytes.Equal(docs[p[0]], docs[p[1]]) {
			r.printf("%s == %s: identical after normalisation (%d bytes)\n", p[0], p[1], len(docs[p[0]]))
			continue
		}
		r.fail("%s/%s != %s after normalisation", s.name, p[0], p[1])
		r.printf("%s != %s after normalisation:\n", p[0], p[1])
		r.lineDiff(s, docs[p[0]], docs[p[1]])
	}

	// cli vs web finding sets, for each pair that ran.
	for _, p := range [][2]string{{"cli", "web"}, {"container-cli", "container-web"}} {
		a, b := runs[p[0]], runs[p[1]]
		if a == nil || b == nil || !a.ran || !b.ran {
			continue
		}
		r.findingDiff(s, p, a, b)
	}

	if r.has("web") && r.has("container-web") {
		r.exports(s, base)
	}
	if r.has("container-cli") {
		values := valuesOf(parsed["cli"], parsed["container-cli"])
		r.redaction(s, base, values)
	}
	r.ratios(s, runs)
}

func readTimes(path string) ([]float64, int) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, 0
	}
	var out []float64
	failures := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		out = append(out, v)
		if f[2] != "200" {
			failures++
		}
	}
	return out, failures
}

func quantiles(xs []float64) (p50, max float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[(len(s)-1)/2], s[len(s)-1]
}

func (r *report) table(s set, runs map[string]*surfaceRun) {
	r.printf("%-14s %6s %9s %6s %6s %6s %8s %6s %9s %9s %9s\n",
		"surface", "files", "findings", "high", "medium", "low", "not-exam", "exit", "wall(s)", "p50(s)", "max(s)")
	for _, sf := range surfaceNames {
		run := runs[sf]
		if run == nil {
			continue
		}
		h, m, l := bandCounts(run.findings)
		p50, max := "-", "-"
		if len(run.perFile) > 0 {
			a, b := quantiles(run.perFile)
			p50, max = fmt.Sprintf("%.3f", a), fmt.Sprintf("%.3f", b)
		}
		r.printf("%-14s %6d %9d %6d %6d %6d %8d %6s %9.2f %9s %9s\n",
			sf, run.files, len(run.findings), h, m, l, run.notExam, run.exit, run.seconds, p50, max)
	}
	if s.aggregate {
		for _, sf := range surfaceNames {
			if run := runs[sf]; run != nil {
				r.printf("  %s by type: %s\n", sf, typeCounts(run.findings))
			}
		}
	}
}

// lineDiff prints the first differing lines of two normalised documents. For an aggregate set it
// prints only how many lines differ: a line of a normalised report can hold a path or a value.
func (r *report) lineDiff(s set, a, b []byte) {
	al := strings.Split(string(a), "\n")
	bl := strings.Split(string(b), "\n")
	n := len(al)
	if len(bl) > n {
		n = len(bl)
	}
	shown, differ := 0, 0
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x == y {
			continue
		}
		differ++
		if s.aggregate || shown >= 12 {
			continue
		}
		shown++
		r.printf("  line %d\n    - %s\n    + %s\n", i+1, truncate(x, 160), truncate(y, 160))
	}
	r.printf("  %d line(s) differ (normalised files are under raw/%s/ with --keep)\n", differ, s.name)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (r *report) findingDiff(s set, p [2]string, a, b *surfaceRun) {
	onlyA, onlyB := multisetDiff(a.findings, b.findings)
	unexplained := 0
	var lines []string
	classify := func(side string, f finding) {
		line := f.rel + "\t" + f.typ + "\t" + f.line + "\t" + f.conf
		for i := range r.allowlist {
			e := &r.allowlist[i]
			if e.pattern.MatchString(line) {
				e.used++
				lines = append(lines, fmt.Sprintf("  allowlisted %s %s  (%s)", side, strings.ReplaceAll(line, "\t", " "), e.reason))
				return
			}
		}
		unexplained++
		lines = append(lines, fmt.Sprintf("  UNEXPLAINED %s %s value=%s", side, strings.ReplaceAll(line, "\t", " "), f.sha))
	}
	for _, f := range onlyA {
		classify("only-"+p[0], f)
	}
	for _, f := range onlyB {
		classify("only-"+p[1], f)
	}
	if a.notExam != b.notExam {
		unexplained++
		lines = append(lines, fmt.Sprintf("  UNEXPLAINED not-examined count %s=%d %s=%d", p[0], a.notExam, p[1], b.notExam))
	}
	if len(lines) == 0 {
		r.printf("%s vs %s: identical finding sets (%d findings)\n", p[0], p[1], len(a.findings))
		return
	}
	r.printf("%s vs %s: %d only in %s, %d only in %s, %d unexplained\n", p[0], p[1], len(onlyA), p[0], len(onlyB), p[1], unexplained)
	if !s.aggregate {
		for i, l := range lines {
			if i >= 40 {
				r.printf("  … %d more\n", len(lines)-i)
				break
			}
			r.printf("%s\n", l)
		}
	}
	if unexplained > 0 {
		r.fail("%s: %s vs %s: %d unexplained difference(s)", s.name, p[0], p[1], unexplained)
	}
}

// exports compares every /export body the two web surfaces returned, chunk by chunk and format by
// format, after normalizeExport.
func (r *report) exports(s set, base string) {
	hostDir := filepath.Join(base, "export", "web")
	ctrDir := filepath.Join(base, "export", "container-web")
	entries, err := os.ReadDir(hostDir)
	if err != nil {
		r.printf("exports: none (%v)\n", err)
		return
	}
	compared, differ, refused := 0, 0, 0
	formats := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".code") {
			continue
		}
		format := name[strings.LastIndex(name, ".")+1:]
		formats[format] = true
		hostCode := strings.TrimSpace(readString(filepath.Join(hostDir, name+".code")))
		ctrCode := strings.TrimSpace(readString(filepath.Join(ctrDir, name+".code")))
		hostBody, _ := os.ReadFile(filepath.Join(hostDir, name))
		ctrBody, err := os.ReadFile(filepath.Join(ctrDir, name))
		compared++
		if err != nil {
			differ++
			r.fail("%s: export %s missing from container-web", s.name, name)
			continue
		}
		if hostCode != "200" || ctrCode != "200" {
			refused++
			if hostCode != ctrCode {
				differ++
				r.fail("%s: export %s answered %s on web and %s on container-web", s.name, name, hostCode, ctrCode)
			}
			continue
		}
		if !bytes.Equal(normalizeExport(format, hostBody), normalizeExport(format, ctrBody)) {
			differ++
			r.fail("%s: export %s differs between web and container-web after normalisation", s.name, name)
		}
	}
	names := make([]string, 0, len(formats))
	for f := range formats {
		names = append(names, f)
	}
	sort.Strings(names)
	r.printf("exports web vs container-web: %d bodies over %d format(s) [%s], %d differ, %d refused on both\n",
		compared, len(names), strings.Join(names, " "), differ, refused)
}

func readString(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}

// valuesOf collects, per relative path, the matched values the CLI reported: surface 1's list when
// it ran, else surface 3's.
func valuesOf(docs ...map[string]any) map[string][]string {
	for _, doc := range docs {
		if doc == nil {
			continue
		}
		out := map[string][]string{}
		res, _ := doc["results"].([]any)
		for _, x := range res {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			out[str(m, "filename")] = append(out[str(m, "filename")], str(m, "text"))
		}
		return out
	}
	return nil
}

// redaction checks the copies the container wrote under every strategy and output directory.
func (r *report) redaction(s set, base string, values map[string][]string) {
	dirs, err := os.ReadDir(filepath.Join(base, "redact"))
	if err != nil {
		r.fail("%s: no redaction runs (%v)", s.name, err)
		return
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		runDir := filepath.Join(base, "redact", d.Name())
		meta := readMeta(filepath.Join(runDir, "run.meta"))
		if meta["exit"] != "0" {
			r.fail("%s: redaction %s exited %s in the container", s.name, d.Name(), meta["exit"])
		}
		copies := locateCopies(filepath.Join(runDir, "extracted"))
		disclosed := disclosedUnredacted(filepath.Join(runDir, "run.json"))
		rels := make([]string, 0, len(values))
		for rel := range values {
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		checked, survived, skipped, rewritten, tokens, refusedDisclosed, missing := 0, 0, 0, 0, 0, 0, 0
		var survivors []string
		for _, rel := range rels {
			copyPath, ok := copies[rel]
			if !ok {
				if disclosed[rel] {
					refusedDisclosed++
				} else {
					missing++
					if !s.aggregate {
						survivors = append(survivors, "no redacted copy and not disclosed: "+rel)
					}
				}
				continue
			}
			parts, err := readParts(copyPath)
			if err != nil {
				r.fail("%s: redaction %s: cannot read the copy of %s: %v", s.name, d.Name(), relOrHidden(s, rel), err)
				continue
			}
			if orig, err := os.ReadFile(filepath.Join(s.hostRoot, filepath.FromSlash(rel))); err == nil {
				if cp, err := os.ReadFile(copyPath); err == nil && !bytes.Equal(orig, cp) {
					rewritten++
				}
			}
			for _, p := range parts {
				tokens += bytes.Count(p, []byte("-REDACTED]"))
			}
			for _, v := range values[rel] {
				if len(v) < minValueBytes {
					skipped++
					continue
				}
				checked++
				if survives(parts, v) {
					survived++
					if !s.aggregate {
						survivors = append(survivors, fmt.Sprintf("%s keeps a reported value (sha256 %s, %d bytes)", rel, shortHash(v), len(v)))
					}
				}
			}
		}
		r.printf("redaction %-28s exit=%s copies=%d rewritten=%d values-checked=%d survived=%d skipped(<%dB)=%d simple-tokens=%d refused+disclosed=%d missing+undisclosed=%d\n",
			d.Name(), meta["exit"], len(copies), rewritten, checked, survived, minValueBytes, skipped, tokens, refusedDisclosed, missing)
		for i, sv := range survivors {
			if i >= 20 {
				r.printf("  … %d more\n", len(survivors)-i)
				break
			}
			r.printf("  %s\n", sv)
		}
		if survived > 0 || missing > 0 {
			r.fail("%s: redaction %s: %d surviving value(s), %d file(s) with findings and neither a copy nor a disclosure", s.name, d.Name(), survived, missing)
		}
	}
}

func relOrHidden(s set, rel string) string {
	if s.aggregate {
		return "<private file>"
	}
	return rel
}

// locateCopies maps each redacted copy to its input's relative path. The redactor mirrors the input's
// absolute path below the output directory, so a copy of /home/ferret/in/a/b.txt is at
// <out>/home/ferret/in/a/b.txt.
func locateCopies(root string) map[string]string {
	out := map[string]string{}
	marker := strings.TrimPrefix(containerRoot, "/") + "/"
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		slash := filepath.ToSlash(path)
		if i := strings.Index(slash, marker); i >= 0 {
			out[slash[i+len(marker):]] = path
		}
		return nil
	})
	return out
}

// disclosedUnredacted returns the inputs the redaction run itself named in its "unredacted" list.
func disclosedUnredacted(path string) map[string]bool {
	out := map[string]bool{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var doc struct {
		Unredacted []struct {
			Path string `json:"path"`
		} `json:"unredacted"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return out
	}
	strip := rootRewriter(containerRoot)
	for _, u := range doc.Unredacted {
		out[strip(u.Path)] = true
	}
	return out
}

// readParts returns the bytes to search: every part of an OOXML container (the value lives inside
// the XML, and the zip is compressed, so the container's own bytes would hide it), otherwise the
// file itself.
func readParts(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp":
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return [][]byte{raw}, nil
		}
		var parts [][]byte
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
			rc.Close()
			if err == nil {
				parts = append(parts, b)
			}
		}
		return parts, nil
	}
	return [][]byte{raw}, nil
}

// survives reports whether a value is still present in any part, as written, XML-escaped, or as
// UTF-16LE (how the legacy .doc/.xls formats store text), as a token of its own.
//
// "Of its own" means the occurrence is not glued to a letter or digit on a side where the value
// itself ends in one: inside a longer run of letters and digits it is part of another token, which
// the scan did not report and the redactor rightly left. Measured on the golden inputs, the member ID
// BEEF1234567 is redacted where it was reported and also occurs inside the decoy 0xDEADBEEF12345678,
// which a plain substring search counts as a surviving value.
func survives(parts [][]byte, v string) bool {
	type form struct {
		b    []byte
		unit int // bytes per character, for the boundary check
	}
	forms := []form{{[]byte(v), 1}}
	if esc := xmlEscape(v); esc != v {
		forms = append(forms, form{[]byte(esc), 1})
	}
	forms = append(forms, form{utf16LE(v), 2})
	for _, p := range parts {
		for _, f := range forms {
			if containsToken(p, f.b, f.unit) {
				return true
			}
		}
	}
	return false
}

// containsToken reports whether needle occurs in hay with a non-alphanumeric character (or the edge
// of hay) on each side where needle itself starts or ends with one. unit is 1 for single-byte text and
// 2 for UTF-16LE, whose character before an occurrence is the two bytes before it.
func containsToken(hay, needle []byte, unit int) bool {
	if len(needle) == 0 {
		return false
	}
	gluedStart := isAlnum(needle[0])
	gluedEnd := isAlnum(needle[len(needle)-unit])
	for off := 0; ; {
		i := bytes.Index(hay[off:], needle)
		if i < 0 {
			return false
		}
		start := off + i
		end := start + len(needle)
		before := start-unit >= 0 && isAlnumAt(hay, start-unit, unit)
		after := end+unit <= len(hay) && isAlnumAt(hay, end, unit)
		if !(gluedStart && before) && !(gluedEnd && after) {
			return true
		}
		off = start + 1
	}
}

func isAlnumAt(b []byte, i, unit int) bool {
	if unit == 2 && b[i+1] != 0 {
		return true // a non-ASCII UTF-16 character: treat it as part of a word
	}
	return isAlnum(b[i])
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func utf16LE(s string) []byte {
	var b []byte
	for _, r := range s {
		if r > 0xFFFF {
			return []byte(s)
		}
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func (r *report) ratios(s set, runs map[string]*surfaceRun) {
	for _, p := range [][2]string{{"container-cli", "cli"}, {"container-web", "web"}} {
		c, h := runs[p[0]], runs[p[1]]
		if c == nil || h == nil || h.seconds <= 0 {
			continue
		}
		ratio := c.seconds / h.seconds
		line := fmt.Sprintf("%s: %s/%s wall-clock ratio %.2f (%.2fs / %.2fs)", s.name, p[0], p[1], ratio, c.seconds, h.seconds)
		if len(c.perFile) > 0 && len(h.perFile) > 0 {
			cp, _ := quantiles(c.perFile)
			hp, _ := quantiles(h.perFile)
			if hp > 0 {
				line += fmt.Sprintf(", per-file p50 ratio %.2f", cp/hp)
			}
		}
		r.printf("%s\n", line)
		if ratio > ratioWarn {
			r.warn("%s (above %.1f)", line, ratioWarn)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// runtime facts the script recorded

func (r *report) facts() {
	path := filepath.Join(r.work, "raw", "facts.tsv")
	raw, err := os.ReadFile(path)
	if err != nil {
		r.fail("no runtime facts recorded (%v)", err)
		return
	}
	r.printf("=== runtime facts ===\n")
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		f := strings.SplitN(line, "\t", 3)
		if len(f) != 3 {
			continue
		}
		r.printf("%-6s %-34s %s\n", f[0], f[1], f[2])
		if f[0] == "FAIL" {
			r.fail("runtime fact: %s: %s", f[1], f[2])
		}
	}
}

func (r *report) printAllowlist() {
	r.printf("\n=== allowlist in effect (scripts/surface-parity/allowlist.tsv) ===\n")
	if len(r.allowlist) == 0 {
		r.printf("(empty)\n")
		return
	}
	for _, e := range r.allowlist {
		r.printf("%s\t%s\t%s\t(used %d)\n", e.pair, e.raw, e.reason, e.used)
	}
}
