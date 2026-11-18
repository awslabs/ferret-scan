// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/version"
)

// The audit log's registry oracle and declared-field guard (#865, box 10).
//
// Oracle: every redactor the CLI registers (core.NewDefaultRedactionManager, read back through
// Capabilities and GetRedactorForFile, so a new redactor is seen without anyone editing a list) has
// a fixture here, and under every strategy it declares, its real mappings go through
// AddRedactionResult and ExportAuditLog and the exported log is checked against the run: the
// version, the strategy, each entry's confidence and line against the finding it covers, and each
// redacted_text against the bytes written. A registered redactor without a fixture fails.
//
// Guard: every leaf the audit JSON declares (read by reflection from redactors.RedactionAuditLog)
// is non-zero in at least one log the oracle exported, or is allowlisted here with the reason it is
// always zero. A field added to the log and never set, or a source that stops setting one, fails.
//
// Synthetic values only: a reserved-domain address, 555-01xx numbers, zero-serial and sequential
// card numbers.

// auditCase is one input for a registered redactor and the findings the report carries for it.
type auditCase struct {
	file    string
	build   func(t *testing.T) []byte
	matches func(src string) []detector.Match
	// refused: the redactor refuses every file of the type, so no audit entry may exist.
	refused bool
	// wide: the value is stored as UTF-16LE, so redacted_text is looked for at that width.
	wide bool
}

const (
	oracleVisa = "4000000000000002"
	oracleMC   = "5100000000000008"
)

func lineMatch(src string, lines []string) func(line int, typ, text string, conf float64) detector.Match {
	return func(line int, typ, text string, conf float64) detector.Match {
		m := detector.Match{Text: text, Type: typ, LineNumber: line, Confidence: conf, Filename: src}
		if line >= 1 && line <= len(lines) {
			m.Context = detector.ContextInfo{FullLine: lines[line-1]}
		}
		return m
	}
}

func textCase(file string, lines []string, ms func(m func(int, string, string, float64) detector.Match) []detector.Match) auditCase {
	return auditCase{
		file:    file,
		build:   func(*testing.T) []byte { return []byte(strings.Join(lines, "\n") + "\n") },
		matches: func(src string) []detector.Match { return ms(lineMatch(src, lines)) },
	}
}

// mp4Atom and mp4WithComment build the udta>meta>ilst>NAME>data layout ffmpeg writes into .mp4.
func mp4Atom(kind string, payload ...[]byte) []byte {
	body := bytes.Join(payload, nil)
	out := binary.BigEndian.AppendUint32(nil, uint32(8+len(body)))
	return append(append(out, kind...), body...)
}

func mp4WithComment(comment string) []byte {
	tag := mp4Atom("\xa9cmt", mp4Atom("data", []byte{0, 0, 0, 1}, []byte{0, 0, 0, 0}, []byte(comment)))
	udta := mp4Atom("udta", mp4Atom("meta", []byte{0, 0, 0, 0}, mp4Atom("ilst", tag)))
	file := append(mp4Atom("ftyp", []byte("isomiso2mp41")), mp4Atom("moov", mp4Atom("mvhd", make([]byte, 100)), udta)...)
	return append(file, mp4Atom("mdat", bytes.Repeat([]byte{0xCD}, 512))...)
}

// auditCases holds one or more inputs per registered redactor name. Between them they reach every
// path that writes an audit field: the text redactor's exact, fuzzy and corrected placements and its
// text-search fallback (SVG, RTF), an overlap group, an embedded part, EXIF removals, and a merged
// same-length mask.
func auditCases() map[string][]auditCase {
	sample := []string{
		"Customer record (synthetic test data)",
		"Contact email: " + e2eEmail,
		"Payment card: " + oracleVisa,
		"Phone: " + e2ePhone,
		"Backup card " + oracleMC,
		"Ref " + e2eCard + "876",
	}
	dup := []string{"Card: " + oracleVisa + " and again " + oracleVisa}
	svg := `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="50"><text x="1" y="20">Card ` + oracleVisa +
		`</text><text x="1" y="40">Mail ` + e2eEmail + `</text></svg>` + "\n"
	rtf := `{\rtf1\ansi{\fonttbl\f0 Helvetica;}\f0 Card ` + oracleVisa + `\par Mail ` + e2eEmail + `\par}` + "\n"
	textOf := func(b string) func(*testing.T) []byte { return func(*testing.T) []byte { return []byte(b) } }
	markup := func(src string) []detector.Match {
		return []detector.Match{
			{Text: oracleVisa, Type: "VISA", LineNumber: 1, Confidence: 15, Filename: src},
			{Text: e2eEmail, Type: "BUSINESS", LineNumber: 2, Confidence: 45, Filename: src},
		}
	}
	const field = "contact " + e2eEmail
	const union = e2eCard + "876"

	return map[string][]auditCase{
		"plaintext_redactor": {
			textCase("sample.txt", sample, func(m func(int, string, string, float64) detector.Match) []detector.Match {
				return []detector.Match{
					m(2, "BUSINESS", e2eEmail, 61), m(3, "VISA", oracleVisa, 15), m(4, "PHONE", e2ePhone, 100),
					m(5, "MASTERCARD", oracleMC, 21),
					// A card running into an account number: one overlap group, one entry (#773).
					m(6, "VISA", e2eCard, 95), m(6, "BANK_ACCOUNT", "9012349876", 60),
				}
			}),
			textCase("dup.txt", dup, func(m func(int, string, string, float64) detector.Match) []detector.Match {
				return []detector.Match{m(1, "VISA", oracleVisa, 15), m(1, "VISA", oracleVisa, 15)}
			}),
		},
		"svg_redactor": {{file: "draw.svg", build: textOf(svg), matches: markup}},
		"rtf_redactor": {{file: "note.rtf", build: textOf(rtf), matches: markup}},
		"office_redactor": {{
			file: "withimg.docx",
			build: func(t *testing.T) []byte {
				return docxWith(t, "Phone "+e2ePhone, "word/media/image1.jpeg", jpegWithTwoFields(t, field, "Jane Doe"))
			},
			matches: func(src string) []detector.Match {
				return []detector.Match{
					{Text: e2ePhone, Type: "PHONE", LineNumber: 1, Confidence: 100, Filename: src},
					{Text: e2eEmail, Type: "BUSINESS", LineNumber: 2, Confidence: 53, Filename: src + " -> image1.jpeg"},
				}
			},
		}, {
			// A value inside an embedded document: a content entry at embedded_media, with its path.
			file: "nested.docx",
			build: func(t *testing.T) []byte {
				inner := docxWith(t, "Email "+e2eEmail, "docProps/custom.xml", []byte(`<?xml version="1.0"?><Properties/>`))
				return docxWith(t, "Quarterly notes", "word/embeddings/oleObject1.docx", inner)
			},
			matches: func(src string) []detector.Match {
				return []detector.Match{{Text: e2eEmail, Type: "BUSINESS", LineNumber: 1, Confidence: 61,
					Filename: src + " -> oleObject1.docx"}}
			},
		}},
		"image_metadata_redactor": {{
			file:  "photo.jpg",
			build: func(t *testing.T) []byte { return jpegWithTwoFields(t, field, "Jane Doe") },
			matches: func(src string) []detector.Match {
				return []detector.Match{{Text: e2eEmail, Type: "BUSINESS", LineNumber: 1, Confidence: 53, Filename: src}}
			},
		}},
		"audio_metadata_redactor": {{
			file: "merged.wav",
			build: func(*testing.T) []byte {
				return wavWithLabelledValues(map[string]string{"ICMT": field, "IART": "Phone " + e2ePhone})
			},
			matches: func(src string) []detector.Match {
				return []detector.Match{
					{Text: e2eEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 5, Filename: src},
					{Text: field, Type: "EMAIL", Confidence: 50, LineNumber: 5, Filename: src},
					{Text: e2ePhone, Type: "PHONE", Confidence: 100, LineNumber: 6, Filename: src},
				}
			},
		}},
		"video_metadata_redactor": {{
			file:  "movie.mp4",
			build: func(*testing.T) []byte { return mp4WithComment(field) },
			matches: func(src string) []detector.Match {
				return []detector.Match{{Text: e2eEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 3, Filename: src}}
			},
		}},
		"legacy_ole_redactor": {{
			file:  "w.doc",
			build: func(*testing.T) []byte { return olefixture.LegacyDoc("Email "+e2eEmail+"\rRef "+union+"\r", nil) },
			matches: func(src string) []detector.Match {
				return []detector.Match{
					{Text: e2eEmail, Type: "BUSINESS", Validator: "email", Confidence: 90, LineNumber: 1, Filename: src},
					{Text: e2eCard, Type: "VISA", Validator: "creditcard", Confidence: 95, LineNumber: 2, Filename: src,
						Context: detector.ContextInfo{FullLine: "Ref " + union}},
					{Text: "9012349876", Type: "BANK_ACCOUNT", Validator: "bankaccount", Confidence: 60, LineNumber: 2, Filename: src,
						Context: detector.ContextInfo{FullLine: "Ref " + union}},
				}
			},
		}},
		"pdf_redactor": {{
			file:  "doc.pdf",
			build: func(*testing.T) []byte { return []byte("%PDF-1.4\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n") },
			matches: func(src string) []detector.Match {
				return []detector.Match{{Text: e2eEmail, Type: "BUSINESS", Confidence: 53, LineNumber: 1, Filename: src}}
			},
			refused: true,
		}},
	}
}

// registeredRedactorNames is the registry's own answer: the name of the redactor every registered
// type (redactable or declared unimplemented) selects.
func registeredRedactorNames(t *testing.T) []string {
	t.Helper()
	rm, _, err := core.NewDefaultRedactionManager(t.TempDir(), redactors.RedactionFormatPreserving, nil)
	if err != nil {
		t.Fatal(err)
	}
	caps := rm.Capabilities()
	types := append([]string(nil), caps.Redactable...)
	for ext := range caps.Unimplemented {
		types = append(types, ext)
	}
	seen := map[string]bool{}
	dir := t.TempDir()
	for _, ext := range types {
		r, err := rm.GetRedactorForFile(filepath.Join(dir, "probe"+ext))
		if err != nil {
			t.Fatalf("%s is registered but GetRedactorForFile refuses it: %v", ext, err)
		}
		seen[r.GetName()] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// oracleRun is one exported audit log: its raw JSON and what produced it.
type oracleRun struct {
	what     string
	raw      []byte
	out      string
	strategy redactors.RedactionStrategy
	c        auditCase
	matches  []detector.Match
}

// runOracleCase redacts one case under one strategy through the CLI's registry and exports the log.
// ok is false when the redactor refused (an error, or a declared refusal); the log is still exported.
func runOracleCase(t *testing.T, name string, c auditCase, st redactors.RedactionStrategy) (oracleRun, bool) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, c.file)
	if err := os.WriteFile(src, c.build(t), 0o600); err != nil {
		t.Fatal(err)
	}
	rm, om, err := core.NewDefaultRedactionManager(filepath.Join(dir, "out"), st, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rm.GetRedactorForFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if r.GetName() != name {
		t.Fatalf("%s selects %s, want %s; the fixture no longer reaches the redactor it is for", c.file, r.GetName(), name)
	}
	out, err := om.CreateMirroredPath(src)
	if err != nil {
		t.Fatal(err)
	}
	matches := c.matches(src)
	res, rerr := r.RedactDocument(src, out, matches, st)
	ok := rerr == nil && res != nil && res.Success
	if ok {
		rm.AddRedactionResult(src, out, res)
	}
	logPath := filepath.Join(dir, "audit.json")
	if err := rm.ExportAuditLog(logPath); err != nil {
		t.Fatalf("%s %s: export: %v", name, st, err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return oracleRun{what: name + "/" + c.file + "/" + st.String(), raw: raw, out: out, strategy: st, c: c, matches: matches}, ok
}

// runAllOracleCases runs every case of every registered redactor under every declared strategy.
func runAllOracleCases(t *testing.T) []oracleRun {
	t.Helper()
	cases := auditCases()
	var runs []oracleRun
	for _, name := range registeredRedactorNames(t) {
		cs, ok := cases[name]
		if !ok || len(cs) == 0 {
			t.Errorf("registered redactor %s has no audit fixture in auditCases; add one so its audit log is checked against the run", name)
			continue
		}
		strategies, ok := declaredStrategies[name]
		if !ok {
			t.Errorf("registered redactor %s has no declaredStrategies row", name)
			continue
		}
		for _, c := range cs {
			for _, st := range strategies {
				run, redacted := runOracleCase(t, name, c, st)
				switch {
				case c.refused && redacted:
					t.Errorf("%s: a redactor declared to refuse wrote a redaction", run.what)
				case !c.refused && !redacted:
					t.Errorf("%s: the fixture was refused; it no longer exercises the audit log", run.what)
				}
				runs = append(runs, run)
			}
		}
	}
	return runs
}

type oracleEntry struct {
	DataType          string   `json:"data_type"`
	RedactedText      string   `json:"redacted_text"`
	Strategy          string   `json:"strategy"`
	RequestedStrategy *string  `json:"requested_strategy"`
	Confidence        float64  `json:"confidence"`
	Line              int      `json:"line"`
	MemberTypes       []string `json:"member_types"`
}

type oracleDoc struct {
	FerretVersion      string            `json:"ferret_version"`
	ContentRedactions  []oracleEntry     `json:"content_redactions"`
	MetadataRedactions []json.RawMessage `json:"metadata_redactions"`
	Summary            struct {
		Strategy   string `json:"strategy"`
		Total      int    `json:"total_redactions"`
		Successful int    `json:"successful_redactions"`
		Failed     int    `json:"failed_redactions"`
	} `json:"redaction_summary"`
}

type oracleEnvelope struct {
	FerretVersion  string               `json:"ferret_version"`
	TotalDocuments int                  `json:"total_documents"`
	AuditLogs      map[string]oracleDoc `json:"audit_logs"`
}

// TestEveryRegisteredRedactorsAuditLogIsTheRun is the registry oracle.
func TestEveryRegisteredRedactorsAuditLogIsTheRun(t *testing.T) {
	runs := runAllOracleCases(t)
	for _, run := range runs {
		var env oracleEnvelope
		if err := json.Unmarshal(run.raw, &env); err != nil {
			t.Fatalf("%s: %v", run.what, err)
		}
		if env.FerretVersion != version.Short() {
			t.Errorf("%s: envelope ferret_version %q, want %q", run.what, env.FerretVersion, version.Short())
		}
		if run.c.refused {
			if env.TotalDocuments != 0 || len(env.AuditLogs) != 0 {
				t.Errorf("%s: a refused file has %d audit document(s), want none", run.what, env.TotalDocuments)
			}
			continue
		}
		if env.TotalDocuments != 1 || len(env.AuditLogs) != 1 {
			t.Fatalf("%s: %d audit documents, want 1", run.what, env.TotalDocuments)
		}
		raw, err := os.ReadFile(run.out)
		if err != nil {
			t.Fatal(err)
		}
		written := unzipDeep(t, raw, 0)
		for _, doc := range env.AuditLogs {
			checkOracleDoc(t, run, doc, written)
		}
	}
}

func checkOracleDoc(t *testing.T, run oracleRun, doc oracleDoc, written []byte) {
	t.Helper()
	if doc.FerretVersion != version.Short() {
		t.Errorf("%s: document ferret_version %q, want %q", run.what, doc.FerretVersion, version.Short())
	}
	s := doc.Summary
	if s.Strategy != run.strategy.String() {
		t.Errorf("%s: summary strategy %q, want the run's %q", run.what, s.Strategy, run.strategy)
	}
	if n := len(doc.ContentRedactions) + len(doc.MetadataRedactions); s.Total != n || s.Successful != n || s.Failed != 0 {
		t.Errorf("%s: summary total %d successful %d failed %d, want %d, %d, 0", run.what, s.Total, s.Successful, s.Failed, n, n)
	}
	for _, e := range doc.ContentRedactions {
		masked := e.Strategy == string(redactors.AuditMask)
		switch {
		case masked && (e.RequestedStrategy == nil || *e.RequestedStrategy != run.strategy.String()):
			t.Errorf("%s %s: a mask entry must name the requested %q, got %v", run.what, e.DataType, run.strategy, e.RequestedStrategy)
		case !masked && e.RequestedStrategy != nil:
			t.Errorf("%s %s: requested_strategy %q on an entry that is not a mask", run.what, e.DataType, *e.RequestedStrategy)
		case !masked && e.Strategy != run.strategy.String():
			t.Errorf("%s %s: entry strategy %q, want the run's %q", run.what, e.DataType, e.Strategy, run.strategy)
		}
		if !coversAFinding(e, run.matches) {
			t.Errorf("%s %s: line %d confidence %v matches no reported finding's line and confidence / 100",
				run.what, e.DataType, e.Line, e.Confidence)
		}
		form := []byte(e.RedactedText)
		if run.c.wide {
			form = utf16LE(e.RedactedText)
		}
		if e.RedactedText == "" || !holdsWhole(written, form, run.c.wide) {
			t.Errorf("%s %s: redacted_text %q is not in the bytes written", run.what, e.DataType, e.RedactedText)
		}
	}
}

// unzipDeep is b with every ZIP entry decompressed, nested containers included: a value written
// inside an embedded .docx is compressed twice, and grepping compressed bytes finds nothing.
func unzipDeep(t *testing.T, b []byte, depth int) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil || depth > 3 {
		return b
	}
	var all []byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		part, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		all = append(all, unzipDeep(t, part, depth+1)...)
	}
	return all
}

// coversAFinding: some reported finding of the entry's type (or of a group member's type) is on the
// entry's line and has the entry's confidence x 100.
func coversAFinding(e oracleEntry, matches []detector.Match) bool {
	types := map[string]bool{e.DataType: true}
	for _, mt := range e.MemberTypes {
		types[mt] = true
	}
	for _, m := range matches {
		if types[m.Type] && m.LineNumber == e.Line && math.Abs(m.Confidence/100-e.Confidence) < 1e-9 {
			return true
		}
	}
	return false
}

// ---------- the declared-field guard ----------

// alwaysZero are the declared leaves no run sets, each with the reason. A leaf listed here that a
// run does set fails too, so the list cannot go stale.
var alwaysZero = map[string]string{
	"audit_logs.*.redaction_summary.failed_redactions": "0 by construction: a document that could not be redacted " +
		"gets no audit entry and is reported as not redacted instead (RedactionSummary.FailedRedactions)",
	"audit_logs.*.metadata_redactions[].redacted_value": "null for a removal, the only metadata action any redactor " +
		"records (AddRedactionResult writes action \"removed\")",
}

// envelopeLeaves are the export envelope's own keys (an unnamed struct in ExportAllAuditLogs).
var envelopeLeaves = []string{"export_timestamp", "ferret_version", "total_documents"}

var timeType = reflect.TypeOf(time.Time{})

// declaredLeaves lists every JSON leaf of t under prefix, by its json tag: a struct (other than
// time.Time) or a pointer to one is descended into, a slice of structs as "name[]".
func declaredLeaves(prefix string, t reflect.Type, out map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" || !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		ft := f.Type
		path := prefix + name
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		switch {
		case ft.Kind() == reflect.Struct && ft != timeType:
			declaredLeaves(path+".", ft, out)
		case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct && ft.Elem() != timeType:
			declaredLeaves(path+"[].", ft.Elem(), out)
		default:
			out[path] = true
		}
	}
}

// setLeaves records every leaf path of v that holds a non-zero value: a non-empty string, a
// non-zero number, true, or a non-empty list of scalars. Map keys under audit_logs become "*".
func setLeaves(path string, v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if path == "audit_logs" {
				p = path + ".*"
			}
			setLeaves(p, child, out)
		}
	case []any:
		if len(x) == 0 {
			return
		}
		if _, isObj := x[0].(map[string]any); !isObj {
			out[path] = true
			return
		}
		for _, child := range x {
			setLeaves(path+"[]", child, out)
		}
	case string:
		if x != "" {
			out[path] = true
		}
	case float64:
		if x != 0 {
			out[path] = true
		}
	case bool:
		if x {
			out[path] = true
		}
	}
}

func TestEveryDeclaredAuditFieldIsSetByARun(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range envelopeLeaves {
		declared[k] = true
	}
	declaredLeaves("audit_logs.*.", reflect.TypeOf(redactors.RedactionAuditLog{}), declared)

	set := map[string]bool{}
	for _, run := range runAllOracleCases(t) {
		var v any
		if err := json.Unmarshal(run.raw, &v); err != nil {
			t.Fatalf("%s: %v", run.what, err)
		}
		setLeaves("", v, set)
	}
	if len(set) == 0 {
		t.Fatal("no run set any audit field; the guard is not looking at a log")
	}

	var unset, undeclared, stale []string
	for leaf := range declared {
		_, allowed := alwaysZero[leaf]
		switch {
		case set[leaf] && allowed:
			stale = append(stale, leaf)
		case !set[leaf] && !allowed:
			unset = append(unset, leaf)
		}
	}
	for leaf := range set {
		if !declared[leaf] {
			undeclared = append(undeclared, leaf)
		}
	}
	for leaf := range alwaysZero {
		if !declared[leaf] {
			stale = append(stale, leaf+" (no longer declared)")
		}
	}
	sort.Strings(unset)
	sort.Strings(undeclared)
	sort.Strings(stale)
	for _, l := range unset {
		t.Errorf("declared audit field %s is zero in every log the oracle exported: set it from the run, "+
			"add a fixture that reaches it, or allowlist it in alwaysZero with the reason", l)
	}
	for _, l := range undeclared {
		t.Errorf("audit field %s is written but not declared on RedactionAuditLog", l)
	}
	for _, l := range stale {
		t.Errorf("alwaysZero lists %s, which a run sets or which is gone; remove it", l)
	}
}
