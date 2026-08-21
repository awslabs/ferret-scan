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
	"strconv"
	"strings"
	"testing"
)

// End-to-end contracts for the unredacted disclosure, driven through the real binary
// because an exit code and a stream choice are CLI contracts, not library ones.
//
// The matrix measured on main BEFORE this change, on a PDF with findings under
// --enable-redaction:
//
//	scenario                              rc   in-band disclosure
//	default                               0    NONE in any of 7 formats
//	--fail-on-incomplete                  0    NONE
//
// Exit 0 with values in cleartext and a clean-looking report on stdout is the one
// outcome the sink rule forbids (#441).

func buildForRedactionTest(t *testing.T) string {
	t.Helper()
	name := "ferret-scan-unredacted-test"
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

type redactRun struct {
	rc      int
	stdout  string
	stderr  string
	written int
}

// runRedaction scans dir with redaction enabled and reports what happened.
//
// --config os.DevNull so a developer's own config cannot change the outcome, which is
// the same precaution the other exit-code tests take.
func runRedaction(t *testing.T, bin, dir, format string, extra ...string) redactRun {
	t.Helper()
	outDir := filepath.Join(t.TempDir(), "redacted")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	args := append([]string{
		"--file", dir, "--recursive", "--config", os.DevNull,
		"--enable-redaction", "--redaction-output-dir", outDir,
		"--format", format, "--limit", "0", "--quiet",
	}, extra...)

	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()

	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}

	written := 0
	_ = filepath.Walk(outDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			written++
		}
		return nil
	})

	return redactRun{rc, so.String(), se.String(), written}
}

// buildValidPDF builds a structurally valid PDF with a correct xref AND startxref,
// carrying text the extractor can actually read.
//
// Both the xref and startxref are required. A hand-rolled PDF without them makes the
// extractor ERROR rather than parse, and the consequence is a silent false pass: the file
// then yields no findings, so nothing is redacted, nothing is refused, and the exit code
// becomes 3 for an entirely different reason (a coverage gap). That happened while writing
// this test — the escalation assertion passed while the disclosure was empty. The same
// warning is on internal/core's copy of this helper, which is where this is ported from.
func buildValidPDF(t *testing.T, text string) []byte {
	t.Helper()
	content := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET\n"
	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R " +
			"/Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
		"4 0 obj\n<< /Length " + strconv.Itoa(len(content)) + " >>\nstream\n" + content + "endstream\nendobj\n",
		"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
	}
	var sb strings.Builder
	sb.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objs))
	for _, o := range objs {
		offsets = append(offsets, sb.Len())
		sb.WriteString(o)
	}
	xref := sb.Len()
	sb.WriteString("xref\n0 " + strconv.Itoa(len(objs)+1) + "\n0000000000 65535 f \n")
	for _, off := range offsets {
		sb.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}
	sb.WriteString("trailer\n<< /Size " + strconv.Itoa(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" +
		strconv.Itoa(xref) + "\n%%EOF\n")
	return []byte(sb.String())
}

// unredactableDir builds a directory holding one file that CANNOT be redacted plus one
// that can, so every assertion is about the DIFFERENCE rather than about the tool refusing
// everything.
//
// The unredactable file is a .pdf, because PDF redaction is not implemented — a stable
// property of the tool rather than a contrived fixture. It must be a VALID pdf whose text
// extracts, or the refusal path is never reached; see buildValidPDF.
func unredactableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "report.pdf"),
		buildValidPDF(t, "Patient SSN 449-87-4100"), 0o600); err != nil {
		t.Fatalf("write pdf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("SSN 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	return dir
}

// requireRefusalHappened guards every assertion in this file against the false pass
// described on buildValidPDF: if the PDF did not produce findings, there was no redaction
// to refuse, and any exit code or disclosure assertion is measuring something else.
func requireRefusalHappened(t *testing.T, stdoutJSON string) {
	t.Helper()
	var doc struct {
		Stats struct {
			FilesNotRedacted int `json:"files_not_redacted"`
			TotalFindings    int `json:"total_findings"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(stdoutJSON), &doc); err != nil {
		t.Fatalf("could not read the run's json: %v", err)
	}
	if doc.Stats.TotalFindings == 0 {
		t.Fatal("the fixture produced NO findings, so nothing was redacted and nothing refused; " +
			"the pdf almost certainly failed to extract")
	}
	if doc.Stats.FilesNotRedacted == 0 {
		t.Fatal("no file was refused, so this test is not exercising the disclosure at all")
	}
}

// --fail-on-incomplete must escalate a refusal, and its absence must not.
//
// This is the decision the flag's meaning was widened for: it was "the scan did not see
// everything" and is now "the run did not fully do what was asked". Both halves are
// asserted, because escalating unconditionally would break every pipeline that redacts a
// PDF today, and escalating never is the defect.
func TestUnredactedFileEscalatesOnlyWithTheFlag(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	// Establish, in json, that a refusal genuinely occurs for this fixture before
	// asserting anything about exit codes. rc=3 can also come from a COVERAGE gap, so
	// without this the escalation assertion could pass while the disclosure is empty —
	// which is exactly what happened on the first draft's invalid pdf.
	requireRefusalHappened(t, runRedaction(t, bin, dir, "json").stdout)

	without := runRedaction(t, bin, dir, "text")
	if without.rc != 0 {
		t.Errorf("without --fail-on-incomplete rc = %d, want 0: adding a new default failure "+
			"would break every pipeline that redacts a PDF today\n%s", without.rc, without.stderr)
	}

	with := runRedaction(t, bin, dir, "text", "--fail-on-incomplete")
	if with.rc != exitCodeIncompleteCoverage {
		t.Errorf("with --fail-on-incomplete rc = %d, want %d: a run that leaves values in "+
			"cleartext must be gateable in CI\n%s", with.rc, exitCodeIncompleteCoverage, with.stderr)
	}

	// Non-vacuity: the refusal must actually have happened, and the OTHER file must
	// actually have been redacted. Without this the test would pass on a build that
	// refused everything, or one that wrote nothing at all.
	if without.written != 1 {
		t.Errorf("wrote %d redacted copies, want exactly 1 (the .txt): if 0, the tool refused "+
			"everything and the exit codes above prove nothing; if 2, nothing was refused",
			without.written)
	}
}

// A run where everything redacts must stay green even with the flag set.
//
// The inverse of the test above. If the escalation keyed on "redaction was requested"
// rather than "a refusal occurred", every redacting pipeline would start failing.
func TestFullyRedactedRunStaysZeroWithTheFlag(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("SSN 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	run := runRedaction(t, bin, dir, "text", "--fail-on-incomplete")
	if run.rc != 0 {
		t.Errorf("a fully redacted run exited %d with --fail-on-incomplete, want 0\n%s", run.rc, run.stderr)
	}
	if run.written != 1 {
		t.Fatalf("wrote %d copies, want 1 — nothing was redacted, so the zero above is vacuous", run.written)
	}
	if strings.Contains(run.stdout, "VALUES LEFT IN CLEARTEXT") {
		t.Errorf("a fully redacted run claims an exposure:\n%s", run.stdout)
	}
}

// Every format must carry the disclosure IN-BAND on stdout, and no format may leak the
// raw value.
//
// In-band matters because stderr is discarded by pipelines — that is the whole defect.
// The leak check is here as well as in the unit tests because the disclosure's detail is
// a redactor's error string, and one of those did interpolate match.Text; a regression
// there would reach seven formats at once and only an end-to-end assertion sees the real
// strings.
func TestEveryFormatDisclosesOnStdoutAndLeaksNothing(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	// Each format's own idiom, as in the formatter-level test.
	want := map[string]string{
		"text":        "VALUES LEFT IN CLEARTEXT",
		"json":        `"unredacted"`,
		"yaml":        "unredacted:",
		"csv":         "Not Redacted Reason",
		"junit":       `name="unredacted"`,
		"gitlab-sast": "NOT REDACTED",
		"sarif":       "ferret-scan/not-redacted",
	}

	for format, needle := range want {
		t.Run(format, func(t *testing.T) {
			run := runRedaction(t, bin, dir, format)
			if !strings.Contains(run.stdout, needle) {
				t.Errorf("%s does not disclose on STDOUT (missing %q). stderr is discarded by "+
					"pipelines, so an out-of-band-only warning is the defect this fixes.\n"+
					"--- stdout ---\n%s", format, needle, run.stdout)
			}
			// BSC4: the raw matched value must never appear, with or without --show-match
			// being asked for. Here it is not asked for.
			if strings.Contains(run.stdout, "449-87-4100") {
				t.Errorf("%s leaked the raw value into stdout without --show-match\n%s", format, run.stdout)
			}
			if strings.Contains(run.stderr, "449-87-4100") {
				t.Errorf("%s leaked the raw value into stderr\n%s", format, run.stderr)
			}
		})
	}
}

// The JSON counters must be the TRUE totals and must agree with the entry list.
//
// A summary that disagrees with its own list is how a report loses trust, and the count
// is what a consumer gates on.
func TestJSONCountersAgreeWithTheList(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	run := runRedaction(t, bin, dir, "json")

	var doc struct {
		Stats struct {
			FilesNotRedacted  int `json:"files_not_redacted"`
			ValuesNotRedacted int `json:"values_not_redacted"`
			TotalFindings     int `json:"total_findings"`
		} `json:"stats"`
		Unredacted []struct {
			Path           string `json:"path"`
			Cause          string `json:"cause"`
			ReportedValues int    `json:"reported_values"`
		} `json:"unredacted"`
	}
	if err := json.Unmarshal([]byte(run.stdout), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, run.stdout)
	}

	if doc.Stats.FilesNotRedacted != 1 {
		t.Errorf("files_not_redacted = %d, want 1", doc.Stats.FilesNotRedacted)
	}
	if len(doc.Unredacted) != 1 {
		t.Fatalf("unredacted[] has %d entries, want 1", len(doc.Unredacted))
	}
	if got := doc.Unredacted[0].ReportedValues; got < 1 {
		t.Errorf("reported_values = %d, want at least 1 — a disclosure that cannot say how much "+
			"is exposed does not size the problem", got)
	}
	if doc.Stats.ValuesNotRedacted != doc.Unredacted[0].ReportedValues {
		t.Errorf("stats.values_not_redacted (%d) disagrees with the entry's reported_values (%d)",
			doc.Stats.ValuesNotRedacted, doc.Unredacted[0].ReportedValues)
	}
	if !strings.Contains(doc.Unredacted[0].Cause, "no redactor") {
		t.Errorf("cause = %q, want the no-redactor classification for a PDF", doc.Unredacted[0].Cause)
	}
	// The findings themselves must survive: the refusal is about the WRITE, and losing
	// the findings would hide what is exposed.
	if doc.Stats.TotalFindings < 1 {
		t.Error("the run reported no findings, so the disclosure has nothing to be about")
	}
}

// A run with BOTH a coverage gap and a redaction refusal must state both, inside one
// frame, with the exit-code hint exactly once.
//
// Two blocks each ending in "Add --fail-on-incomplete …" reads as two separate policies
// when it is one escalation covering both.
func TestBothDisclosuresAppearOnceEach(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 000 does not deny reads on Windows")
	}
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	unreadable := filepath.Join(dir, "unreadable.txt")
	if err := os.WriteFile(unreadable, []byte("SSN 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	// The flag is deliberately NOT set here: the hint is only shown when escalation is
	// off, so this is the case where "exactly once" is a meaningful assertion.
	run := runRedaction(t, bin, dir, "text")

	if !strings.Contains(run.stdout, "NOT FULLY EXAMINED") {
		t.Errorf("the coverage gap is not disclosed\n%s", run.stdout)
	}
	if !strings.Contains(run.stdout, "VALUES LEFT IN CLEARTEXT") {
		t.Errorf("the redaction refusal is not disclosed\n%s", run.stdout)
	}
	if n := strings.Count(run.stdout, "--fail-on-incomplete"); n != 1 {
		t.Errorf("the exit-code hint appears %d times in one summary frame, want 1: both "+
			"disclosures feed the same escalation, so saying it twice reads as two policies\n%s",
			n, run.stdout)
	}
	// And with the flag, the same run escalates.
	gated := runRedaction(t, bin, dir, "text", "--fail-on-incomplete")
	if gated.rc != exitCodeIncompleteCoverage {
		t.Errorf("rc = %d, want %d when both a coverage gap and a refusal occurred",
			gated.rc, exitCodeIncompleteCoverage)
	}
	// With escalation on, neither block nags about the flag — but both disclosures remain.
	for _, want := range []string{"NOT FULLY EXAMINED", "VALUES LEFT IN CLEARTEXT"} {
		if !strings.Contains(gated.stdout, want) {
			t.Errorf("with the flag set, %q disappeared from the report\n%s", want, gated.stdout)
		}
	}
}

// --limit truncates the findings LIST; it must not shrink the reported exposure.
//
// The values are in cleartext whether or not the report chose to print each finding, so a
// consumer gating on the counters must see the true numbers.
func TestLimitDoesNotShrinkTheReportedExposure(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	full := runRedaction(t, bin, dir, "json")
	var fullDoc, limDoc struct {
		Stats struct {
			FilesNotRedacted  int `json:"files_not_redacted"`
			ValuesNotRedacted int `json:"values_not_redacted"`
		} `json:"stats"`
	}
	if err := json.Unmarshal([]byte(full.stdout), &fullDoc); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}

	limited := runRedaction(t, bin, dir, "json", "--limit", "1")
	if err := json.Unmarshal([]byte(limited.stdout), &limDoc); err != nil {
		t.Fatalf("unmarshal limited: %v", err)
	}

	if limDoc.Stats.FilesNotRedacted != fullDoc.Stats.FilesNotRedacted ||
		limDoc.Stats.ValuesNotRedacted != fullDoc.Stats.ValuesNotRedacted {
		t.Errorf("--limit changed the reported exposure: files %d->%d, values %d->%d. The values "+
			"are in cleartext regardless of how many findings the report printed",
			fullDoc.Stats.FilesNotRedacted, limDoc.Stats.FilesNotRedacted,
			fullDoc.Stats.ValuesNotRedacted, limDoc.Stats.ValuesNotRedacted)
	}
	if fullDoc.Stats.ValuesNotRedacted == 0 {
		t.Fatal("the baseline reports zero exposed values, so the comparison above is vacuous")
	}
}

// A scan that never asked for redaction must not gain the disclosure or the CSV columns.
//
// Read-only scanning is the common path, and a warning that appears when nothing could
// have been redacted is noise that trains people to ignore it.
func TestReadOnlyScanCarriesNoRedactionDisclosure(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	for _, format := range []string{"text", "json", "csv"} {
		t.Run(format, func(t *testing.T) {
			args := []string{
				"--file", dir, "--recursive", "--config", os.DevNull,
				"--format", format, "--limit", "0", "--quiet",
			}
			cmd := exec.Command(bin, args...)
			var so, se strings.Builder
			cmd.Stdout = &so
			cmd.Stderr = &se
			_ = cmd.Run()

			for _, bad := range []string{
				"VALUES LEFT IN CLEARTEXT", "files_not_redacted", "Not Redacted Reason",
			} {
				if strings.Contains(so.String(), bad) {
					t.Errorf("a read-only scan emitted %q in %s output:\n%s", bad, format, so.String())
				}
			}
		})
	}
}

// A file whose findings are ALL suppressed must not be reported as an exposure.
//
// The redactor still emits a diagnostic for it — there was no copy to write — but nothing
// was reported, so there is no reported exposure to disclose. Keeping the entry produced a
// self-contradiction, measured: "files_not_redacted=1" alongside "reported_values=0", and
// a VALUES LEFT IN CLEARTEXT banner for a file whose findings the operator had explicitly
// accepted.
//
// BOTH directions are asserted. Dropping zero-value entries relies on the diagnostic's
// path and the match's Filename being the same string; if that ever diverges, every entry
// would silently drop and the disclosure would vanish entirely — the dangerous direction.
// The second half of this test is what catches that.
func TestSuppressedFileIsNotReportedAsExposed(t *testing.T) {
	bin := buildForRedactionTest(t)
	dir := unredactableDir(t)

	// Direction 1: with nothing suppressed, the PDF IS reported as exposed. This is the
	// guard against the drop rule hiding real exposures.
	before := runRedaction(t, bin, dir, "json")
	requireRefusalHappened(t, before.stdout)

	// Generate suppressions with this same binary, then enable them all.
	supFile := filepath.Join(t.TempDir(), "sup.yaml")
	gen := exec.Command(bin, "--file", dir, "--recursive", "--config", os.DevNull,
		"--generate-suppressions", "--suppression-file", supFile, "--limit", "0", "--quiet")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("generate suppressions: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(supFile)
	if err != nil {
		t.Fatalf("read suppressions: %v", err)
	}
	enabled := strings.ReplaceAll(string(raw), "enabled: false", "enabled: true")
	if enabled == string(raw) {
		t.Fatal("no rules were generated, so the suppressed case below is vacuous")
	}
	if err := os.WriteFile(supFile, []byte(enabled), 0o600); err != nil {
		t.Fatalf("write suppressions: %v", err)
	}

	// Direction 2: with everything suppressed, no exposure is claimed.
	after := runRedaction(t, bin, dir, "json", "--suppression-file", supFile)

	var doc struct {
		Stats struct {
			TotalFindings    int `json:"total_findings"`
			Suppressed       int `json:"suppressed"`
			FilesNotRedacted int `json:"files_not_redacted"`
		} `json:"stats"`
		Unredacted []struct {
			ReportedValues int `json:"reported_values"`
		} `json:"unredacted"`
	}
	if err := json.Unmarshal([]byte(after.stdout), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, after.stdout)
	}

	if doc.Stats.Suppressed == 0 {
		t.Fatal("nothing was suppressed, so this test is not exercising the case")
	}
	if doc.Stats.TotalFindings != 0 {
		t.Fatalf("expected every finding suppressed, got %d reported", doc.Stats.TotalFindings)
	}
	if doc.Stats.FilesNotRedacted != 0 {
		t.Errorf("files_not_redacted = %d on a run where every finding was suppressed: the "+
			"disclosure counts REPORTED values, and none were reported",
			doc.Stats.FilesNotRedacted)
	}
	if len(doc.Unredacted) != 0 {
		t.Errorf("unredacted[] has %d entries with reported_values=%v — an exposure of zero "+
			"reported values is a contradiction", len(doc.Unredacted), doc.Unredacted)
	}

	// The text report must not show the banner either.
	text := runRedaction(t, bin, dir, "text", "--suppression-file", supFile)
	if strings.Contains(text.stdout, "VALUES LEFT IN CLEARTEXT") {
		t.Errorf("the text report claims an exposure for a fully suppressed file:\n%s", text.stdout)
	}
	// And it must not escalate the exit code.
	gated := runRedaction(t, bin, dir, "text", "--suppression-file", supFile, "--fail-on-incomplete")
	if gated.rc != 0 {
		t.Errorf("rc = %d on a fully suppressed run with --fail-on-incomplete, want 0", gated.rc)
	}
}

// An unwritable output directory must be reported as a WRITE failure, not as a missing
// redactor.
//
// The two need different remedies — one is the operator's filesystem, the other is a tool
// limitation — and this is the only cause whose classifier arm fires on an error the tool
// itself does not author.
func TestUnwritableOutputDirIsClassifiedAsAWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 500 does not deny directory writes on Windows")
	}
	bin := buildForRedactionTest(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("SSN 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "readonly")
	if err := os.MkdirAll(outDir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(outDir, 0o755) })

	cmd := exec.Command(bin, "--file", dir, "--recursive", "--config", os.DevNull,
		"--enable-redaction", "--redaction-output-dir", outDir,
		"--format", "json", "--limit", "0", "--quiet")
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	_ = cmd.Run()

	var doc struct {
		Unredacted []struct {
			Cause string `json:"cause"`
		} `json:"unredacted"`
	}
	if err := json.Unmarshal([]byte(so.String()), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, so.String())
	}
	if len(doc.Unredacted) != 1 {
		t.Fatalf("expected 1 unredacted entry for an unwritable output dir, got %d\n%s",
			len(doc.Unredacted), so.String())
	}
	if !strings.Contains(doc.Unredacted[0].Cause, "could not write") {
		t.Errorf("cause = %q, want a write failure: a filesystem problem must not be reported "+
			"as a missing redactor, because the remedies are unrelated", doc.Unredacted[0].Cause)
	}
}
