// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// #879: the context analyzer's document adjustment (tabular_boost +20 in a CSV, TSV or FixedWidth
// document, test_data_penalty -30) reached a secrets finding twice, once inside this validator's
// score and once more in the document bridge, which applies it to every validator's findings.
// Measured with the CLI on main: `token = getToken()` scored 75 in a key=value file and 100 as a
// cell of a 14-row TSV, where dropping the file's Configuration +15 and adding one +20 is 80.
//
// Everything in this file uses only symbols main also has, so it compiles against main and fails
// there by assertion.

const plainConfigFixture = "host = db.internal\n" +
	"port = 5432\n" +
	"token = getToken()\n" +
	"user = svc\n" +
	"timeout = 30\n"

// tabularFixture is the issue's TSV: an id/setting/note header and 14 rows, one of which holds
// cell on row 7 (line 8). Every other row is an inert retries setting.
func tabularFixture(sep, cell string) string {
	var b strings.Builder
	b.WriteString("id" + sep + "setting" + sep + "note\n")
	for i := 1; i <= 14; i++ {
		setting := fmt.Sprintf("retries = %d", i)
		if i == 7 {
			setting = cell
		}
		fmt.Fprintf(&b, "%d%s%s%srow %d\n", i, sep, setting, sep, i)
	}
	return b.String()
}

// scanThroughBridge runs the validator the way a scan does: behind the Detector facade, whose
// document bridge applies the context adjustment after the validator returns.
func scanThroughBridge(t *testing.T, filename, content string) []detector.Match {
	t.Helper()
	d := validators.NewDetector(nil)
	if err := d.SetupValidators(map[string]detector.Validator{"SECRETS": NewValidator()}); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}
	matches, err := d.ValidateProcessedContent(&preprocessors.ProcessedContent{
		OriginalPath:  filename,
		Filename:      filename,
		Text:          content,
		Format:        "Plain Text",
		ProcessorType: "plaintext",
		Success:       true,
	})
	if err != nil {
		t.Fatalf("ValidateProcessedContent: %v", err)
	}
	return matches
}

// onlyFindingOnLine returns the single secrets finding on line, failing the test when there is
// not exactly one.
func onlyFindingOnLine(t *testing.T, what string, matches []detector.Match, line int) detector.Match {
	t.Helper()
	var found []detector.Match
	for _, m := range matches {
		if m.Validator == "secrets" && m.LineNumber == line {
			found = append(found, m)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one secrets finding on line %d, got %d (all: %+v)", what, line, len(found), matches)
	}
	return found[0]
}

func metaFloat(t *testing.T, m detector.Match, key string) float64 {
	t.Helper()
	raw, ok := m.Metadata[key]
	if !ok {
		t.Fatalf("finding on line %d has no %s metadata", m.LineNumber, key)
	}
	f, ok := raw.(float64)
	if !ok {
		t.Fatalf("finding on line %d: %s is %T, want float64", m.LineNumber, key, raw)
	}
	return f
}

// TestDocumentContextAdjustmentIsAppliedOnce pins the issue's reproduction end to end. The TSV
// finding is the plain one without the validator's own Configuration +15 and with ONE
// tabular_boost: 75 - 15 + 20 = 80 (main: 100). And the metadata accounts for the whole stack:
// what the TSV added over the docType-neutral score is exactly confidence_adjustment (main: 40
// applied, 20 recorded).
func TestDocumentContextAdjustmentIsAppliedOnce(t *testing.T) {
	plain := onlyFindingOnLine(t, "plain", scanThroughBridge(t, "settings.conf", plainConfigFixture), 3)
	tsv := onlyFindingOnLine(t, "tsv", scanThroughBridge(t, "settings.tsv", tabularFixture("\t", "token = getToken()")), 8)

	if got := plain.Metadata["context_doctype"]; got != "Configuration" {
		t.Fatalf("precondition: plain file typed %v, want Configuration", got)
	}
	if got := tsv.Metadata["context_doctype"]; got != "TSV" {
		t.Fatalf("precondition: tabular file typed %v, want TSV", got)
	}
	if adj := metaFloat(t, plain, "confidence_adjustment"); adj != 0 {
		t.Fatalf("precondition: plain file's document adjustment = %v, want 0", adj)
	}
	adj := metaFloat(t, tsv, "confidence_adjustment")
	if adj != 20 {
		t.Fatalf("precondition: TSV document adjustment = %v, want the one tabular_boost, 20", adj)
	}
	if plain.Confidence != 75 {
		t.Fatalf("precondition: plain-file score = %v, want 75 (the issue's)", plain.Confidence)
	}

	neutral := plain.Confidence - 15 // the plain file's score without its Configuration +15
	if want := neutral + 20; tsv.Confidence != want {
		t.Errorf("TSV cell scored %v, want %v: the plain score %v, less the Configuration +15, plus one tabular_boost", tsv.Confidence, want, plain.Confidence)
	}
	if stack := tsv.Confidence - neutral; stack != adj {
		t.Errorf("the TSV added %v over the docType-neutral score, but confidence_adjustment records %v", stack, adj)
	}
	if orig := metaFloat(t, tsv, "original_confidence"); orig+adj != tsv.Confidence {
		t.Errorf("original_confidence %v + confidence_adjustment %v != confidence %v", orig, adj, tsv.Confidence)
	}
}

// TestValidatorScoreLeavesTheDocumentAdjustmentToTheBridge pins the mechanism: called directly,
// the validator reports the TSV cell at its docType-neutral 60 (main: 80, the +20 already in).
func TestValidatorScoreLeavesTheDocumentAdjustmentToTheBridge(t *testing.T) {
	v := NewValidator()
	matches, err := v.ValidateContent(tabularFixture("\t", "token = getToken()"), "settings.tsv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	m := onlyFindingOnLine(t, "validator alone", matches, 8)
	if m.Confidence != 60 {
		t.Errorf("validator scored the TSV cell %v, want 60: the bridge adds tabular_boost, the validator must not", m.Confidence)
	}
}

// TestTabularDocumentKeepsTheReportingThreshold is the recall control for the fix. Deleting the
// validator's +20 alone also moved its reporting threshold: these credentials score exactly 60
// without it, the keyword path reports above 60, and a TSV or CSV cell holding one reported
// NOTHING, so it was never redacted, where main reported 100 and the plain file 75. The
// threshold is judged on the score the bridge reports, so each is still reported, at 80.
func TestTabularDocumentKeepsTheReportingThreshold(t *testing.T) {
	cells := []string{
		"password = summer2024",
		"password = Winter2023!",
		"password = letmein99",
		"db_password = svcorders1",
		"passwd = Tr0ub4dor&3",
	}
	for _, cell := range cells {
		plain := onlyFindingOnLine(t, cell+" (plain)", scanThroughBridge(t, "settings.conf", "host = db.internal\n"+cell+"\nport = 5432\n"), 2)
		for _, f := range []struct{ name, sep string }{{"settings.tsv", "\t"}, {"settings.csv", ","}} {
			tab := onlyFindingOnLine(t, cell+" ("+f.name+")", scanThroughBridge(t, f.name, tabularFixture(f.sep, cell)), 8)
			if want := plain.Confidence - 15 + 20; tab.Confidence != want {
				t.Errorf("%q in %s scored %v, want %v (plain %v - 15 + one tabular_boost)", cell, f.name, tab.Confidence, want, plain.Confidence)
			}
		}
	}
}

// TestTestDataPenaltyIsAppliedOnce covers the other key GetConfidenceAdjustment reads. A document
// whose prose names five of the analyzer's eight test-data phrases takes test_data_penalty -30,
// once. The reference is the same file without the phrase line: the phrase line is a comment, so
// the document type and the line's own score do not move, and the keyword corroborates the
// value, so the file-wide test verdict does not move it either (#785).
func TestTestDataPenaltyIsAppliedOnce(t *testing.T) {
	const cred = `password = "Zq7Xk2Lm9Pw4Rt8V"`
	body := "host = db.internal\nport = 5432\n" + cred + "\nuser = svc\n"
	phrases := "# test data, sample data, dummy data, mock data, test case\n"

	ref := onlyFindingOnLine(t, "reference", scanThroughBridge(t, "settings.conf", body), 3)
	pen := onlyFindingOnLine(t, "test-data document", scanThroughBridge(t, "settings.conf", phrases+body), 4)

	if adj := metaFloat(t, ref, "confidence_adjustment"); adj != 0 {
		t.Fatalf("precondition: reference document adjustment = %v, want 0", adj)
	}
	adj := metaFloat(t, pen, "confidence_adjustment")
	if adj != -30 {
		t.Fatalf("precondition: test-data document adjustment = %v, want test_data_penalty, -30", adj)
	}
	if got, want := pen.Metadata["context_doctype"], ref.Metadata["context_doctype"]; got != want {
		t.Fatalf("precondition: the phrase line moved the document type, %v -> %v", want, got)
	}
	if want := ref.Confidence + adj; pen.Confidence != want {
		t.Errorf("test-data document scored %v, want %v: the reference %v with ONE test_data_penalty", pen.Confidence, want, ref.Confidence)
	}
}
