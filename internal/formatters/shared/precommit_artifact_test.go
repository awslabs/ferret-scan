// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	csvfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	jsonfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	yamlfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// #353, second defect: in pre-commit mode with no findings, an EXPLICITLY requested --output file
// was created and left empty.
//
// The formatters return an empty document in pre-commit mode when there is nothing to report, which
// is deliberate noise reduction on a developer's every commit — the mode signals out of band
// through the exit code and stderr. That reasoning holds for a terminal and not for a path the
// caller named: with --output the caller asked for a machine artifact and got zero bytes.
//
// Measured on the CLI before the fix, clean tree, --format json --output r.json:
//
//	ordinary run    237 bytes, valid JSON, results: []
//	PRE_COMMIT=1      0 bytes, JSONDecodeError
//
// Same shape as the bug #351 fixed for --format: an explicit request discarded by an inference the
// caller never opted into. Quiet mode governs console chatter, not whether a requested artifact
// exists.

type formatterUnderTest struct {
	name string
	f    formatters.Formatter
	// parse returns an error when the payload is not a well-formed document of this format.
	parse func(string) error
}

func formattersToTest() []formatterUnderTest {
	return []formatterUnderTest{
		{"json", jsonfmt.NewFormatter(), func(s string) error {
			var v map[string]any
			return json.Unmarshal([]byte(s), &v)
		}},
		{"yaml", yamlfmt.NewFormatter(), func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errEmpty
			}
			return nil
		}},
		{"csv", csvfmt.NewFormatter(), func(s string) error {
			_, err := csv.NewReader(strings.NewReader(s)).ReadAll()
			return err
		}},
	}
}

type emptyErr struct{}

func (emptyErr) Error() string { return "document is empty" }

var errEmpty = emptyErr{}

func opts(precommit, toFile bool) formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NoColor:         true,
		PrecommitMode:   precommit,
		OutputToFile:    toFile,
		Limit:           0,
	}
}

// TestAnExplicitlyRequestedArtifactIsAlwaysWritten is the regression test.
func TestAnExplicitlyRequestedArtifactIsAlwaysWritten(t *testing.T) {
	for _, fut := range formattersToTest() {
		t.Run(fut.name, func(t *testing.T) {
			// No findings — the case that produced zero bytes.
			out, err := fut.f.Format(nil, nil, opts(true, true))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if strings.TrimSpace(out) == "" {
				t.Fatalf("pre-commit mode with --output produced an EMPTY document.\n" +
					"The caller named a path and expects a parseable artifact there; zero bytes is " +
					"worse than a missing file because a consumer reads it as a parse error or as " +
					"no findings (#353).")
			}
			if err := fut.parse(out); err != nil {
				t.Errorf("the document is not well-formed %s: %v\n%q", fut.name, err, out)
			}
		})
	}
}

// TestPrecommitStaysQuietOnTheConsole is the other direction, and it is the behaviour the empty
// return exists to provide. Silencing a clean commit on the terminal is deliberate; the fix must
// not take that away.
func TestPrecommitStaysQuietOnTheConsole(t *testing.T) {
	for _, fut := range formattersToTest() {
		t.Run(fut.name, func(t *testing.T) {
			out, err := fut.f.Format(nil, nil, opts(true, false))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if strings.TrimSpace(out) != "" {
				t.Errorf("pre-commit mode with no findings and no --output produced %d bytes; it "+
					"is meant to stay silent on a developer's every commit:\n%q", len(out), out)
			}
		})
	}
}

// TestOutputToFileChangesNothingWhenThereAreFindings bounds the blast radius: the new field must
// only affect the empty case, since that is the only place the early return fires.
func TestOutputToFileChangesNothingWhenThereAreFindings(t *testing.T) {
	m := []detector.Match{{
		Text:       "452-11-9384",
		Type:       "SSN",
		Confidence: 95,
		Filename:   "f.txt",
		LineNumber: 1,
		Validator:  "ssn",
		Context:    detector.ContextInfo{FullLine: "SSN: 452-11-9384"},
	}}
	for _, fut := range formattersToTest() {
		t.Run(fut.name, func(t *testing.T) {
			toFile, err := fut.f.Format(m, nil, opts(true, true))
			if err != nil {
				t.Fatalf("Format(toFile): %v", err)
			}
			toConsole, err := fut.f.Format(m, nil, opts(true, false))
			if err != nil {
				t.Fatalf("Format(toConsole): %v", err)
			}
			if toFile != toConsole {
				t.Errorf("OutputToFile changed the document for a run WITH findings.\n"+
					"It must only govern the empty case.\n  toFile:    %q\n  toConsole: %q",
					toFile, toConsole)
			}
			if strings.TrimSpace(toFile) == "" {
				t.Error("a run with findings produced an empty document, so this comparison is vacuous")
			}
		})
	}
}

// TestOrdinaryModeIsUnaffected: outside pre-commit mode the field must be inert, so an ordinary
// run is byte-identical whichever way its output is going.
func TestOrdinaryModeIsUnaffected(t *testing.T) {
	for _, fut := range formattersToTest() {
		t.Run(fut.name, func(t *testing.T) {
			a, err := fut.f.Format(nil, nil, opts(false, false))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			b, err := fut.f.Format(nil, nil, opts(false, true))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if a != b {
				t.Errorf("OutputToFile changed the document outside pre-commit mode:\n  %q\n  %q", a, b)
			}
			if strings.TrimSpace(a) == "" {
				t.Errorf("an ordinary clean run produced an empty document; it should carry the "+
					"coverage stats: %q", a)
			}
		})
	}
}
