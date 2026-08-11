// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/formatters/shared"
)

// JUnit XML structures based on the standard JUnit XML schema
type TestSuites struct {
	XMLName    xml.Name    `xml:"testsuites"`
	Name       string      `xml:"name,attr"`
	Tests      int         `xml:"tests,attr"`
	Failures   int         `xml:"failures,attr"`
	Errors     int         `xml:"errors,attr"`
	Time       string      `xml:"time,attr"`
	TestSuites []TestSuite `xml:"testsuite"`
}

type TestSuite struct {
	XMLName   xml.Name   `xml:"testsuite"`
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Errors    int        `xml:"errors,attr"`
	Time      string     `xml:"time,attr"`
	TestCases []TestCase `xml:"testcase"`

	// SystemOut carries suite-level informational detail, the same standard
	// <system-out> element TestCase already uses for suppressed findings. It is
	// used here to declare that --limit dropped findings and what the real total
	// was, because JUnit has no field for "this report is partial" and the
	// tests/failures attributes describe the report rather than the scan.
	//
	// omitempty keeps a complete report byte-for-byte unchanged.
	SystemOut string `xml:"system-out,omitempty"`
}

type TestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Name      string   `xml:"name,attr"`
	ClassName string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *Failure `xml:"failure,omitempty"`

	// Skipped marks a file that was NOT examined: the standard, non-failing JUnit
	// element. Used by default for unexamined files so a disclosure cannot turn a
	// green pipeline red on its own.
	Skipped *Skipped `xml:"skipped,omitempty"`

	// Error marks an unexamined file when --fail-on-incomplete is set, so the XML
	// verdict agrees with the process exit code (3) instead of contradicting it.
	//
	// Distinct from Failure: a failure means the tool found something wrong IN the
	// file; an error means the tool could not evaluate the file at all. Reporting
	// "cannot read" as a PII finding would be a fabricated finding.
	Error *Failure `xml:"error,omitempty"`
	// SystemOut carries informational, non-failing detail (the standard JUnit
	// <system-out> element). Suppressed findings use it so they convey their
	// detail without being reported as failures.
	SystemOut string `xml:"system-out,omitempty"`
}

type Failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}

// Skipped is the standard non-failing JUnit element, used for files that were not
// examined.
//
// No `type` attribute: the JUnit 10 XSD declares only `message` on <skipped>, unlike
// <failure> and <error> which also carry `type`. Adding one would make the document
// fail schema validation, and Jenkins' xunit-plugin validates against that XSD and
// rejects the WHOLE file rather than the offending element.
type Skipped struct {
	Message string `xml:"message,attr"`
	Content string `xml:",chardata"`
}

// Formatter implements JUnit XML output formatting
type Formatter struct{}

// NewFormatter creates a new JUnit XML formatter
func NewFormatter() *Formatter {
	return &Formatter{}
}

func (f *Formatter) Name() string {
	return "junit"
}

func (f *Formatter) Description() string {
	return "JUnit XML format for CI/CD integration and test reporting"
}

func (f *Formatter) FileExtension() string {
	return ".xml"
}

func (f *Formatter) Format(matches []detector.Match, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) (string, error) {
	// Filter matches by confidence level
	filteredMatches := f.filterMatchesByConfidence(matches, options)

	// Give the findings the shared total order before grouping, so the detail
	// lines inside each <failure> are emitted in a fixed sequence. Safe to sort
	// in place: the filter above returned a fresh slice.
	shared.SortMatchesByPriority(filteredMatches)

	// Suppressed testcases share the active findings' total order, so re-running
	// the same scan produces a comparable report rather than one whose skipped
	// testcases moved around.
	shared.SortSuppressedByPriority(suppressedMatches)

	// Honor --limit before grouping, so the per-file <testcase> split and the
	// suite's Tests/Failures counters describe the findings the report actually
	// carries.
	filteredMatches, totalFindings, truncated := shared.ApplyLimit(filteredMatches, options)

	// Group matches by file for better organization
	fileGroups := f.groupMatchesByFile(filteredMatches)

	// Create test suites structure
	testSuites := TestSuites{
		Name:       "ferret-scan",
		Tests:      0,
		Failures:   0,
		Errors:     0,
		Time:       "0.000",
		TestSuites: []TestSuite{},
	}

	// Create a test suite for security findings
	securitySuite := TestSuite{
		Name:      "security-scan",
		Tests:     0,
		Failures:  0,
		Errors:    0,
		Time:      "0.000",
		TestCases: []TestCase{},
	}

	// Process each file, in sorted filename order. Ranging the group map
	// directly reordered the <testcase> elements between runs, so two JUnit
	// reports of one unchanged scan were not comparable — and CI systems that
	// diff or fingerprint the report treated the reshuffle as new results.
	for _, filename := range sortedKeys(fileGroups) {
		testCase := f.createTestCaseForFile(filename, fileGroups[filename], options)
		securitySuite.TestCases = append(securitySuite.TestCases, testCase)
		securitySuite.Tests++

		if testCase.Failure != nil {
			securitySuite.Failures++
		}
	}

	// Add suppressed matches as separate test cases if requested
	if len(suppressedMatches) > 0 {
		suppressedSuite := TestSuite{
			Name:      "suppressed-findings",
			Tests:     0,
			Failures:  0,
			Errors:    0,
			Time:      "0.000",
			TestCases: []TestCase{},
		}

		suppressedGroups := f.groupSuppressedMatchesByFile(suppressedMatches)
		for _, filename := range sortedKeys(suppressedGroups) {
			testCase := f.createTestCaseForSuppressedFile(filename, suppressedGroups[filename], options)
			suppressedSuite.TestCases = append(suppressedSuite.TestCases, testCase)
			suppressedSuite.Tests++
		}

		if suppressedSuite.Tests > 0 {
			testSuites.TestSuites = append(testSuites.TestSuites, suppressedSuite)
			testSuites.Tests += suppressedSuite.Tests
		}
	}

	// Add the main security suite
	// Say so when --limit dropped findings.
	//
	// Without this the report is indistinguishable from a complete one: the
	// tests/failures attributes count what the report CARRIES, so a CI job reading
	// them sees the capped number and nothing anywhere says more findings existed.
	// Silently under-reporting is worse than reporting nothing, because the count
	// looks authoritative. text/json/yaml already disclose this.
	if truncated {
		// Count FINDINGS, not testcases. JUnit groups findings by file, so a
		// 3-finding cap inside one file produces a single <testcase> — reporting
		// len(TestCases) said "showing 1 of 36" for a --limit 3 run, which is a
		// different and wronger claim than the one being fixed.
		securitySuite.SystemOut = fmt.Sprintf(
			"ferret-scan: output truncated by --limit. Showing %d of %d findings. "+
				"Re-run with --limit 0 for the complete set.",
			len(filteredMatches), totalFindings)
	}

	testSuites.TestSuites = append(testSuites.TestSuites, securitySuite)
	testSuites.Tests += securitySuite.Tests
	testSuites.Failures += securitySuite.Failures

	// Declare the files that were NOT examined, as their own suite.
	//
	// Appended AFTER the security suite so the findings stay first in the report,
	// and unconditionally — a scan with zero findings and unreadable files is
	// exactly the case where this must appear.
	//
	// Rolls up Tests and Errors ONLY. There is deliberately no `skipped` attribute
	// on <testsuites>: the JUnit 10 XSD does not declare one there (it exists on
	// <testsuite>), so adding it makes the document fail validation — measured, and
	// Jenkins' xunit-plugin rejects the whole file rather than the bad attribute.
	// The skipped count therefore lives on the suite alone, which is both valid and
	// where consumers look for it.
	if notExaminedSuite, ok := buildNotExaminedSuite(options); ok {
		testSuites.TestSuites = append(testSuites.TestSuites, notExaminedSuite)
		testSuites.Tests += notExaminedSuite.Tests
		testSuites.Errors += notExaminedSuite.Errors
	}

	// Generate XML
	xmlData, err := xml.MarshalIndent(testSuites, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JUnit XML: %w", err)
	}

	// Add XML declaration
	return xml.Header + string(xmlData), nil
}

// filterMatchesByConfidence filters matches based on confidence level settings
func (f *Formatter) filterMatchesByConfidence(matches []detector.Match, options formatters.FormatterOptions) []detector.Match {
	var filtered []detector.Match
	for _, match := range matches {
		if (match.Confidence >= 90 && options.ConfidenceLevel["high"]) ||
			(match.Confidence >= 60 && match.Confidence < 90 && options.ConfidenceLevel["medium"]) ||
			(match.Confidence < 60 && options.ConfidenceLevel["low"]) {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// sortedKeys returns a group map's filenames in ascending order, so the
// <testcase> elements derived from them are emitted in a fixed sequence.
func sortedKeys[V any](groups map[string]V) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// groupMatchesByFile groups matches by filename
func (f *Formatter) groupMatchesByFile(matches []detector.Match) map[string][]detector.Match {
	groups := make(map[string][]detector.Match)
	for _, match := range matches {
		groups[match.Filename] = append(groups[match.Filename], match)
	}
	return groups
}

// groupSuppressedMatchesByFile groups suppressed matches by filename
func (f *Formatter) groupSuppressedMatchesByFile(suppressedMatches []detector.SuppressedMatch) map[string][]detector.SuppressedMatch {
	groups := make(map[string][]detector.SuppressedMatch)
	for _, suppressed := range suppressedMatches {
		filename := suppressed.Match.Filename
		groups[filename] = append(groups[filename], suppressed)
	}
	return groups
}

// createTestCaseForFile creates a JUnit test case for a file with its matches
func (f *Formatter) createTestCaseForFile(filename string, matches []detector.Match, options formatters.FormatterOptions) TestCase {
	basename := filepath.Base(filename)

	testCase := TestCase{
		Name:      basename,
		ClassName: "security-scan",
		Time:      "0.001",
	}

	if len(matches) > 0 {
		// File has security findings - create failure
		failure := f.createFailureFromMatches(matches, options)
		testCase.Failure = &failure
	}
	// If no matches, the test case passes (no failure element)

	return testCase
}

// createTestCaseForSuppressedFile creates a JUnit test case for suppressed findings
func (f *Formatter) createTestCaseForSuppressedFile(filename string, suppressedMatches []detector.SuppressedMatch, options formatters.FormatterOptions) TestCase {
	basename := filepath.Base(filename)

	// Suppressed findings don't create failures - they're informational - so
	// their detail goes in <system-out> rather than <failure>. We still honor
	// --show-match here so the matched value surfaces exactly when the operator
	// opts in, matching the active-finding path and every other formatter; the
	// default (no --show-match) emits type/line/confidence only, never the value.
	var out strings.Builder
	for i, suppressed := range suppressedMatches {
		if i > 0 {
			out.WriteString("\n")
		}
		match := suppressed.Match
		out.WriteString(fmt.Sprintf("Line %d: %s suppressed by %s (%.1f%%)",
			match.LineNumber, match.Type, suppressed.SuppressedBy, match.Confidence))
		if suppressed.RuleReason != "" {
			out.WriteString(fmt.Sprintf(" - %s", suppressed.RuleReason))
		}
		if options.ShowMatch {
			out.WriteString(fmt.Sprintf("\nMatch: %s", match.Text))
			// FullLine carries the raw value; gate on ShowMatch too (consistent
			// with the active path) so --verbose never re-leaks when hidden.
			if options.Verbose && match.Context.FullLine != "" {
				out.WriteString(fmt.Sprintf("\nContext: %s", match.Context.FullLine))
			}
		}
	}

	return TestCase{
		Name:      basename + " (suppressed)",
		ClassName: "suppressed-findings",
		Time:      "0.001",
		SystemOut: out.String(),
	}
}

// createFailureFromMatches creates a JUnit failure from security matches
func (f *Formatter) createFailureFromMatches(matches []detector.Match, options formatters.FormatterOptions) Failure {
	var messageBuilder strings.Builder
	var contentBuilder strings.Builder

	// Matches arrive already in the shared total order (Format sorts before
	// grouping, and grouping preserves it), so no re-sort is needed here. The
	// local bubble sort this replaced ordered only on confidence band and score,
	// which left same-confidence findings in whatever order the scanner produced.

	// Create summary message
	if len(matches) == 1 {
		match := matches[0]
		messageBuilder.WriteString(fmt.Sprintf("%s found", match.Type))
		if options.ShowMatch {
			messageBuilder.WriteString(fmt.Sprintf(": %s", match.Text))
		}
	} else {
		messageBuilder.WriteString(fmt.Sprintf("%d security findings detected", len(matches)))
	}

	// Create detailed content
	for i, match := range matches {
		if i > 0 {
			contentBuilder.WriteString("\n")
		}

		confidenceLevel := f.getConfidenceLevel(match.Confidence)
		contentBuilder.WriteString(fmt.Sprintf("Line %d: %s detected with %.1f%% confidence (%s)",
			match.LineNumber, match.Type, match.Confidence, confidenceLevel))

		if options.ShowMatch {
			contentBuilder.WriteString(fmt.Sprintf("\nMatch: %s", match.Text))
		}

		// Gated on ShowMatch too: FullLine contains the raw matched value, so
		// emitting it when ShowMatch is false would re-leak the hidden secret
		// (consistent with the JSON/YAML/SARIF/text formatters).
		if options.Verbose && options.ShowMatch && match.Context.FullLine != "" {
			contentBuilder.WriteString(fmt.Sprintf("\nContext: %s", match.Context.FullLine))
		}

		// Add validator information
		contentBuilder.WriteString(fmt.Sprintf("\nValidator: %s", match.Validator))
	}

	return Failure{
		Message: messageBuilder.String(),
		Type:    f.getFailureType(matches),
		Content: contentBuilder.String(),
	}
}

// getFailureType determines the failure type based on matches
func (f *Formatter) getFailureType(matches []detector.Match) string {
	if len(matches) == 1 {
		return matches[0].Type
	}

	// Multiple matches - use a generic type
	return "SECURITY_FINDINGS"
}

// getConfidenceLevel returns the confidence level as a string
func (f *Formatter) getConfidenceLevel(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Register the formatter during package initialization
func init() {
	formatters.Register(NewFormatter())
}
