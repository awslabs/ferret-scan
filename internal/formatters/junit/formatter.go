// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/formatters"
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
}

type TestCase struct {
	XMLName   xml.Name `xml:"testcase"`
	Name      string   `xml:"name,attr"`
	ClassName string   `xml:"classname,attr"`
	Time      string   `xml:"time,attr"`
	Failure   *Failure `xml:"failure,omitempty"`
}

type Failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
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

	// Process each file
	for filename, fileMatches := range fileGroups {
		testCase := f.createTestCaseForFile(filename, fileMatches, options)
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
		for filename, suppressed := range suppressedGroups {
			testCase := f.createTestCaseForSuppressedFile(filename, suppressed, options)
			suppressedSuite.TestCases = append(suppressedSuite.TestCases, testCase)
			suppressedSuite.Tests++
		}

		if suppressedSuite.Tests > 0 {
			testSuites.TestSuites = append(testSuites.TestSuites, suppressedSuite)
			testSuites.Tests += suppressedSuite.Tests
		}
	}

	// Add the main security suite
	testSuites.TestSuites = append(testSuites.TestSuites, securitySuite)
	testSuites.Tests += securitySuite.Tests
	testSuites.Failures += securitySuite.Failures

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

	return TestCase{
		Name:      basename + " (suppressed)",
		ClassName: "suppressed-findings",
		Time:      "0.001",
		// Suppressed findings don't create failures - they're informational
	}
}

// createFailureFromMatches creates a JUnit failure from security matches
func (f *Formatter) createFailureFromMatches(matches []detector.Match, options formatters.FormatterOptions) Failure {
	var messageBuilder strings.Builder
	var contentBuilder strings.Builder

	// Sort matches by confidence level for consistent output
	f.sortMatches(matches)

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

		if options.Verbose && match.Context.FullLine != "" {
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

// sortMatches sorts matches by confidence level (HIGH, MEDIUM, LOW) and then by confidence score
func (f *Formatter) sortMatches(matches []detector.Match) {
	// Sort using a custom comparison function
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			// Get confidence levels
			level1 := f.getConfidenceLevel(matches[i].Confidence)
			level2 := f.getConfidenceLevel(matches[j].Confidence)

			// Define level priority (lower number = higher priority)
			levelPriority := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}

			// Compare by level first
			if levelPriority[level1] > levelPriority[level2] {
				// Swap if level1 has lower priority than level2
				matches[i], matches[j] = matches[j], matches[i]
			} else if levelPriority[level1] == levelPriority[level2] {
				// Same level, sort by confidence score (higher first)
				if matches[i].Confidence < matches[j].Confidence {
					matches[i], matches[j] = matches[j], matches[i]
				}
			}
		}
	}
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
