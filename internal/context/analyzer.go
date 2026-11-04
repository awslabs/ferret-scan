// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// ContextAnalyzer provides advanced context analysis for all validators
type ContextAnalyzer struct {
	// Document structure patterns
	structureDetector *StructureDetector

	// Domain classification patterns
	domainClassifier *DomainClassifier

	// Semantic pattern analysis
	semanticPatterns map[string][]string

	// Cross-validator insights
	crossValidatorPatterns map[string]CrossValidatorPattern
}

// ContextInsights provides comprehensive context analysis results
type ContextInsights struct {
	DocumentType          string
	Domain                string
	StructureConfidence   float64
	DomainConfidence      float64
	SemanticContext       map[string]float64
	CrossValidatorSignals []CrossValidatorSignal
	ConfidenceAdjustments map[string]float64
	MetaInformation       map[string]interface{}
}

// CrossValidatorSignal represents insights from analyzing multiple data types
type CrossValidatorSignal struct {
	ValidatorType string
	SignalType    string
	Confidence    float64
	Evidence      string
	Impact        float64
}

// CrossValidatorPattern defines patterns that span multiple validators
type CrossValidatorPattern struct {
	Name        string
	Validators  []string
	Pattern     *regexp.Regexp
	Confidence  float64
	Description string
}

// StructureDetector identifies document structure and format
type StructureDetector struct {
	patterns map[string]structurePattern
}

// DomainClassifier identifies the business domain/industry context
type DomainClassifier struct {
	domainKeywords map[string][]string
	confidence     map[string]float64
}

// NewContextAnalyzer creates a new enhanced context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	ca := &ContextAnalyzer{
		structureDetector:      NewStructureDetector(),
		domainClassifier:       NewDomainClassifier(),
		semanticPatterns:       initSemanticPatterns(),
		crossValidatorPatterns: initCrossValidatorPatterns(),
	}

	return ca
}

// AnalyzeContext performs comprehensive context analysis
func (ca *ContextAnalyzer) AnalyzeContext(content string, filePath string) ContextInsights {
	insights := ContextInsights{
		SemanticContext:       make(map[string]float64),
		ConfidenceAdjustments: make(map[string]float64),
		MetaInformation:       make(map[string]interface{}),
	}

	// Document structure analysis
	docType, structureConf := ca.structureDetector.DetectStructure(content, filePath)
	insights.DocumentType = docType
	insights.StructureConfidence = structureConf

	// Domain classification
	domain, domainConf := ca.domainClassifier.ClassifyDomain(content)
	insights.Domain = domain
	insights.DomainConfidence = domainConf

	// Semantic pattern analysis
	insights.SemanticContext = ca.analyzeSemanticPatterns(content)

	// Cross-validator signal detection
	insights.CrossValidatorSignals = ca.detectCrossValidatorSignals(content)

	// Generate confidence adjustments
	insights.ConfidenceAdjustments = ca.calculateConfidenceAdjustments(insights)

	// Extract meta information
	insights.MetaInformation = ca.extractMetaInformation(content, filePath)

	return insights
}

// NewStructureDetector creates a document structure detector.
//
// The Configuration pattern allows leading whitespace (#788): a key under an INI `[section]` or in a
// YAML map is as much a configuration line as one at column 0, and anchoring at column 0 typed the
// same keys Configuration or Unknown on their indentation alone.
//
// CSV and TSV are not patterns: a line with two commas or two tabs is not a table row on its own
// (#849). See delimitedShare.
//
// Each pattern carries a necessary condition, tested first because it is cheap. The shares are taken
// over the whole document since #849, and the four case-insensitive patterns cost about 5 µs a line
// each in Go's regexp: over 2000 lines every pattern together cost 31 to 59 ms, against 0.8 ms for the
// 2000-character sample they used to see. A line the condition rejects cannot match the pattern and a
// line it accepts is matched against it, so the condition moves no share
// (TestStructurePrefiltersAreNecessaryConditions).
func NewStructureDetector() *StructureDetector {
	patterns := map[string]structurePattern{
		"JSON": {re: regexp.MustCompile(`^\s*[\{\[].*[\}\]]\s*$`)},
		"XML": {re: regexp.MustCompile(`<\?xml|<[a-zA-Z][^>]*>`),
			may: func(line, _ string) bool { return strings.IndexByte(line, '<') >= 0 }},
		"SQL": {re: regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b`),
			may: containsAnyWord("select", "insert", "update", "delete", "create", "alter", "drop")},
		"Log": {re: regexp.MustCompile(`\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}`),
			may: func(line, _ string) bool {
				return strings.IndexByte(line, '-') >= 0 && strings.IndexByte(line, ':') >= 0
			}},
		"Email": {re: regexp.MustCompile(`(?i)(from:|to:|subject:|date:)`),
			may: containsAnyWord("from:", "to:", "subject:", "date:")},
		"Code": {re: regexp.MustCompile(`(?i)(function|class|import|include|def\s)`),
			may: containsAnyWord("function", "class", "import", "include", "def")},
		// At least 20+3+20+3 characters, and a run of three whitespace characters.
		"FixedWidth": {re: regexp.MustCompile(`(?m)^.{20,}\s{3,}.{20,}\s{3,}.*$`),
			may: func(line, _ string) bool { return len(line) >= 46 && hasWhitespaceRun(line, 3) }},
		"Report": {re: regexp.MustCompile(`(?i)(report|summary|total|subtotal|balance)`),
			may: containsAnyWord("report", "summary", "total", "balance")},
		"Configuration": {re: regexp.MustCompile(`(?m)^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[=:]\s*.*$`),
			may: func(line, _ string) bool { return strings.ContainsAny(line, "=:") }},
	}

	return &StructureDetector{patterns: patterns}
}

// structurePattern is the line pattern of one structure type.
type structurePattern struct {
	re *regexp.Regexp
	// may is a necessary condition for re, consulted only for an ASCII line: a line it rejects cannot
	// match re, and a line it accepts is matched against re. lower is the line lowercased. On an ASCII
	// line a `(?i)` literal matches exactly its ASCII case variants, so a lowercase substring test
	// loses no match there; on any other line Unicode case folding can match more (`ſ` folds to `s`,
	// the Kelvin sign to `k`), so the condition is skipped. nil means always match against re.
	may func(line, lower string) bool
}

// containsAnyWord returns a condition true when the lowercased line contains one of words.
func containsAnyWord(words ...string) func(line, lower string) bool {
	return func(_, lower string) bool {
		for _, w := range words {
			if strings.Contains(lower, w) {
				return true
			}
		}
		return false
	}
}

// hasWhitespaceRun reports whether line holds n consecutive bytes of RE2's `\s` class, [\t\n\f\r ].
func hasWhitespaceRun(line string, n int) bool {
	run := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ' ', '\t', '\n', '\f', '\r':
			if run++; run >= n {
				return true
			}
		default:
			run = 0
		}
	}
	return false
}

// lowerASCII returns the line lowercased and true when every byte of it is ASCII, else "" and false.
func lowerASCII(line string) (string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] >= utf8.RuneSelf {
			return "", false
		}
	}
	return strings.ToLower(line), true
}

// DetectStructure identifies the document structure type
func (sd *StructureDetector) DetectStructure(content, filePath string) (string, float64) {
	// Check file extension hints first
	if strings.HasSuffix(strings.ToLower(filePath), ".csv") {
		return "CSV", 0.9
	}
	if strings.HasSuffix(strings.ToLower(filePath), ".json") {
		return "JSON", 0.9
	}
	if strings.HasSuffix(strings.ToLower(filePath), ".xml") {
		return "XML", 0.9
	}

	lines := structureSample(content)

	// Count each pattern's matching lines, one pass over the sample. The Configuration share is
	// taken over the configuration lines only (see isConfigurationLine), every other share over
	// every sampled line.
	matches := make(map[string]int, len(sd.patterns))
	configLines := 0
	commas := make(map[int]int)
	tabs := make(map[int]int)
	for _, line := range lines {
		isConfig := isConfigurationLine(line)
		if isConfig {
			configLines++
		}
		lower, ascii := lowerASCII(line)
		for structType, p := range sd.patterns {
			if structType == "Configuration" && !isConfig {
				continue
			}
			if ascii && p.may != nil && !p.may(line, lower) {
				continue
			}
			if p.re.MatchString(line) {
				matches[structType]++
			}
		}
		if n := delimiterCount(line, ','); n >= 2 && !endsSentence(line) {
			commas[n]++
		}
		if n := delimiterCount(line, '\t'); n >= 2 {
			tabs[n]++
		}
	}

	scores := make(map[string]float64, len(sd.patterns)+2)
	for structType := range sd.patterns {
		over := len(lines)
		if structType == "Configuration" {
			over = configLines
		}
		if over > 0 {
			scores[structType] = float64(matches[structType]) / float64(over)
		} else {
			scores[structType] = 0
		}
	}
	scores["CSV"] = delimitedShare(commas, len(lines), true)
	scores["TSV"] = delimitedShare(tabs, len(lines), false)

	// Find the highest scoring structure type. Ties are broken by type name so
	// the result is deterministic: ranging a map with a strict > let Go's
	// randomized iteration order decide between equal scores, so the same
	// content was detected as "TSV" on one run and "Code" on the next. That
	// choice feeds calculateConfidenceAdjustments (tabular_boost is +20), so the
	// flapping moved every finding in the document across a confidence band.
	bestType := "Unknown"
	bestScore := 0.0

	for structType, score := range scores {
		if score > bestScore || (score == bestScore && score > 0 && structType < bestType) {
			bestScore = score
			bestType = structType
		}
	}

	// Require minimum confidence threshold
	if bestScore < 0.3 {
		return "Unknown", bestScore
	}

	return bestType, bestScore
}

// endsSentence reports whether a line's last non-blank byte ends a sentence: `.`, `!` or `?`. Such a
// line is prose, not a CSV row (#849): a paragraph of an extracted document is one line that ends in a
// full stop, and its commas are punctuation. Stated cost: a CSV row whose last field is unquoted free
// text ending in a full stop is not counted as a row; a `.csv` path is typed by its extension first.
func endsSentence(line string) bool {
	t := strings.TrimRight(line, " \t\r")
	if t == "" {
		return false
	}
	switch t[len(t)-1] {
	case '.', '!', '?':
		return true
	}
	return false
}

// The bounds of the sample DetectStructure types a document from (#849); see structureSample.
const (
	structureSampleBytes = 32 << 10
	structureSampleLines = 2000
	structureWindows     = 16
	structureLineBytes   = 2000
)

// structureSample returns the lines DetectStructure types a document from (#849). Until #849 that was
// its first 2000 characters, so a document was typed by its first screen: ten tab-separated rows of a
// title block typed 800 lines of prose TSV, and tabular_boost gave every finding in it +20 (#787).
//
// A document of at most structureSampleBytes and structureSampleLines lines is typed from every line.
// A longer one is typed from structureWindows windows of consecutive lines, evenly spaced from its
// first line to its last and all of one length, sized so the sample is about structureSampleBytes at
// the document's mean line length and never more than structureSampleLines lines. Each window weighs
// the same, so a title block can weigh one window at most, and the sample costs about what the old
// one did: measured on one core, DetectStructure takes 0.3 to 2.2 ms a document against the old 0.7
// to 0.9 ms, the most on a 145 KB Go file and on an 8 MB log, a millisecond of which is finding the
// log's line boundaries.
//
// Every line is cut to structureLineBytes before the patterns see it, so no line costs more than the
// whole old sample did, and a document that is one long line is typed from what it was typed from.
//
// The empty element a trailing newline splits into is dropped (#788). It is no line of the file -- a
// file an editor wrote ends in a newline, and its last line is the one before it -- but it was in
// every share's denominator until #788, so the same six credential lines were 2 of 7 (0.286, Unknown)
// with a trailing newline and 2 of 6 (0.333, Configuration, +15 on every secrets candidate in the
// file) without one.
func structureSample(content string) []string {
	content = strings.TrimSuffix(content, "\n")
	total := strings.Count(content, "\n") + 1
	if total <= structureSampleLines && len(content) <= structureSampleBytes {
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			if len(line) > structureLineBytes {
				lines[i] = line[:structureLineBytes]
			}
		}
		return lines
	}
	meanLine := len(content) / total
	if meanLine < 1 {
		meanLine = 1
	}
	windowLines := structureSampleBytes / structureWindows / meanLine
	if windowLines < 1 {
		windowLines = 1
	}
	if limit := structureSampleLines / structureWindows; windowLines > limit {
		windowLines = limit
	}
	lines := make([]string, 0, structureWindows*windowLines)
	rest, idx := content, 0
	next := func() string {
		line := rest
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		idx++
		if len(line) > structureLineBytes {
			line = line[:structureLineBytes]
		}
		return line
	}
	for w := 0; w < structureWindows; w++ {
		first := w * (total - windowLines) / (structureWindows - 1)
		for idx < first {
			next()
		}
		for k := 0; k < windowLines && idx < total; k++ {
			lines = append(lines, next())
		}
	}
	return lines
}

// delimitedShare is the CSV or the TSV share of a sample of total lines, given how many of its lines
// hold each count of two or more delimiters (#849). Until #849 the CSV pattern took any line with two
// commas and the TSV pattern any line with two tabs, and CSV and TSV are tabular_boost, +20 on every
// finding of every validator in the document.
//
// A comma is ordinary punctuation in prose and in code, so a line holding two is no row on its own;
// the rows of a CSV table have one field count, so a CSV share (oneTable) counts only the lines with
// the sample's most common count, and DetectStructure counts no line that ends a sentence
// (endsSentence). Of 1,039 prose documents rewritten one paragraph a line, the shape a document
// extraction produces, main typed 193 CSV and these two rules 7, each of them one or two lines long.
//
// A tab is not punctuation, so a line holding two past its indentation is a row, and the TSV share
// counts every such line: the spreadsheet extractor writes each non-empty cell and a tab, so the rows
// of one sheet hold different counts and so do the sheets of one workbook, and a one-count rule would
// stop typing them TSV.
func delimitedShare(counts map[int]int, total int, oneTable bool) float64 {
	if total == 0 {
		return 0
	}
	rows := 0
	for _, c := range counts {
		if !oneTable {
			rows += c
		} else if c > rows {
			rows = c
		}
	}
	return float64(rows) / float64(total)
}

// delimiterCount counts the field delimiters on a line (#849): none in its indentation, since leading
// spaces and tabs are layout (Go source indents with tabs, and counting them typed 177 of this
// repository's Go files TSV on their indentation alone, measured when #849 was fixed), and for a
// comma none inside a double-quoted field. Stated cost: an empty first cell of a tab-separated row is
// indistinguishable from indentation, so `\tB\tC` holds one delimiter.
func delimiterCount(line string, delim byte) int {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	n, quoted := 0, false
	for ; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"' && delim == ',':
			quoted = !quoted
		case c == delim && !quoted:
			n++
		}
	}
	return n
}

// isConfigurationLine reports whether a line counts toward the Configuration share, which is taken
// over every line except blank and comment-only ones (#788). Blank lines separate a config file's
// sections and comment lines hold its notes and its commented-out defaults; they are the layout of a
// config file, so they may neither lower its share nor raise it. A comment-only line is one whose
// first non-blank byte starts a line comment: `#` (shell, YAML, TOML, `.env`, INI), `;` (INI) or `//`.
// A commented-out assignment (`#db_password=...`) is a comment like any other: how many lines an
// author disabled does not move the type of what is left.
//
// Only the Configuration share is taken over this subset. The other shares keep every sampled line in
// their denominator. Taking every share over the subset was measured in #788 on 21,439 third-party
// files, with the CSV and TSV patterns of the time: it typed at least 576 Go source files TSV that
// were Unknown before, and comma-rich prose CSV, adding the tabular boost of +20 to every finding of
// every validator in them, because the TSV pattern counted indentation tabs and the CSV pattern took
// any line with two commas, and blank lines between blocks and paragraphs were what kept those files
// under the threshold. #849 bounded those two tests (delimitedShare) and left the denominators alone.
func isConfigurationLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed != "" && !isCommentOnlyLine(trimmed)
}

// isCommentOnlyLine reports whether a trimmed, non-empty line is a line comment.
func isCommentOnlyLine(trimmed string) bool {
	return trimmed[0] == '#' || trimmed[0] == ';' || strings.HasPrefix(trimmed, "//")
}

// NewDomainClassifier creates a business domain classifier
func NewDomainClassifier() *DomainClassifier {
	domainKeywords := map[string][]string{
		"Healthcare": {
			"patient", "medical", "hospital", "doctor", "nurse", "treatment",
			"diagnosis", "medication", "healthcare", "clinic", "physician",
			"medicare", "medicaid", "insurance", "health plan", "hipaa",
		},
		"Financial": {
			"bank", "account", "transaction", "payment", "credit", "debit",
			"loan", "mortgage", "investment", "finance", "financial",
			"routing", "aba", "iban", "swift", "pci", "payment card",
		},
		"HR_Payroll": {
			"employee", "payroll", "salary", "wage", "benefits", "hr",
			"human resources", "personnel", "staff", "hire", "employment",
			"w2", "w-2", "1099", "tax", "withholding", "pto", "vacation",
		},
		"Government": {
			"federal", "state", "government", "agency", "department",
			"public", "citizen", "taxpayer", "irs", "tax", "social security",
			"medicare", "veterans", "military", "passport", "immigration",
		},
		"Education": {
			"student", "school", "university", "college", "education",
			"academic", "grade", "course", "curriculum", "teacher",
			"professor", "enrollment", "transcript", "ferpa", "student id",
		},
		"Retail": {
			"customer", "purchase", "order", "product", "inventory",
			"sale", "receipt", "refund", "shipping", "delivery",
			"merchant", "pos", "retail", "store", "warehouse",
		},
	}

	return &DomainClassifier{
		domainKeywords: domainKeywords,
		confidence:     make(map[string]float64),
	}
}

// ClassifyDomain identifies the business domain context
func (dc *DomainClassifier) ClassifyDomain(content string) (string, float64) {
	lowerContent := strings.ToLower(content)

	// Sample content for analysis (first 5000 chars)
	sample := lowerContent
	if len(lowerContent) > 5000 {
		sample = lowerContent[:5000]
	}

	domainScores := make(map[string]int)
	totalKeywords := 0

	// Count keyword matches for each domain
	for domain, keywords := range dc.domainKeywords {
		for _, keyword := range keywords {
			if strings.Contains(sample, keyword) {
				domainScores[domain]++
				totalKeywords++
			}
		}
	}

	if totalKeywords == 0 {
		return "Unknown", 0.0
	}

	// Find the highest scoring domain. Ties are broken by domain name so the
	// result is deterministic: ranging a map with a strict > let Go's randomized
	// iteration order decide between equal scores, so the same input classified
	// as (for example) Financial on one run and Retail on the next — the domain
	// lands in reported metadata, which made output non-reproducible.
	bestDomain := "Unknown"
	bestScore := 0

	for domain, score := range domainScores {
		if score > bestScore || (score == bestScore && score > 0 && domain < bestDomain) {
			bestScore = score
			bestDomain = domain
		}
	}

	// Calculate confidence based on keyword density
	confidence := float64(bestScore) / float64(totalKeywords)

	// Require minimum confidence threshold
	if confidence < 0.3 {
		return "Unknown", confidence
	}

	return bestDomain, confidence
}

// Initialize semantic patterns for advanced analysis
func initSemanticPatterns() map[string][]string {
	return map[string][]string{
		"PersonalData": {
			"personal information", "personally identifiable", "pii",
			"private data", "confidential", "sensitive information",
		},
		"FinancialData": {
			"financial information", "bank details", "account information",
			"payment data", "credit information", "financial records",
		},
		"MedicalData": {
			"medical information", "health records", "patient data",
			"medical history", "health information", "clinical data",
		},
		"TestData": {
			"test data", "sample data", "example", "dummy data",
			"mock data", "test case", "test scenario", "placeholder",
		},
		"Production": {
			"production", "live data", "real data", "actual",
			"operational", "customer data", "user data",
		},
	}
}

// Initialize cross-validator patterns
func initCrossValidatorPatterns() map[string]CrossValidatorPattern {
	patterns := make(map[string]CrossValidatorPattern)

	// Employee Record Pattern
	patterns["EmployeeRecord"] = CrossValidatorPattern{
		Name:        "Employee Record",
		Validators:  []string{"ssn", "creditcard"},
		Pattern:     regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+\d{3}-\d{2}-\d{4}`),
		Confidence:  0.8,
		Description: "Employee records containing names and SSNs",
	}

	// Customer Database Pattern
	patterns["CustomerDatabase"] = CrossValidatorPattern{
		Name:        "Customer Database",
		Validators:  []string{"creditcard", "ssn"},
		Pattern:     regexp.MustCompile(`\d{4}-\d{4}-\d{4}-\d{4}.*\d{3}-\d{2}-\d{4}`),
		Confidence:  0.9,
		Description: "Customer database with payment and identity info",
	}

	// Financial Report Pattern
	patterns["FinancialReport"] = CrossValidatorPattern{
		Name:        "Financial Report",
		Validators:  []string{"creditcard", "ssn"},
		Pattern:     regexp.MustCompile(`(?i)(total|balance|amount|payment).*\$\d+`),
		Confidence:  0.7,
		Description: "Financial reports with monetary amounts",
	}

	return patterns
}

// analyzeSemanticPatterns performs semantic pattern analysis
func (ca *ContextAnalyzer) analyzeSemanticPatterns(content string) map[string]float64 {
	results := make(map[string]float64)
	lowerContent := strings.ToLower(content)

	for category, patterns := range ca.semanticPatterns {
		score := 0.0
		for _, pattern := range patterns {
			if strings.Contains(lowerContent, pattern) {
				score += 1.0
			}
		}

		// Normalize score
		if len(patterns) > 0 {
			results[category] = score / float64(len(patterns))
		}
	}

	return results
}

// detectCrossValidatorSignals identifies patterns spanning multiple validators
func (ca *ContextAnalyzer) detectCrossValidatorSignals(content string) []CrossValidatorSignal {
	var signals []CrossValidatorSignal

	for _, pattern := range ca.crossValidatorPatterns {
		if pattern.Pattern.MatchString(content) {
			signal := CrossValidatorSignal{
				ValidatorType: strings.Join(pattern.Validators, ","),
				SignalType:    pattern.Name,
				Confidence:    pattern.Confidence,
				Evidence:      pattern.Description,
				Impact:        15.0, // Base confidence boost
			}
			signals = append(signals, signal)
		}
	}

	return signals
}

// calculateConfidenceAdjustments generates validator-specific confidence adjustments
func (ca *ContextAnalyzer) calculateConfidenceAdjustments(insights ContextInsights) map[string]float64 {
	adjustments := make(map[string]float64)

	// Document structure adjustments
	switch insights.DocumentType {
	case "CSV", "TSV", "FixedWidth":
		adjustments["tabular_boost"] = 20.0
	case "Log":
		adjustments["log_penalty"] = -10.0
	case "Code":
		adjustments["code_penalty"] = -15.0
	}

	// Domain-specific adjustments
	switch insights.Domain {
	case "Healthcare":
		adjustments["ssn_healthcare_boost"] = 18.0
		adjustments["creditcard_healthcare_penalty"] = -5.0
	case "Financial":
		adjustments["creditcard_financial_boost"] = 25.0
		adjustments["ssn_financial_boost"] = 10.0
	case "HR_Payroll":
		adjustments["ssn_hr_boost"] = 20.0
		adjustments["creditcard_hr_penalty"] = -10.0
	}

	// Semantic context adjustments
	if testScore, exists := insights.SemanticContext["TestData"]; exists && testScore > 0.5 {
		adjustments["test_data_penalty"] = -30.0
	}

	if prodScore, exists := insights.SemanticContext["Production"]; exists && prodScore > 0.5 {
		adjustments["production_boost"] = 15.0
	}

	// Cross-validator signal adjustments
	for _, signal := range insights.CrossValidatorSignals {
		adjustments[signal.SignalType+"_boost"] = signal.Impact
	}

	return adjustments
}

// extractMetaInformation extracts additional metadata from content
func (ca *ContextAnalyzer) extractMetaInformation(content, filePath string) map[string]interface{} {
	meta := make(map[string]interface{})

	// Basic statistics
	meta["content_length"] = len(content)
	meta["line_count"] = len(strings.Split(content, "\n"))
	meta["file_path"] = filePath

	// Character distribution analysis
	digitCount := 0
	alphaCount := 0
	spaceCount := 0

	for _, char := range content {
		if char >= '0' && char <= '9' {
			digitCount++
		} else if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			alphaCount++
		} else if char == ' ' || char == '\t' {
			spaceCount++
		}
	}

	totalChars := len(content)
	if totalChars > 0 {
		meta["digit_ratio"] = float64(digitCount) / float64(totalChars)
		meta["alpha_ratio"] = float64(alphaCount) / float64(totalChars)
		meta["space_ratio"] = float64(spaceCount) / float64(totalChars)
	}

	// Detect common delimiters
	meta["comma_count"] = strings.Count(content, ",")
	meta["tab_count"] = strings.Count(content, "\t")
	meta["pipe_count"] = strings.Count(content, "|")
	meta["semicolon_count"] = strings.Count(content, ";")

	return meta
}

// GetConfidenceAdjustment returns validator-specific confidence adjustment
func (ca *ContextAnalyzer) GetConfidenceAdjustment(insights ContextInsights, validatorName string) float64 {
	adjustment := 0.0

	// Apply general adjustments
	if boost, exists := insights.ConfidenceAdjustments["tabular_boost"]; exists {
		adjustment += boost
	}

	if penalty, exists := insights.ConfidenceAdjustments["test_data_penalty"]; exists {
		adjustment += penalty
	}

	// Apply validator-specific adjustments
	validatorKey := validatorName + "_boost"
	if boost, exists := insights.ConfidenceAdjustments[validatorKey]; exists {
		adjustment += boost
	}

	validatorKey = validatorName + "_penalty"
	if penalty, exists := insights.ConfidenceAdjustments[validatorKey]; exists {
		adjustment += penalty
	}

	// Cap adjustments to reasonable bounds
	if adjustment > 50 {
		adjustment = 50
	} else if adjustment < -50 {
		adjustment = -50
	}

	return adjustment
}
