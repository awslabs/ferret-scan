// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package context

import (
	"regexp"
	"strings"
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
	patterns map[string]*regexp.Regexp
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

// NewStructureDetector creates a document structure detector
func NewStructureDetector() *StructureDetector {
	patterns := map[string]*regexp.Regexp{
		"CSV":           regexp.MustCompile(`(?m)^[^,]*,[^,]*,.*$`),
		"TSV":           regexp.MustCompile(`(?m)^[^\t]*\t[^\t]*\t.*$`),
		"JSON":          regexp.MustCompile(`^\s*[\{\[].*[\}\]]\s*$`),
		"XML":           regexp.MustCompile(`<\?xml|<[a-zA-Z][^>]*>`),
		"SQL":           regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b`),
		"Log":           regexp.MustCompile(`\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}`),
		"Email":         regexp.MustCompile(`(?i)(from:|to:|subject:|date:)`),
		"Code":          regexp.MustCompile(`(?i)(function|class|import|include|def\s)`),
		"FixedWidth":    regexp.MustCompile(`(?m)^.{20,}\s{3,}.{20,}\s{3,}.*$`),
		"Report":        regexp.MustCompile(`(?i)(report|summary|total|subtotal|balance)`),
		"Configuration": regexp.MustCompile(`(?m)^[a-zA-Z_][a-zA-Z0-9_]*\s*[=:]\s*.*$`),
	}

	return &StructureDetector{patterns: patterns}
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

	// Sample first 2000 characters for pattern detection
	sample := content
	if len(content) > 2000 {
		sample = content[:2000]
	}

	scores := make(map[string]float64)
	lines := strings.Split(sample, "\n")
	totalLines := len(lines)

	if totalLines == 0 {
		return "Unknown", 0.0
	}

	// Test each pattern
	for structType, pattern := range sd.patterns {
		matches := 0
		for _, line := range lines {
			if pattern.MatchString(line) {
				matches++
			}
		}

		// Calculate confidence based on match percentage
		confidence := float64(matches) / float64(totalLines)
		scores[structType] = confidence
	}

	// Find the highest scoring structure type
	bestType := "Unknown"
	bestScore := 0.0

	for structType, score := range scores {
		if score > bestScore {
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

	// Find the highest scoring domain
	bestDomain := "Unknown"
	bestScore := 0

	for domain, score := range domainScores {
		if score > bestScore {
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
