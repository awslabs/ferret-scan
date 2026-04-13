// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package vin

import (
	"regexp"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

// transliterationMap maps VIN characters to their numeric values for check digit calculation.
var transliterationMap = map[byte]int{
	'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
	'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
	'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9,
	'0': 0, '1': 1, '2': 2, '3': 3, '4': 4,
	'5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
}

// positionWeights are the weights for each of the 17 VIN positions.
var positionWeights = [17]int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}

// knownWMIs maps common World Manufacturer Identifier prefixes to manufacturer names.
var knownWMIs = map[string]string{
	"1G1": "Chevrolet", "1G2": "Pontiac", "1GC": "Chevrolet Truck",
	"1GT": "GMC Truck", "1HG": "Honda", "1J4": "Jeep", "1FA": "Ford",
	"1FB": "Ford", "1FC": "Ford", "1FD": "Ford", "1FM": "Ford",
	"1FT": "Ford Truck", "1FU": "Freightliner", "1GY": "Cadillac",
	"1HD": "Harley-Davidson", "1HF": "Honda", "1LN": "Lincoln",
	"1ME": "Mercury", "1N4": "Nissan", "1NX": "Toyota",
	"2C3": "Chrysler", "2FA": "Ford Canada", "2G1": "Chevrolet Canada",
	"2HG": "Honda Canada", "2HM": "Hyundai Canada", "2T1": "Toyota Canada",
	"3FA": "Ford Mexico", "3G1": "Chevrolet Mexico", "3HG": "Honda Mexico",
	"3VW": "Volkswagen Mexico",
	"JHM": "Honda", "JN1": "Nissan", "JT2": "Toyota", "JTE": "Toyota",
	"JTD": "Toyota", "JTH": "Lexus",
	"KM8": "Hyundai", "KNA": "Kia", "KND": "Kia",
	"SAJ": "Jaguar", "SAL": "Land Rover", "SCA": "Rolls-Royce",
	"SCF": "Aston Martin",
	"WAU": "Audi", "WBA": "BMW", "WBS": "BMW M", "WDB": "Mercedes-Benz",
	"WDD": "Mercedes-Benz", "WF0": "Ford Germany", "WMW": "MINI",
	"WP0": "Porsche", "WUA": "Audi Sport", "WVW": "Volkswagen",
	"YV1": "Volvo",
	"ZAR": "Alfa Romeo", "ZFF": "Ferrari",
}

// Validator implements the detector.Validator interface for detecting
// Vehicle Identification Numbers using regex patterns, check digit validation,
// and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	positiveKeywords []string
	negativeKeywords []string

	testPatterns []string

	observer *observability.StandardObserver
}

// NewValidator creates and returns a new VIN Validator instance.
func NewValidator() *Validator {
	v := &Validator{
		// 17 alphanumeric characters excluding I, O, Q
		pattern: `\b[A-HJ-NPR-Z0-9]{17}\b`,
		positiveKeywords: []string{
			"vin", "vehicle identification", "vehicle id", "chassis",
			"title", "registration", "dmv", "odometer", "mileage",
			"carfax", "autocheck", "recall", "nhtsa", "manufacturer",
			"make", "model", "year", "vehicle number", "frame number",
			"hull id", "vin:", "vin#", "automobile", "car", "truck",
			"motorcycle", "trailer", "fleet", "motor vehicle",
			"insurance claim", "accident report", "vehicle history",
			"dealer", "dealership", "automotive",
		},
		negativeKeywords: []string{
			"serial", "part number", "sku", "product code", "model number",
			"uuid", "hash", "token", "key", "password", "api",
			"mac address", "isbn", "test", "example", "sample", "dummy",
			"base64", "encoded", "hex", "checksum", "digest", "signature",
			"commit", "sha", "md5", "certificate", "license key",
			"activation", "registration key", "product key",
		},
		testPatterns: []string{
			"11111111111111111", "00000000000000000",
			"AAAAAAAAAAAAAAAAA", "12345678901234567",
			"ABCDEFGHJKLMNPRS",
		},
	}
	v.regex = regexp.MustCompile(v.pattern)
	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Validate implements the detector.Validator interface (legacy file-based).
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("vin_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("vin_validator", "validate_file", filePath)
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "VIN validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for VINs.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("vin_validator", "validate_content", originalPath)
	}

	var matches []detector.Match
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		foundMatches := v.regex.FindAllString(line, -1)

		for _, match := range foundMatches {
			upper := strings.ToUpper(match)

			// --- Early rejection cascade ---

			if len(upper) != 17 {
				continue
			}

			if v.isAllRepeating(upper) {
				continue
			}

			if v.isTestPattern(upper) {
				continue
			}

			if !v.checkDigitValid(upper) {
				continue
			}

			if v.isEncodedData(line, match) {
				continue
			}

			// --- Passed all gates: score confidence ---

			confidence, checks := v.CalculateConfidence(upper)

			contextInfo := v.buildContext(line, match)
			contextImpact := v.AnalyzeContext(match, contextInfo)
			confidence += contextImpact

			contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
			contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
			contextInfo.ConfidenceImpact = contextImpact

			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			if confidence <= 0 {
				continue
			}

			manufacturer := v.detectManufacturer(upper)
			metadata := map[string]any{
				"validation_checks": checks,
				"context_impact":    contextImpact,
				"source":            "preprocessed_content",
			}
			if manufacturer != "" {
				metadata["manufacturer"] = manufacturer
			}

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1,
				Type:       "VIN",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "vin",
				Context:    contextInfo,
				Metadata:   metadata,
			})
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(lines),
			"content_length":  len(content),
		})
	}
	return matches, nil
}

// CalculateConfidence returns a base confidence and validation checks map.
func (v *Validator) CalculateConfidence(vin string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":        true,
		"check_digit":   true,
		"known_wmi":     false,
		"valid_year":    false,
		"not_test":      true,
		"not_repeating": true,
	}

	confidence := 65.0

	// Check digit already validated in early rejection, so always +20
	confidence += 20
	checks["check_digit"] = true

	// Known manufacturer
	if v.detectManufacturer(vin) != "" {
		checks["known_wmi"] = true
		confidence += 10
	}

	// Valid model year (position 10)
	if v.isValidModelYear(vin[9]) {
		checks["valid_year"] = true
		confidence += 5
	}

	return confidence, checks
}

// AnalyzeContext adjusts confidence based on surrounding text.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)
	fullLine := strings.ToLower(context.FullLine)

	var impact float64

	for _, keyword := range v.positiveKeywords {
		kw := strings.ToLower(keyword)
		if strings.Contains(fullContext, kw) {
			if strings.Contains(fullLine, kw) {
				impact += 25
			} else {
				impact += 10
			}
		}
	}

	for _, keyword := range v.negativeKeywords {
		kw := strings.ToLower(keyword)
		if strings.Contains(fullContext, kw) {
			if strings.Contains(fullLine, kw) {
				impact -= 15
			} else {
				impact -= 8
			}
		}
	}

	if impact > 50 {
		impact = 50
	} else if impact < -50 {
		impact = -50
	}

	return impact
}

// findKeywords returns a list of keywords found in the context.
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)

	var found []string
	for _, keyword := range keywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			found = append(found, keyword)
		}
	}
	return found
}

// checkDigitValid validates the VIN check digit (position 9) using the standard
// weighted transliteration algorithm. Returns true if the check digit is correct.
func (v *Validator) checkDigitValid(vin string) bool {
	if len(vin) != 17 {
		return false
	}

	sum := 0
	for i := 0; i < 17; i++ {
		if i == 8 {
			continue // skip check digit position
		}
		val, ok := transliterationMap[vin[i]]
		if !ok {
			return false
		}
		sum += val * positionWeights[i]
	}

	remainder := sum % 11
	var expected byte
	if remainder == 10 {
		expected = 'X'
	} else {
		expected = byte('0' + remainder)
	}

	return vin[8] == expected
}

// isValidModelYear checks if position 10 is a valid model year code.
// Valid codes: A-H, J-N, P, R-T, V-Y (letters), 1-9 (digits).
func (v *Validator) isValidModelYear(c byte) bool {
	switch {
	case c >= '1' && c <= '9':
		return true
	case c >= 'A' && c <= 'H':
		return true
	case c >= 'J' && c <= 'N':
		return true
	case c == 'P':
		return true
	case c >= 'R' && c <= 'T':
		return true
	case c >= 'V' && c <= 'Y':
		return true
	}
	return false
}

// detectManufacturer returns the manufacturer name for a known WMI, or empty string.
func (v *Validator) detectManufacturer(vin string) string {
	if len(vin) < 3 {
		return ""
	}
	return knownWMIs[vin[:3]]
}

// isAllRepeating returns true if all characters in the string are the same.
func (v *Validator) isAllRepeating(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// isTestPattern checks if the VIN matches a known test/placeholder pattern.
func (v *Validator) isTestPattern(vin string) bool {
	for _, tp := range v.testPatterns {
		if vin == tp {
			return true
		}
	}
	return false
}

// isEncodedData detects if the match is likely part of encoded data (base64, hex dumps, etc.).
func (v *Validator) isEncodedData(line, match string) bool {
	lower := strings.ToLower(line)

	// Hex dump patterns: line contains multiple "0x" prefixes typical of hex dumps
	if strings.Count(lower, "0x") >= 3 {
		return true
	}
	if strings.Count(line, " ") > 10 && isHexDump(line) {
		return true
	}

	// Base64-like context (long unbroken alphanumeric strings)
	idx := strings.Index(line, match)
	if idx >= 0 {
		before := idx - 1
		after := idx + len(match)
		if before >= 0 && isAlphanumeric(line[before]) {
			return true
		}
		if after < len(line) && isAlphanumeric(line[after]) {
			return true
		}
	}

	return false
}

func isAlphanumeric(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

func isHexDump(line string) bool {
	hexChars := 0
	for _, c := range line {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ' ' {
			hexChars++
		}
	}
	return len(line) > 0 && float64(hexChars)/float64(len(line)) > 0.85
}

// buildContext extracts context information around a match within the current line.
func (v *Validator) buildContext(line, match string) detector.ContextInfo {
	ctx := detector.ContextInfo{
		FullLine: line,
	}

	idx := strings.Index(line, match)
	if idx >= 0 {
		start := idx - 50
		if start < 0 {
			start = 0
		}
		ctx.BeforeText = line[start:idx]

		end := idx + len(match) + 50
		if end > len(line) {
			end = len(line)
		}
		ctx.AfterText = line[idx+len(match) : end]
	}

	return ctx
}
