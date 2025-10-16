// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package strategies

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ferret-scan/internal/redactors"
)

// SyntheticDataStrategy implements synthetic data generation for redaction
type SyntheticDataStrategy struct {
	// name is the name of this strategy
	name string

	// supportedDataTypes lists the data types this strategy can handle
	supportedDataTypes []string

	// generators maps data types to their generation functions
	generators map[string]DataGenerator

	// validators maps data types to their validation functions
	validators map[string]DataValidator
}

// DataGenerator is a function that generates synthetic data
type DataGenerator func(original string, context RedactionContext) (string, error)

// DataValidator is a function that validates synthetic data
type DataValidator func(original, synthetic, dataType string) *ValidationResult

// NewSyntheticDataStrategy creates a new synthetic data strategy
func NewSyntheticDataStrategy() *SyntheticDataStrategy {
	strategy := &SyntheticDataStrategy{
		name: "synthetic_data_strategy",
		supportedDataTypes: []string{
			"CREDIT_CARD",
			"SSN",
			"EMAIL",
			"PHONE",
			"PERSON_NAME",
			"ADDRESS",
			"DATE",
			"IP_ADDRESS",
			"URL",
		},
		generators: make(map[string]DataGenerator),
		validators: make(map[string]DataValidator),
	}

	// Register generators
	strategy.generators["CREDIT_CARD"] = strategy.generateCreditCard
	strategy.generators["SSN"] = strategy.generateSSN
	strategy.generators["EMAIL"] = strategy.generateEmail
	strategy.generators["PHONE"] = strategy.generatePhone
	strategy.generators["PERSON_NAME"] = strategy.generatePersonName
	strategy.generators["ADDRESS"] = strategy.generateAddress
	strategy.generators["DATE"] = strategy.generateDate
	strategy.generators["IP_ADDRESS"] = strategy.generateIPAddress
	strategy.generators["URL"] = strategy.generateURL

	// Register validators
	strategy.validators["CREDIT_CARD"] = strategy.validateCreditCard
	strategy.validators["SSN"] = strategy.validateSSN
	strategy.validators["EMAIL"] = strategy.validateEmail
	strategy.validators["PHONE"] = strategy.validatePhone
	strategy.validators["PERSON_NAME"] = strategy.validatePersonName
	strategy.validators["ADDRESS"] = strategy.validateAddress
	strategy.validators["DATE"] = strategy.validateDate
	strategy.validators["IP_ADDRESS"] = strategy.validateIPAddress
	strategy.validators["URL"] = strategy.validateURL

	return strategy
}

// GetStrategyType returns the redaction strategy type
func (sds *SyntheticDataStrategy) GetStrategyType() redactors.RedactionStrategy {
	return redactors.RedactionSynthetic
}

// GetStrategyName returns the name of the strategy implementation
func (sds *SyntheticDataStrategy) GetStrategyName() string {
	return sds.name
}

// GetSupportedDataTypes returns the data types this strategy can handle
func (sds *SyntheticDataStrategy) GetSupportedDataTypes() []string {
	return sds.supportedDataTypes
}

// RedactText redacts the given text using synthetic data generation
func (sds *SyntheticDataStrategy) RedactText(originalText, dataType string, context RedactionContext) (*RedactionResult, error) {
	generator, exists := sds.generators[dataType]
	if !exists {
		return nil, fmt.Errorf("no generator available for data type: %s", dataType)
	}

	// Generate synthetic data
	syntheticData, err := generator(originalText, context)
	if err != nil {
		return nil, fmt.Errorf("failed to generate synthetic data: %w", err)
	}

	// Apply format preservation if requested
	if context.PreserveFormat {
		syntheticData = preserveFormat(originalText, syntheticData)
	}

	// Apply length preservation if requested
	if context.PreserveLength && len(syntheticData) != len(originalText) {
		syntheticData = sds.adjustLength(syntheticData, len(originalText), dataType)
	}

	result := &RedactionResult{
		RedactedText:    syntheticData,
		Strategy:        redactors.RedactionSynthetic,
		DataType:        dataType,
		Confidence:      0.95, // High confidence for synthetic data
		PreservedFormat: context.PreserveFormat,
		PreservedLength: context.PreserveLength && len(syntheticData) == len(originalText),
		SecurityLevel:   context.SecurityLevel,
		Metadata: map[string]interface{}{
			"generation_method": "synthetic",
			"original_length":   len(originalText),
			"synthetic_length":  len(syntheticData),
		},
	}

	return result, nil
}

// ValidateRedaction validates that the redaction was performed correctly
func (sds *SyntheticDataStrategy) ValidateRedaction(original, redacted, dataType string) (*ValidationResult, error) {
	validator, exists := sds.validators[dataType]
	if !exists {
		return &ValidationResult{
			Valid:         true,
			Issues:        []ValidationIssue{},
			SecurityScore: 0.8, // Default security score
			FormatScore:   0.8, // Default format score
			Confidence:    0.8, // Default confidence
		}, nil
	}

	return validator(original, redacted, dataType), nil
}

// generateCreditCard generates a synthetic credit card number
func (sds *SyntheticDataStrategy) generateCreditCard(original string, context RedactionContext) (string, error) {
	// Detect the original card type and format
	cardType := sds.detectCreditCardType(original)

	var prefix string
	var length int

	switch cardType {
	case "visa":
		prefix = "4"
		length = 16
	case "mastercard":
		prefix = "5"
		length = 16
	case "amex":
		prefix = "34"
		length = 15
	case "discover":
		prefix = "6"
		length = 16
	default:
		prefix = "4" // Default to Visa
		length = 16
	}

	// Generate random digits for the rest of the number
	digits := make([]string, length)
	for i := 0; i < len(prefix); i++ {
		if i < length {
			digits[i] = string(prefix[i])
		}
	}

	// Fill remaining positions with random digits
	for i := len(prefix); i < length-1; i++ {
		randomDigit, err := generateSecureRandom(0, 10)
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %w", err)
		}
		digits[i] = strconv.FormatInt(randomDigit, 10)
	}

	// Calculate Luhn check digit
	checkDigit := sds.calculateLuhnCheckDigit(strings.Join(digits[:length-1], ""))
	digits[length-1] = strconv.Itoa(checkDigit)

	syntheticNumber := strings.Join(digits, "")

	// Preserve formatting (spaces, dashes) from original
	return sds.preserveCreditCardFormat(original, syntheticNumber), nil
}

// generateSSN generates a synthetic Social Security Number
func (sds *SyntheticDataStrategy) generateSSN(original string, context RedactionContext) (string, error) {
	// Generate area number (001-899, excluding 666)
	var area int64
	for {
		areaRand, err := generateSecureRandom(1, 900)
		if err != nil {
			return "", fmt.Errorf("failed to generate area number: %w", err)
		}
		if areaRand != 666 {
			area = areaRand
			break
		}
	}

	// Generate group number (01-99)
	group, err := generateSecureRandom(1, 100)
	if err != nil {
		return "", fmt.Errorf("failed to generate group number: %w", err)
	}

	// Generate serial number (0001-9999)
	serial, err := generateSecureRandom(1, 10000)
	if err != nil {
		return "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	syntheticSSN := fmt.Sprintf("%03d-%02d-%04d", area, group, serial)

	// Preserve original format if it doesn't use dashes
	if !strings.Contains(original, "-") {
		syntheticSSN = strings.ReplaceAll(syntheticSSN, "-", "")
	}

	return syntheticSSN, nil
}

// generateEmail generates a synthetic email address
func (sds *SyntheticDataStrategy) generateEmail(original string, context RedactionContext) (string, error) {
	// Extract domain from original email if possible
	parts := strings.Split(original, "@")
	var domain string
	if len(parts) == 2 {
		domain = parts[1]
	} else {
		domain = "example.com" // Default domain
	}

	// Generate synthetic username
	usernames := []string{
		"user", "test", "demo", "sample", "example", "anonymous",
		"redacted", "synthetic", "generated", "placeholder",
	}

	usernameIndex, err := generateSecureRandom(0, int64(len(usernames)))
	if err != nil {
		return "", fmt.Errorf("failed to generate username index: %w", err)
	}

	username := usernames[usernameIndex]

	// Add random number to make it unique
	randomNum, err := generateSecureRandom(100, 10000)
	if err != nil {
		return "", fmt.Errorf("failed to generate random number: %w", err)
	}

	syntheticEmail := fmt.Sprintf("%s%d@%s", username, randomNum, domain)

	return syntheticEmail, nil
}

// generatePhone generates a synthetic phone number
func (sds *SyntheticDataStrategy) generatePhone(original string, context RedactionContext) (string, error) {
	// Detect format of original phone number
	format := sds.detectPhoneFormat(original)

	// Generate area code (200-999, excluding certain ranges)
	var areaCode int64
	for {
		area, err := generateSecureRandom(200, 1000)
		if err != nil {
			return "", fmt.Errorf("failed to generate area code: %w", err)
		}
		// Avoid certain reserved area codes
		if area != 555 && area != 800 && area != 888 && area != 877 && area != 866 {
			areaCode = area
			break
		}
	}

	// Generate exchange code (200-999)
	exchange, err := generateSecureRandom(200, 1000)
	if err != nil {
		return "", fmt.Errorf("failed to generate exchange code: %w", err)
	}

	// Generate subscriber number (0000-9999)
	subscriber, err := generateSecureRandom(0, 10000)
	if err != nil {
		return "", fmt.Errorf("failed to generate subscriber number: %w", err)
	}

	// Apply detected format
	switch format {
	case "dots":
		return fmt.Sprintf("%03d.%03d.%04d", areaCode, exchange, subscriber), nil
	case "spaces":
		return fmt.Sprintf("%03d %03d %04d", areaCode, exchange, subscriber), nil
	case "parentheses":
		return fmt.Sprintf("(%03d) %03d-%04d", areaCode, exchange, subscriber), nil
	case "plain":
		return fmt.Sprintf("%03d%03d%04d", areaCode, exchange, subscriber), nil
	default:
		return fmt.Sprintf("(%03d) %03d-%04d", areaCode, exchange, subscriber), nil
	}
}

// generatePersonName generates a synthetic person name
func (sds *SyntheticDataStrategy) generatePersonName(original string, context RedactionContext) (string, error) {
	firstNames := []string{
		"John", "Jane", "Michael", "Sarah", "David", "Lisa", "Robert", "Mary",
		"James", "Patricia", "William", "Jennifer", "Richard", "Linda", "Joseph", "Elizabeth",
		"Thomas", "Barbara", "Christopher", "Susan", "Charles", "Jessica", "Daniel", "Karen",
	}

	lastNames := []string{
		"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
		"Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
		"Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
	}

	// Determine if original is first name only, last name only, or full name
	parts := strings.Fields(original)

	var syntheticName string

	if len(parts) == 1 {
		// Single name - could be first or last
		if strings.Title(parts[0]) == parts[0] {
			// Likely a first name
			firstIndex, err := generateSecureRandom(0, int64(len(firstNames)))
			if err != nil {
				return "", fmt.Errorf("failed to generate first name index: %w", err)
			}
			syntheticName = firstNames[firstIndex]
		} else {
			// Likely a last name
			lastIndex, err := generateSecureRandom(0, int64(len(lastNames)))
			if err != nil {
				return "", fmt.Errorf("failed to generate last name index: %w", err)
			}
			syntheticName = lastNames[lastIndex]
		}
	} else {
		// Multiple parts - generate full name
		firstIndex, err := generateSecureRandom(0, int64(len(firstNames)))
		if err != nil {
			return "", fmt.Errorf("failed to generate first name index: %w", err)
		}

		lastIndex, err := generateSecureRandom(0, int64(len(lastNames)))
		if err != nil {
			return "", fmt.Errorf("failed to generate last name index: %w", err)
		}

		if len(parts) == 2 {
			syntheticName = fmt.Sprintf("%s %s", firstNames[firstIndex], lastNames[lastIndex])
		} else {
			// Handle middle names/initials
			syntheticName = fmt.Sprintf("%s %s %s", firstNames[firstIndex], "M.", lastNames[lastIndex])
		}
	}

	return syntheticName, nil
}

// generateAddress generates a synthetic address
func (sds *SyntheticDataStrategy) generateAddress(original string, context RedactionContext) (string, error) {
	streetNumbers := []string{"123", "456", "789", "101", "202", "303", "404", "505"}
	streetNames := []string{
		"Main St", "Oak Ave", "Pine Rd", "Elm Dr", "Maple Ln", "Cedar Blvd",
		"First St", "Second Ave", "Third Rd", "Park Dr", "Hill St", "Valley Rd",
	}

	streetNumIndex, err := generateSecureRandom(0, int64(len(streetNumbers)))
	if err != nil {
		return "", fmt.Errorf("failed to generate street number index: %w", err)
	}

	streetNameIndex, err := generateSecureRandom(0, int64(len(streetNames)))
	if err != nil {
		return "", fmt.Errorf("failed to generate street name index: %w", err)
	}

	syntheticAddress := fmt.Sprintf("%s %s", streetNumbers[streetNumIndex], streetNames[streetNameIndex])

	return syntheticAddress, nil
}

// generateDate generates a synthetic date
func (sds *SyntheticDataStrategy) generateDate(original string, context RedactionContext) (string, error) {
	// Detect date format from original
	format := sds.detectDateFormat(original)

	// Generate random date within reasonable range
	year, err := generateSecureRandom(1950, 2025)
	if err != nil {
		return "", fmt.Errorf("failed to generate year: %w", err)
	}

	month, err := generateSecureRandom(1, 13)
	if err != nil {
		return "", fmt.Errorf("failed to generate month: %w", err)
	}

	day, err := generateSecureRandom(1, 29) // Use 28 to avoid month-specific issues
	if err != nil {
		return "", fmt.Errorf("failed to generate day: %w", err)
	}

	// Apply detected format
	switch format {
	case "mm/dd/yyyy":
		return fmt.Sprintf("%02d/%02d/%04d", month, day, year), nil
	case "dd/mm/yyyy":
		return fmt.Sprintf("%02d/%02d/%04d", day, month, year), nil
	case "yyyy-mm-dd":
		return fmt.Sprintf("%04d-%02d-%02d", year, month, day), nil
	case "mm-dd-yyyy":
		return fmt.Sprintf("%02d-%02d-%04d", month, day, year), nil
	default:
		return fmt.Sprintf("%02d/%02d/%04d", month, day, year), nil
	}
}

// generateIPAddress generates a synthetic IP address
func (sds *SyntheticDataStrategy) generateIPAddress(original string, context RedactionContext) (string, error) {
	// Generate private IP address ranges to avoid conflicts
	var octets [4]int64

	// Use private IP ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
	ipType, err := generateSecureRandom(0, 3)
	if err != nil {
		return "", fmt.Errorf("failed to generate IP type: %w", err)
	}

	switch ipType {
	case 0: // 10.x.x.x
		octets[0] = 10
		for i := 1; i < 4; i++ {
			octet, err := generateSecureRandom(0, 256)
			if err != nil {
				return "", fmt.Errorf("failed to generate octet: %w", err)
			}
			octets[i] = octet
		}
	case 1: // 172.16-31.x.x
		octets[0] = 172
		second, err := generateSecureRandom(16, 32)
		if err != nil {
			return "", fmt.Errorf("failed to generate second octet: %w", err)
		}
		octets[1] = second
		for i := 2; i < 4; i++ {
			octet, err := generateSecureRandom(0, 256)
			if err != nil {
				return "", fmt.Errorf("failed to generate octet: %w", err)
			}
			octets[i] = octet
		}
	case 2: // 192.168.x.x
		octets[0] = 192
		octets[1] = 168
		for i := 2; i < 4; i++ {
			octet, err := generateSecureRandom(0, 256)
			if err != nil {
				return "", fmt.Errorf("failed to generate octet: %w", err)
			}
			octets[i] = octet
		}
	}

	return fmt.Sprintf("%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]), nil
}

// generateURL generates a synthetic URL
func (sds *SyntheticDataStrategy) generateURL(original string, context RedactionContext) (string, error) {
	domains := []string{
		"example.com", "test.org", "sample.net", "demo.com", "placeholder.org",
		"synthetic.net", "generated.com", "redacted.org",
	}

	paths := []string{
		"/page", "/document", "/file", "/resource", "/content", "/data",
		"/info", "/details", "/item", "/example",
	}

	domainIndex, err := generateSecureRandom(0, int64(len(domains)))
	if err != nil {
		return "", fmt.Errorf("failed to generate domain index: %w", err)
	}

	pathIndex, err := generateSecureRandom(0, int64(len(paths)))
	if err != nil {
		return "", fmt.Errorf("failed to generate path index: %w", err)
	}

	// Detect protocol from original
	protocol := "https"
	if strings.HasPrefix(strings.ToLower(original), "http://") {
		protocol = "http"
	}

	syntheticURL := fmt.Sprintf("%s://%s%s", protocol, domains[domainIndex], paths[pathIndex])

	return syntheticURL, nil
}

// Helper methods for format detection and validation

// detectCreditCardType detects the type of credit card from the number
func (sds *SyntheticDataStrategy) detectCreditCardType(cardNumber string) string {
	// Remove non-digit characters
	digits := regexp.MustCompile(`\D`).ReplaceAllString(cardNumber, "")

	if len(digits) == 0 {
		return "unknown"
	}

	switch {
	case strings.HasPrefix(digits, "4"):
		return "visa"
	case strings.HasPrefix(digits, "5") || strings.HasPrefix(digits, "2"):
		return "mastercard"
	case strings.HasPrefix(digits, "34") || strings.HasPrefix(digits, "37"):
		return "amex"
	case strings.HasPrefix(digits, "6"):
		return "discover"
	default:
		return "unknown"
	}
}

// preserveCreditCardFormat preserves the formatting of the original credit card number
func (sds *SyntheticDataStrategy) preserveCreditCardFormat(original, synthetic string) string {
	if len(original) == 0 {
		return synthetic
	}

	result := make([]rune, 0, len(original))
	syntheticRunes := []rune(synthetic)
	syntheticIndex := 0

	for _, char := range original {
		if char >= '0' && char <= '9' {
			if syntheticIndex < len(syntheticRunes) {
				result = append(result, syntheticRunes[syntheticIndex])
				syntheticIndex++
			}
		} else {
			result = append(result, char) // Preserve spaces, dashes, etc.
		}
	}

	return string(result)
}

// calculateLuhnCheckDigit calculates the Luhn check digit for a credit card number
func (sds *SyntheticDataStrategy) calculateLuhnCheckDigit(number string) int {
	sum := 0
	alternate := false

	// Process digits from right to left
	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return (10 - (sum % 10)) % 10
}

// detectPhoneFormat detects the format of a phone number
func (sds *SyntheticDataStrategy) detectPhoneFormat(phone string) string {
	switch {
	case strings.Contains(phone, "."):
		return "dots"
	case strings.Contains(phone, "(") && strings.Contains(phone, ")"):
		return "parentheses"
	case strings.Count(phone, " ") >= 2:
		return "spaces"
	case !regexp.MustCompile(`\D`).MatchString(phone):
		return "plain"
	default:
		return "standard"
	}
}

// detectDateFormat detects the format of a date string
func (sds *SyntheticDataStrategy) detectDateFormat(date string) string {
	switch {
	case regexp.MustCompile(`\d{2}/\d{2}/\d{4}`).MatchString(date):
		return "mm/dd/yyyy"
	case regexp.MustCompile(`\d{4}-\d{2}-\d{2}`).MatchString(date):
		return "yyyy-mm-dd"
	case regexp.MustCompile(`\d{2}-\d{2}-\d{4}`).MatchString(date):
		return "mm-dd-yyyy"
	default:
		return "mm/dd/yyyy"
	}
}

// adjustLength adjusts the length of synthetic data to match the original
func (sds *SyntheticDataStrategy) adjustLength(synthetic string, targetLength int, dataType string) string {
	if len(synthetic) == targetLength {
		return synthetic
	}

	if len(synthetic) > targetLength {
		// Truncate
		return synthetic[:targetLength]
	}

	// Pad with appropriate characters based on data type
	padding := targetLength - len(synthetic)
	switch dataType {
	case "CREDIT_CARD", "SSN", "PHONE":
		// Pad with zeros
		return synthetic + strings.Repeat("0", padding)
	case "EMAIL", "URL":
		// Pad with 'x' characters
		return synthetic + strings.Repeat("x", padding)
	default:
		// Pad with spaces
		return synthetic + strings.Repeat(" ", padding)
	}
}

// Validation methods

// validateCreditCard validates a synthetic credit card number
func (sds *SyntheticDataStrategy) validateCreditCard(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Check if synthetic number passes Luhn algorithm
	digits := regexp.MustCompile(`\D`).ReplaceAllString(synthetic, "")
	if !sds.isValidLuhn(digits) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypePattern,
			Description: "Synthetic credit card number fails Luhn algorithm validation",
			Suggestion:  "Ensure synthetic credit card numbers are generated with valid check digits",
		})
	}

	// Check format preservation
	formatScore := sds.calculateFormatScore(original, synthetic)
	if formatScore < 0.8 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypeFormat,
			Description: "Format preservation could be improved",
			Suggestion:  "Better preserve the original formatting structure",
		})
	}

	return &ValidationResult{
		Valid:         len(issues) == 0 || issues[0].Severity != SeverityCritical,
		Issues:        issues,
		SecurityScore: 0.95, // High security for synthetic data
		FormatScore:   formatScore,
		Confidence:    0.9,
	}
}

// validateSSN validates a synthetic SSN
func (sds *SyntheticDataStrategy) validateSSN(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Check SSN format
	digits := regexp.MustCompile(`\D`).ReplaceAllString(synthetic, "")
	if len(digits) != 9 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypePattern,
			Description: "Synthetic SSN does not have correct number of digits",
			Suggestion:  "Ensure synthetic SSN has exactly 9 digits",
		})
	}

	// Check for invalid area codes
	if len(digits) >= 3 {
		area, _ := strconv.Atoi(digits[:3])
		if area == 0 || area == 666 || area >= 900 {
			issues = append(issues, ValidationIssue{
				Severity:    SeverityWarning,
				Type:        IssueTypePattern,
				Description: "Synthetic SSN uses invalid area code",
				Suggestion:  "Use valid SSN area codes (001-899, excluding 666)",
			})
		}
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0 || issues[0].Severity != SeverityCritical,
		Issues:        issues,
		SecurityScore: 0.95,
		FormatScore:   formatScore,
		Confidence:    0.9,
	}
}

// validateEmail validates a synthetic email address
func (sds *SyntheticDataStrategy) validateEmail(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Basic email format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(synthetic) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypePattern,
			Description: "Synthetic email does not match valid email format",
			Suggestion:  "Ensure synthetic email follows standard email format",
		})
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0,
		Issues:        issues,
		SecurityScore: 0.9,
		FormatScore:   formatScore,
		Confidence:    0.85,
	}
}

// validatePhone validates a synthetic phone number
func (sds *SyntheticDataStrategy) validatePhone(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Check digit count
	digits := regexp.MustCompile(`\D`).ReplaceAllString(synthetic, "")
	if len(digits) != 10 {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypePattern,
			Description: "Synthetic phone number does not have 10 digits",
			Suggestion:  "Ensure synthetic phone numbers have exactly 10 digits",
		})
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0 || issues[0].Severity != SeverityCritical,
		Issues:        issues,
		SecurityScore: 0.9,
		FormatScore:   formatScore,
		Confidence:    0.85,
	}
}

// validatePersonName validates a synthetic person name
func (sds *SyntheticDataStrategy) validatePersonName(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Check if name contains only valid characters
	nameRegex := regexp.MustCompile(`^[a-zA-Z\s\.\-']+$`)
	if !nameRegex.MatchString(synthetic) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypePattern,
			Description: "Synthetic name contains invalid characters",
			Suggestion:  "Use only letters, spaces, dots, hyphens, and apostrophes in names",
		})
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0,
		Issues:        issues,
		SecurityScore: 0.85,
		FormatScore:   formatScore,
		Confidence:    0.8,
	}
}

// validateAddress validates a synthetic address
func (sds *SyntheticDataStrategy) validateAddress(original, synthetic, dataType string) *ValidationResult {
	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         true,
		Issues:        []ValidationIssue{},
		SecurityScore: 0.8,
		FormatScore:   formatScore,
		Confidence:    0.75,
	}
}

// validateDate validates a synthetic date
func (sds *SyntheticDataStrategy) validateDate(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Try to parse the date to ensure it's valid
	dateFormats := []string{
		"01/02/2006", "02/01/2006", "2006-01-02", "01-02-2006",
		"1/2/2006", "2/1/2006", "2006-1-2", "1-2-2006",
	}

	validDate := false
	for _, format := range dateFormats {
		if _, err := time.Parse(format, synthetic); err == nil {
			validDate = true
			break
		}
	}

	if !validDate {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypePattern,
			Description: "Synthetic date is not in a valid date format",
			Suggestion:  "Ensure synthetic date follows a standard date format",
		})
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         validDate,
		Issues:        issues,
		SecurityScore: 0.9,
		FormatScore:   formatScore,
		Confidence:    0.85,
	}
}

// validateIPAddress validates a synthetic IP address
func (sds *SyntheticDataStrategy) validateIPAddress(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Validate IP address format
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if !ipRegex.MatchString(synthetic) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityError,
			Type:        IssueTypePattern,
			Description: "Synthetic IP address is not in valid format",
			Suggestion:  "Ensure synthetic IP address follows x.x.x.x format",
		})
	} else {
		// Check octet ranges
		parts := strings.Split(synthetic, ".")
		for _, part := range parts {
			if octet, err := strconv.Atoi(part); err != nil || octet < 0 || octet > 255 {
				issues = append(issues, ValidationIssue{
					Severity:    SeverityError,
					Type:        IssueTypePattern,
					Description: "Synthetic IP address has invalid octet values",
					Suggestion:  "Ensure all octets are between 0 and 255",
				})
				break
			}
		}
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0,
		Issues:        issues,
		SecurityScore: 0.9,
		FormatScore:   formatScore,
		Confidence:    0.85,
	}
}

// validateURL validates a synthetic URL
func (sds *SyntheticDataStrategy) validateURL(original, synthetic, dataType string) *ValidationResult {
	issues := []ValidationIssue{}

	// Basic URL format validation
	urlRegex := regexp.MustCompile(`^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`)
	if !urlRegex.MatchString(synthetic) {
		issues = append(issues, ValidationIssue{
			Severity:    SeverityWarning,
			Type:        IssueTypePattern,
			Description: "Synthetic URL may not be in valid format",
			Suggestion:  "Ensure synthetic URL follows standard URL format",
		})
	}

	formatScore := sds.calculateFormatScore(original, synthetic)

	return &ValidationResult{
		Valid:         len(issues) == 0 || issues[0].Severity != SeverityCritical,
		Issues:        issues,
		SecurityScore: 0.85,
		FormatScore:   formatScore,
		Confidence:    0.8,
	}
}

// Helper validation methods

// isValidLuhn validates a number using the Luhn algorithm
func (sds *SyntheticDataStrategy) isValidLuhn(number string) bool {
	sum := 0
	alternate := false

	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit = digit/10 + digit%10
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// calculateFormatScore calculates how well the format was preserved
func (sds *SyntheticDataStrategy) calculateFormatScore(original, synthetic string) float64 {
	if len(original) == 0 || len(synthetic) == 0 {
		return 0.0
	}

	// Compare character types at each position
	matches := 0
	total := 0

	minLen := len(original)
	if len(synthetic) < minLen {
		minLen = len(synthetic)
	}

	for i := 0; i < minLen; i++ {
		origChar := rune(original[i])
		synthChar := rune(synthetic[i])

		total++

		// Check if character types match
		if sds.getCharType(origChar) == sds.getCharType(synthChar) {
			matches++
		}
	}

	if total == 0 {
		return 0.0
	}

	return float64(matches) / float64(total)
}

// getCharType returns the type of a character
func (sds *SyntheticDataStrategy) getCharType(char rune) string {
	switch {
	case char >= '0' && char <= '9':
		return "digit"
	case (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z'):
		return "letter"
	case char == ' ':
		return "space"
	case char == '-':
		return "dash"
	case char == '.':
		return "dot"
	case char == '(' || char == ')':
		return "parenthesis"
	case char == '@':
		return "at"
	case char == '/':
		return "slash"
	case char == ':':
		return "colon"
	default:
		return "other"
	}
}
