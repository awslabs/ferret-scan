// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package comprehend_analyzer_lib

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The AWS SDK v2 dependencies required for this functionality have been removed from go.mod
// to reduce binary size and eliminate cloud service dependencies.

/*
import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/comprehend"
	"github.com/aws/aws-sdk-go-v2/service/comprehend/types"
)
*/

/*
// PIIResult represents the result of PII analysis
type PIIResult struct {
	Filename     string
	DocumentType string
	PIIEntities  []PIIEntity
	HasPII       bool
	HasPHI       bool
	RiskLevel    string
}

// PIIEntity represents a detected PII entity
type PIIEntity struct {
	Type        string
	Text        string
	Confidence  float64
	BeginOffset int32
	EndOffset   int32
}

// AnalyzePII analyzes text for PII/PHI using Amazon Comprehend
func AnalyzePII(text, filename, awsRegion string) (*PIIResult, error) {
	result := &PIIResult{
		Filename:     filename,
		DocumentType: "Text Content",
	}

	// Skip if no text
	if strings.TrimSpace(text) == "" {
		return result, nil
	}

	// Create context with timeout for AWS operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		return result, fmt.Errorf("error loading AWS config: %v", err)
	}

	// Create Comprehend client
	svc := comprehend.NewFromConfig(cfg)

	// Analyze PII entities
	input := &comprehend.DetectPiiEntitiesInput{
		Text:         aws.String(text),
		LanguageCode: types.LanguageCodeEn,
	}

	output, err := svc.DetectPiiEntities(ctx, input)
	if err != nil {
		return result, fmt.Errorf("error calling Comprehend: %v", err)
	}

	// Process results
	for _, entity := range output.Entities {
		piiEntity := PIIEntity{
			Type:        string(entity.Type),
			Confidence:  float64(aws.ToFloat32(entity.Score)),
			BeginOffset: aws.ToInt32(entity.BeginOffset),
			EndOffset:   aws.ToInt32(entity.EndOffset),
		}

		// Extract the actual text
		if int(piiEntity.BeginOffset) < len(text) && int(piiEntity.EndOffset) <= len(text) {
			piiEntity.Text = text[piiEntity.BeginOffset:piiEntity.EndOffset]
		}

		result.PIIEntities = append(result.PIIEntities, piiEntity)

		// Check for PHI (health-related PII)
		if isPHI(piiEntity.Type) {
			result.HasPHI = true
		}
	}

	result.HasPII = len(result.PIIEntities) > 0
	result.RiskLevel = calculateRiskLevel(result.PIIEntities)

	return result, nil
}

// ValidateAWSCredentials checks if AWS credentials are available
func ValidateAWSCredentials(region string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}

	_, err = cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return fmt.Errorf("AWS credentials not found or invalid: %v", err)
	}

	return nil
}

// EstimateComprehendCost provides a rough cost estimate
func EstimateComprehendCost(textLength int) float64 {
	// Comprehend PII detection: $0.0001 per 100 characters (as of 2024)
	const costPer100Chars = 0.0001
	units := float64(textLength) / 100.0
	if units < 1 {
		units = 1
	}
	return units * costPer100Chars
}

// isPHI checks if a PII type is considered PHI (Protected Health Information)
func isPHI(piiType string) bool {
	phiTypes := map[string]bool{
		"DATE_TIME": true,
		"AGE":       true,
		"ADDRESS":   true,
		"PHONE":     true,
		"EMAIL":     true,
		"NAME":      true,
		"SSN":       true,
		"PERSON":    true,
	}
	return phiTypes[piiType]
}

// calculateRiskLevel determines risk level based on detected PII
func calculateRiskLevel(entities []PIIEntity) string {
	if len(entities) == 0 {
		return "NONE"
	}

	highRiskTypes := map[string]bool{
		"SSN":                 true,
		"CREDIT_DEBIT_NUMBER": true,
		"AWS_ACCESS_KEY":      true,
		"AWS_SECRET_KEY":      true,
		"PASSWORD":            true,
		"PIN":                 true,
		"PASSPORT":            true,
		"DRIVER_ID":           true,
	}

	mediumRiskTypes := map[string]bool{
		"PHONE":     true,
		"EMAIL":     true,
		"ADDRESS":   true,
		"DATE_TIME": true,
		"PERSON":    true,
		"NAME":      true,
	}

	for _, entity := range entities {
		if highRiskTypes[entity.Type] {
			return "HIGH"
		}
	}

	for _, entity := range entities {
		if mediumRiskTypes[entity.Type] {
			return "MEDIUM"
		}
	}

	return "LOW"
}
*/
