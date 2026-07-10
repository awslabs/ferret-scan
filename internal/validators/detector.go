// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	stdctx "context"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
	"github.com/awslabs/ferret-scan/internal/router"
)

// ProcessedContentValidator is the optional extension of detector.Validator for
// validators that accept a pre-extracted *preprocessors.ProcessedContent.
// parallel.RunValidators type-asserts for ValidateProcessedContent.
type ProcessedContentValidator interface {
	detector.Validator
	ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error)
}

// Detector is the single facade over the dual-path validation engine. It
// replaces the former five-type pass-through chain
//
//	EnhancedManagerWrapper -> EnhancedValidatorManager ->
//	ValidatorIntegrationHelper -> DualPathIntegration -> EnhancedValidatorBridge
//
// collapsing it to Detector -> EnhancedValidatorBridge -> document/metadata
// bridges (v2 Phase 2, Move B; see docs/proposals/V2_ARCHITECTURE.md). The
// EnhancedValidatorBridge does the real work (content routing, the document and
// metadata fan-outs, context-based confidence adjustment) and is unchanged.
//
// Detector satisfies detector.Validator and exposes the ctx/non-ctx
// ProcessedContent methods that parallel.RunValidators type-asserts for, so it
// drops into validatorsList exactly where the old wrapper did.
type Detector struct {
	bridge *EnhancedValidatorBridge
	// observer is retained because MetadataValidatorAdapter needs it at setup
	// time (to wrap non-PreprocessorAware metadata validators).
	observer observability.Observer
}

// compile-time guarantee the facade keeps satisfying the validator contracts.
var (
	_ detector.Validator        = (*Detector)(nil)
	_ ProcessedContentValidator = (*Detector)(nil)
)

// NewDetector constructs the facade and its underlying dual-path bridge. The
// DualPathConfig values mirror the former NewDualPathIntegration exactly so
// behavior is unchanged (debug logging is driven by the observer's
// DebugObserver, as before — there is no separate "real-time metrics" flag).
func NewDetector(observer observability.Observer) *Detector {
	config := &DualPathConfig{
		EnableContextIntegration: true,
		EnableFallbackMode:       true,
		EnableMetrics:            true,
		EnableDebugLogging:       observer != nil && observer.Debug() != nil,
		MaxRetries:               3,
	}

	bridge := NewEnhancedValidatorBridge(config)
	if observer != nil {
		bridge.SetObserver(observer)
	}

	return &Detector{bridge: bridge, observer: observer}
}

// SetupValidators registers the document validators (everything except METADATA)
// and the metadata validator. It folds together what were three separate methods
// (ValidatorIntegrationHelper.SetupDualPathValidation,
// DualPathIntegration.RegisterDocumentValidators, and
// DualPathIntegration.SetMetadataValidator). Non-PreprocessorAware metadata
// validators are wrapped in a MetadataValidatorAdapter, exactly as before.
func (d *Detector) SetupValidators(validators map[string]detector.Validator) error {
	for name, v := range validators {
		if name == "METADATA" {
			continue // handled separately below
		}
		d.bridge.RegisterDocumentValidator(name, v)
	}

	if mv, exists := validators["METADATA"]; exists {
		if pa, ok := mv.(PreprocessorAwareValidator); ok {
			d.bridge.SetMetadataValidator(pa)
		} else {
			d.bridge.SetMetadataValidator(&MetadataValidatorAdapter{
				validator: mv,
				observer:  d.observer,
			})
		}
	}
	return nil
}

// SetFileRouter wires the file router into the content router for metadata
// capability detection. No-op when fileRouter is nil (e.g. in-memory callers).
func (d *Detector) SetFileRouter(fileRouter *router.FileRouter) {
	if fileRouter == nil {
		return
	}
	if d.bridge != nil && d.bridge.contentRouter != nil {
		d.bridge.contentRouter.SetFileRouter(fileRouter)
	}
}

// Validate implements detector.Validator (unused in this flow, required by interface).
func (d *Detector) Validate(filePath string) ([]detector.Match, error) { return nil, nil }

// CalculateConfidence implements detector.Validator (unused in this flow).
func (d *Detector) CalculateConfidence(match string) (float64, map[string]bool) { return 0.0, nil }

// AnalyzeContext implements detector.Validator (unused in this flow).
func (d *Detector) AnalyzeContext(match string, c detector.ContextInfo) float64 { return 0.0 }

// ValidateContent implements detector.Validator. It wraps the string into a
// ProcessedContent and runs the dual-path validation (background context).
func (d *Detector) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return d.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateProcessedContent runs the dual-path validation with a background context.
func (d *Detector) ValidateProcessedContent(content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	return d.ValidateProcessedContentCtx(stdctx.Background(), content)
}

// ValidateContentCtx is the context-aware form of ValidateContent. ctx reaches
// the per-validator dispatch chokepoint (deadline/cancellation + panic recovery).
func (d *Detector) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	processedContent := &preprocessors.ProcessedContent{
		Text:         content,
		OriginalPath: originalPath,
		Success:      true,
	}
	return d.ValidateProcessedContentCtx(ctx, processedContent)
}

// ValidateProcessedContentCtx is the context-aware form of
// ValidateProcessedContent and the single live entry point: it delegates
// straight to the dual-path bridge (one hop, versus the former five).
func (d *Detector) ValidateProcessedContentCtx(ctx stdctx.Context, content *preprocessors.ProcessedContent) ([]detector.Match, error) {
	return d.bridge.ProcessContentCtx(ctx, content)
}
