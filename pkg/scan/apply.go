// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	plaintextredactor "github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// RedactStrategy mirrors the three redaction strategies the engine supports.
type RedactStrategy int

const (
	// StrategyFormatPreserving keeps length and structure: ****-****-****-0004.
	StrategyFormatPreserving RedactStrategy = iota
	// StrategySimple replaces the entire value with a fixed token.
	StrategySimple
	// StrategySynthetic replaces with realistic fake data.
	StrategySynthetic
)

// Redacted is the result of applying redaction to text.
type Redacted struct {
	Text  string // the redacted output
	Count int    // number of values redacted
}

// RedactText takes text and pre-computed findings, and returns the redacted
// output. This is the pure redaction primitive: it does NOT re-detect — it
// masks the findings you already have.
//
// Use this when you've already called ScanText and want to redact based on
// those findings. For a one-call detect-and-redact, use pkg/redact.Engine.Redact.
//
// Only findings whose Text field is non-empty can be redacted (they must contain
// the matched substring to locate it in the source text).
func RedactText(text string, findings []Finding, strategy RedactStrategy) (*Redacted, error) {
	if len(findings) == 0 {
		return &Redacted{Text: text, Count: 0}, nil
	}

	// Convert public findings to internal matches (the redactor's input type).
	matches := make([]detector.Match, 0, len(findings))
	for _, f := range findings {
		if f.Text == "" {
			continue // can't redact without the matched substring
		}
		matches = append(matches, detector.Match{
			Text:       f.Text,
			Type:       f.Type,
			Confidence: f.Confidence,
			LineNumber: f.LineNumber,
			Filename:   f.Filename,
			Validator:  f.Validator,
		})
	}

	if len(matches) == 0 {
		return &Redacted{Text: text, Count: 0}, nil
	}

	// Use the plaintext redactor (stateless, no output-manager needed for
	// in-memory string redaction).
	redactor := plaintextredactor.NewPlainTextRedactor(nil, nil)
	redacted, _, err := redactor.RedactString(text, matches, mapStrategy(strategy))
	if err != nil {
		return nil, err
	}

	return &Redacted{Text: redacted, Count: len(matches)}, nil
}

func mapStrategy(s RedactStrategy) redactors.RedactionStrategy {
	switch s {
	case StrategySimple:
		return redactors.RedactionSimple
	case StrategySynthetic:
		return redactors.RedactionSynthetic
	default:
		return redactors.RedactionFormatPreserving
	}
}
