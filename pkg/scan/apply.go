// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"strings"

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
	// Text is the redacted output.
	Text string

	// Count is how many values were actually REPLACED — not how many findings were passed in.
	//
	// The distinction is the point. It used to be len(findings), which made it an attestation this
	// package could not support: a finding the redactor cannot locate in the text is skipped, and
	// counting it told the caller a value had been masked when it was still in the clear. Measured
	// before the change, on one line holding six consolidated copyright notices, RedactText returned
	// Count=1 with output byte-identical to its input.
	//
	// So Count < len(findings) is meaningful and worth checking: it means at least one reported value
	// could not be located and is still present in Text. The known remaining case is a
	// SOCIAL_MEDIA_CLUSTER, whose members span several lines and cannot be recovered from a single
	// line of context — see #631.
	Count int
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
		m := detector.Match{
			Text:       f.Text,
			Type:       f.Type,
			Confidence: f.Confidence,
			LineNumber: f.LineNumber,
			Filename:   f.Filename,
			Validator:  f.Validator,
			// Context was dropped here, and dropping it disabled a safety net that the redactor
			// this function calls ALREADY runs. plaintext.RedactString invokes
			// redactors.RestoreBoundedMatchText, whose gate isBoundedMatch requires both
			// Context.FullLine and Metadata[MatchTextTruncatedKey] -- so with neither carried
			// across, a finding whose Text is a rendered SUMMARY rather than a document span
			// could not be located, was silently skipped, and was still counted as redacted.
			Context: detector.ContextInfo{
				BeforeText: f.ContextBefore,
				AfterText:  f.ContextAfter,
				FullLine:   f.FullLine,
			},
		}

		// The truncation flag is DERIVED here rather than plumbed through, because pkg/scan.Finding
		// carries no Metadata at all -- mapResult discards it a layer earlier -- and widening the
		// public struct to pass one boolean is a compatibility cost for an internal detail.
		//
		// The condition is exactly when the restore is both NEEDED and SAFE: the reported text does
		// not occur in the input (so it cannot be located as given) while its own full line does (so
		// there is a real span to mask instead). Deriving it from the two observable facts cannot
		// mis-fire on a finding that is locatable, because such a finding fails the first test.
		//
		// Measured before this, with default TextOptions{} and no config, on one line holding six
		// "Copyright (c) 2026 Acme Corporation ... CONFIDENTIAL" notices: one
		// INTELLECTUAL_PROPERTY finding at 98%, reported Text ending
		// "[+17 more matches on line]", and RedactText returning Count=1 with output BYTE-IDENTICAL
		// to the input for all three strategies -- six values in cleartext, attested as redacted.
		// Tested against the finding's OWN LINE, not the whole document, and that is a complexity
		// decision as much as a correctness one.
		//
		// A first version asked !strings.Contains(text, f.Text), which is O(document) per finding and
		// therefore O(findings x bytes) overall. Measured on distinct values: 27ms/95ms/339ms became
		// 30ms/110ms/395ms at 1049/2099/4199 findings -- about 16% on a path that is already
		// superlinear for other reasons. Against its own line the check is O(line), and the cost
		// disappears.
		//
		// It is also the more precise test. A normal match IS a literal substring of the line it was
		// found on; a bounded consolidated Text is a rendered SUMMARY of several matches and is not.
		// A match with no single line -- the multi-line SECRETS types -- has an empty FullLine and is
		// excluded by the first condition, which is what RestoreBoundedMatchText requires anyway.
		if line := strings.TrimSpace(f.FullLine); line != "" && f.Text != "" && !strings.Contains(f.FullLine, f.Text) {
			m.Metadata = map[string]any{redactors.MatchTextTruncatedKey: true}
		}

		matches = append(matches, m)
	}

	if len(matches) == 0 {
		return &Redacted{Text: text, Count: 0}, nil
	}

	// Use the plaintext redactor (stateless, no output-manager needed for
	// in-memory string redaction).
	redactor := plaintextredactor.NewPlainTextRedactor(nil, nil)
	redacted, mappings, err := redactor.RedactString(text, matches, mapStrategy(strategy))
	if err != nil {
		return nil, err
	}

	// Count the replacements the redactor actually MADE, not the findings handed to it.
	//
	// It was len(matches), which made Count an attestation the function could not support: a match
	// the redactor cannot locate hits `continue` before its mapping is appended, so a value left in
	// cleartext was still counted as redacted. A caller comparing len(Findings) against Count can now
	// see the gap -- which matters most for the case this cannot fix, a SOCIAL_MEDIA_CLUSTER whose
	// members span several lines and so cannot be recovered from a single FullLine.
	return &Redacted{Text: redacted, Count: len(mappings)}, nil
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
