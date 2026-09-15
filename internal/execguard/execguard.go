// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package execguard provides the single dispatch chokepoint through which every
// validator invocation should pass. It exists to close two structural gaps
// identified in the v2 architecture audit (see docs/proposals/V2_ARCHITECTURE.md):
//
//   - Gap 1.3 — a panic inside a validator goroutine crashes the entire process,
//     because Go panics do not cross goroutine boundaries and the only recover()
//     lives on a different (worker) goroutine. SafeRun recovers at the boundary
//     where untrusted/complex validator code is actually invoked and converts the
//     panic into a NON-retryable error, so the surrounding resilience retry
//     wrapper does not re-run a deterministically-panicking validator.
//
//   - Gap 1.1 — the detector.Validator interface takes no context.Context, so a
//     running validator cannot observe cancellation or a deadline. execguard
//     introduces the OPTIONAL ContextAwareValidator extension interface: a
//     validator that implements ValidateContentCtx is handed the context and can
//     poll it; validators that do not are invoked exactly as before. This is the
//     additive, behavior-preserving seam that Phase 3 builds on to make residual
//     O(n^2) hot paths interruptible.
//
// Phase 1 deliberately does NOT change the detector.Validator interface itself
// (that would be a source-breaking change for the ~13 validators and any external
// implementers). The optional interface + helper is a zero-breakage shim that can
// be adopted incrementally.
package execguard

import (
	"context"
	"errors"
	"fmt"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/resilience"
	"github.com/awslabs/ferret-scan/v2/internal/textnorm"
	"strconv"
	"strings"
)

// ErrMatchBudgetExceeded is returned (alongside the truncated, capped matches) by
// ValidateContent when a validator emits more matches than its ValidatorBudget
// MatchLimit allows. Callers can errors.Is-check it to record incomplete coverage
// (see internal/core/scanner.go). It is distinct from context errors: a match-cap
// hit is not a deadline/cancellation.
var ErrMatchBudgetExceeded = errors.New("validator match budget exceeded")

// ErrContentTooLarge is returned by a validator that DECLINED to scan its input because the
// content exceeded a size the validator will not process. It belongs to the same family as
// ErrMatchBudgetExceeded: a guard fired, so the result is partial and must be disclosed, while
// whatever the validator did find is genuine.
//
// Returning an error rather than an empty slice is the whole point. `return nil, nil` is
// indistinguishable from "scanned it, found nothing", so a caller cannot tell coverage was lost:
// cloudresources refused anything over 5MB that way, and a real AWS ARN on line 1 of a 6MB file
// was reported as a clean, complete scan — files_processed=1, no files_not_examined, exit 0 (#414).
// 5MB is small for the file types that carry infrastructure identifiers: Terraform plans,
// CloudTrail exports, build logs, support bundles.
//
// The cap itself is legitimate — this validator has a measured DoS history — so the fix is to
// DISCLOSE the refusal, not to remove the bound.
var ErrContentTooLarge = errors.New("validator declined oversize content")

// ErrValidatorPanicked is returned by SafeRun when a validator panicked and the panic was
// recovered. It belongs to the same family as ErrMatchBudgetExceeded and ErrContentTooLarge for
// exactly the reason stated there, only more so: a panicking validator returns ZERO matches for the
// WHOLE file, so if the panic is not disclosed the output is indistinguishable from "scanned it,
// found nothing".
//
// It was not disclosed. Recovering the panic is right — one bad validator must not kill a scan — but
// the recovered error's only consumer was a --debug log line, gated behind an observer that is nil
// unless --debug is passed. Measured at HEAD before this change, on a file containing a VIN plus a
// run of U+212A KELVIN SIGN (#656): 0 findings, exit 0, `--fail-on-incomplete` ALSO exit 0, SARIF
// with zero toolExecutionNotifications, and a stats block reading files_processed 1, files_skipped 0,
// total_findings 0. The tool affirmatively reported a clean, complete scan of a file it had abandoned.
//
// Because only reported findings reach the redactor, that is a redaction bypass an attacker triggers
// with one character class, and the silence is the part that makes it dangerous: a crash would have
// been noticed the first time.
//
// This is a DISCLOSURE fix, deliberately independent of any individual panic's cause. The specific
// indexing bug behind #656 is fixed too (see internal/bytefold), but a bug class cannot be closed by
// enumerating its instances — the NEXT panic, from a nil map or a slice bound nobody has thought of,
// now reaches the same channel without anyone having to predict it.
var ErrValidatorPanicked = errors.New("validator panicked")

// IsCoverageCutShort reports whether err means a validator GUARD fired rather than a validator
// failing: the scan completed, the result is partial, and whatever was found is genuine.
//
// This exists because the same family was enumerated in FOUR places — parallel.partialMatchesSurvive,
// validators.firstBudgetError, the dual-path bridge's match-preservation branch, and core.ScanContent
// — and adding a member meant finding all four. Missing one is silent: ErrContentTooLarge was
// returned correctly by cloudresources, recorded by the bridge, and then dropped by
// firstBudgetError, so the refusal was logged and never disclosed (#414). One predicate cannot
// drift out of step with itself.
//
// Callers that need to distinguish WHICH guard fired (to word a message) still switch on the
// specific sentinel; this answers only "was coverage cut short".
func IsCoverageCutShort(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, ErrMatchBudgetExceeded) ||
		errors.Is(err, ErrContentTooLarge) ||
		errors.Is(err, ErrValidatorPanicked)
}

// ContextAwareValidator is an OPTIONAL extension of detector.Validator. A
// validator that implements it receives the active context and is expected to
// poll ctx.Err() at loop/match boundaries so it can abort promptly on deadline
// or cancellation. Validators that do not implement it keep their current
// behavior and are invoked through the legacy ValidateContent method.
type ContextAwareValidator interface {
	ValidateContentCtx(ctx context.Context, content, originalPath string) ([]detector.Match, error)
}

// SafeRun executes fn under panic recovery and best-effort boundary
// cancellation. It is the primitive both fan-out sites use.
//
// Semantics:
//   - If ctx is already cancelled/expired when SafeRun is entered, fn is NOT
//     invoked and ctx.Err() is returned. (A validator already in flight cannot
//     be interrupted in Phase 1 — see package doc — but new work is not started.)
//   - If fn panics, the panic is recovered and returned as a NON-retryable
//     resilience error. matches is reset to nil so a partial slice produced
//     before the panic is never surfaced as if it were complete.
//
// Note on no-payload-bytes: the recovered value is interpolated into the error
// message. Runtime panics (nil map, index out of range, etc.) carry no payload
// content; a validator that explicitly panic()s with matched bytes would be the
// only way payload could reach this message, which no current validator does.
// Callers already gate validator-error logging behind --debug.
func SafeRun(ctx context.Context, name string, fn func() ([]detector.Match, error)) (matches []detector.Match, err error) {
	defer func() {
		if r := recover(); r != nil {
			matches = nil
			// Non-retryable: a deterministic panic will panic again on retry,
			// so re-running it only amplifies the failure. NewPermanentError
			// produces a *resilience.ClassifiedError that ClassifyError returns
			// verbatim (Retryable=false), bypassing string-based reclassification.
			// The sentinel goes in the CAUSE slot, not the message, so
			// errors.Is traverses to it via ClassifiedError.Unwrap. Matching on
			// the message text would work today and break the first time anyone
			// reworded it.
			err = resilience.NewPermanentError(
				fmt.Sprintf("validator %q panicked: %v", name, r), ErrValidatorPanicked)
		}
	}()

	if ctx != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
	}

	return fn()
}

// ValidateContent dispatches a single validator's content validation through the
// chokepoint: it prefers the context-aware method when the validator implements
// ContextAwareValidator, otherwise it calls the legacy ValidateContent. Either
// way the call is wrapped by SafeRun (panic recovery + boundary cancellation).
func ValidateContent(ctx context.Context, name string, v detector.Validator, content, originalPath string) ([]detector.Match, error) {
	b := budgetFor(ctx, name)

	// Per-validator TIME budget: derive a child deadline tighter than the parent
	// (per-file/job) deadline. context.WithTimeout never extends a parent deadline,
	// so the tighter of {parent, TimeLimit} always wins. The derived ctx is the one
	// handed to a ContextAwareValidator, which polls it via LineLoopCancelled — so
	// a runaway validator self-terminates at its own budget. Disabled (<=0) leaves
	// ctx untouched: byte-identical to the no-budget path.
	if b.TimeLimit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.TimeLimit)
		defer cancel()
	}

	matches, err := SafeRun(ctx, name, func() ([]detector.Match, error) {
		if cav, ok := v.(ContextAwareValidator); ok {
			return cav.ValidateContentCtx(ctx, content, originalPath)
		}
		return v.ValidateContent(content, originalPath)
	})

	// SECOND PASS over a canonicalised copy, for the characters ordinary software substitutes.
	//
	// RE2 makes \d and \s ASCII-only, so every structured pattern in this repository is anchored on
	// ASCII while a word processor, a PDF extractor or an HTML paste routinely produces something
	// else. Measured at HEAD, 61 of 80 combinations of 8 structured types and 10 substitutions lost
	// the finding entirely — an SSN typed into Word and touched by autocorrect reported clean (#671).
	//
	// ADDITIVE, never a replacement. The first pass above is untouched, so no existing finding moves
	// and ASCII content behaves byte-identically. This only adds matches the ASCII patterns could not
	// see, and each one is verified against the original bytes before it is trusted — see
	// normalizedPassMatches.
	//
	// Gated on the content containing such a character NEXT TO A DIGIT, not merely containing one.
	// The broader gate was measured and rejected: 833 of 1,497 real documents contain a normalizable
	// character — almost always an en dash or a non-breaking space in prose — so gating on that alone
	// ran every validator twice on 55% of the corpus for +59% wall clock and 8 findings. See
	// textnorm.HasNormalizableNearDigit for the measurement and the reasoning.
	//
	// Placed BEFORE the match budget below so the cap applies to the union rather than to the first
	// pass alone: a budget that counted only one pass would let the total exceed it.
	if err == nil && textnorm.HasNormalizableNearDigit(content) {
		matches = append(matches, normalizedPassMatches(ctx, name, v, content, originalPath, matches)...)
	}

	// Per-validator MATCH budget: cap only a SUCCESSFUL result. Never truncate a
	// partial slice returned alongside an error (e.g. ctx.Err() from a timed-out
	// scan) — that path already carries its own incompleteness meaning, and
	// dropping matches a timed-out scan did find would double-signal. When the
	// count is at/under the cap (or the cap is disabled), matches is returned
	// completely unmutated: byte-identical to the no-budget path.
	if err == nil && b.MatchLimit > 0 && len(matches) > b.MatchLimit {
		matches = matches[:b.MatchLimit]
		err = fmt.Errorf("%w: validator %q emitted more than %d matches", ErrMatchBudgetExceeded, name, b.MatchLimit)
	}
	return matches, err
}

// normalizedPassMatches runs the validator over a canonicalised copy of content and returns the
// matches the ASCII pass could not see, each carrying the ORIGINAL bytes.
//
// # Why the reported text must be the original
//
// Redaction is text-based: internal/redactors/plaintext locates a finding with
// strings.Index(text, match.Text) and asserts actualText == match.Text before writing. A match
// reported with normalized text would therefore not be found in the file, and this detection fix
// would become a redaction failure — values reported and then left in cleartext, which is the one
// outcome the sink rule forbids. So every match from the normalized copy is translated back through
// textnorm's offset table and re-sliced from the original line.
//
// # The verification gate
//
// A mapping that is subtly wrong is worse than a missing finding: it would mask the wrong bytes and
// leave the value in place. So each recovered span is checked — folding the original substring must
// reproduce exactly what the validator matched — and a match that fails is DROPPED rather than
// reported. That trades a finding for never redacting the wrong bytes, and the drop is silent only in
// the sense that the value was already invisible before this pass existed.
func normalizedPassMatches(
	ctx context.Context,
	name string,
	v detector.Validator,
	content, originalPath string,
	first []detector.Match,
) []detector.Match {
	normalized, _ := textnorm.Normalize(content)
	if normalized == content {
		return nil
	}

	found, err := SafeRun(ctx, name, func() ([]detector.Match, error) {
		if cav, ok := v.(ContextAwareValidator); ok {
			return cav.ValidateContentCtx(ctx, normalized, originalPath)
		}
		return v.ValidateContent(normalized, originalPath)
	})
	if err != nil || len(found) == 0 {
		// A failure in the ADDITIVE pass must not fail the scan: the first pass already succeeded,
		// and its findings are what the caller is entitled to. The incompleteness of this pass is
		// bounded by what it could have added, which is nothing the ASCII patterns would have found.
		return nil
	}

	// What the first pass already reported, keyed on the canonical form so the same value is not
	// reported twice in different spellings.
	seen := make(map[string]struct{}, len(first))
	for _, m := range first {
		seen[matchKey(m.Type, m.LineNumber, textnorm.Fold(m.Text))] = struct{}{}
	}

	origLines := strings.Split(content, "\n")
	normLines := strings.Split(normalized, "\n")

	var out []detector.Match
	for _, m := range found {
		key := matchKey(m.Type, m.LineNumber, textnorm.Fold(m.Text))
		if _, dup := seen[key]; dup {
			continue
		}

		// LineNumber is 1-based. Normalization replaces runes and drops zero-width ones; it never
		// touches a newline, so the two slices have the same length and a line number means the same
		// thing in both.
		idx := m.LineNumber - 1
		if idx < 0 || idx >= len(origLines) || idx >= len(normLines) {
			continue
		}
		origLine, normLine := origLines[idx], normLines[idx]

		start := strings.Index(normLine, m.Text)
		if start < 0 {
			continue // cannot locate it, so cannot map it
		}
		_, lineOffsets := textnorm.Normalize(origLine)
		oStart, oEnd := textnorm.OrigSpan(lineOffsets, start, start+len(m.Text))
		if oStart < 0 || oEnd > len(origLine) || oEnd <= oStart {
			continue
		}
		origText := origLine[oStart:oEnd]

		// GATE 1 — CORRECTNESS: the original bytes must fold to exactly what the validator matched.
		if textnorm.Fold(origText) != m.Text {
			continue
		}

		// GATE 2 — PRECISION: the value must not be ordinary prose.
		//
		// Canonicalising dashes and spaces creates spurious STRUCTURE in running text. Measured over
		// 1,497 real documents, the pass without this gate added 28 findings of which about 26 were
		// false positives, every one from a validator that reads a dash as a separator rather than as
		// punctuation:
		//
		//	RECOVERY_CODES  "long-term", "avail<HYPHEN>able", "MACsec<NBHYPHEN>encrypted", "endpoints<EMDASH>..."
		//	PERSON_NAME     "Flushing Meadows<ENDASH>Corona" — a park, an already-known FP class
		//
		// The test is a property of the VALUE, not a list of validators: a hand-maintained opt-in list
		// would have been incomplete on day one and would not cover a validator added later.
		//
		// An earlier version required two ASCII digits, which was measurably WRONG: it cut the false
		// positives to 7 but also dropped an AWS access key written with fullwidth digits, because
		// AKIAIOSFODNN7EXAMPLE contains exactly one digit. A secret is not prose, and a gate that
		// cannot tell those apart is the wrong gate. isProse asks the question directly.
		if isProse(m.Text) {
			continue
		}

		m.Text = origText
		m.Context.FullLine = origLine
		// Columns are assigned at the scan convergence from the ORIGINAL line; a column computed
		// against the normalized copy would address the wrong bytes.
		m.StartColumn = 0
		m.EndColumn = 0
		m.SecureText = nil // rebuilt downstream from Text; a stale copy would carry normalized bytes

		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}

// matchKey identifies a finding for dedup across the two passes: the same value on the same line from
// the same validator is one finding however it was spelled.
func matchKey(typ string, line int, folded string) string {
	return typ + "\x00" + strconv.Itoa(line) + "\x00" + folded
}

// isProse reports whether s looks like ordinary running text rather than a structured value.
//
// Prose here means: it contains a lowercase letter, no digit, and no character outside the set that
// running text uses — letters, spaces and hyphens. Anything else is structure:
//
//	"long-term", "avail-able", "MACsec-encrypted"   prose      -> rejected
//	"Flushing Meadows-Corona"                       prose      -> rejected
//	"AKIAIOSFODNN7EXAMPLE"                          no lower   -> kept (an AWS key)
//	"jane.roe@corp.example"                         has @ and . -> kept (an address)
//	"449-87-4100", "GB82 WEST 1234 ..."             has digits -> kept
//
// Judged on the FOLDED text, which is what the validator matched, so a Unicode dash has already
// become '-' and a fullwidth digit has already become '0'-'9' by the time this runs.
//
// Deliberately not complete: "L1076-L1085", a line-range reference, has digits and no lowercase, so it
// is still reported by RECOVERY_CODES. Three such findings survive across the 1,497-document corpus.
// That is the residual cost of the pass, set against 53 invariance violations it removes — and the
// alternative, a per-validator allowlist, trades a bounded and visible cost for an unbounded and
// invisible one.
func isProse(s string) bool {
	hasLower, hasDigit := false, false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r >= 'A' && r <= 'Z', r == ' ', r == '-':
			// Letters, spaces and hyphens are what running text is made of.
		default:
			// Anything else — '@', '.', '/', '+', '=', ':' — is structure, not prose.
			return false
		}
	}
	return hasLower && !hasDigit
}
