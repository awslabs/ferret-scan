// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Declared redaction capability: which registered file types can actually be rewritten.
//
// # The problem this exists to solve
//
// A redactor declares the types it handles through GetSupportedTypes, and RegisterRedactor indexes it
// under every one of them. Nothing checked that a declared type could actually be redacted, and two
// redactors declare types they always refuse:
//
//	pdf    "pdf", ".pdf"                          RedactDocument and RedactContent both return an
//	                                              error unconditionally — content redaction is not
//	                                              implemented, and refusing is correct because a
//	                                              "redacted" PDF still holding the values would be
//	                                              worse than no output.
//	image  ".gif" ".bmp" ".tiff" ".tif" ".webp"   The format switch implements JPEG and PNG only; every
//	                                              other declared extension reaches an arm that returns
//	                                              "metadata redaction not implemented for X images",
//	                                              for the same fail-safe reason.
//
// Measured at HEAD with the real binary: a .pdf with one finding and a .tiff with one finding each
// write ZERO artifacts, while .txt, .csv, .svg, .rtf, .docx, .wav, .jpg and .png each write one.
//
// The runtime already handles this honestly — both refusals reach the operator as
// UnredactedNoRedactor, "no redactor for this file type", with a detail naming the format, in every
// output format. What was missing is that the declaration was not machine-readable, so nothing could
// check a DOCUMENTED claim against it. `--help` advertised
// `ferret-scan --file *.pdf --enable-redaction --redaction-output-dir ./safe-docs`, a command that can
// never succeed, and README.md promised ".pdf→.pdf"; the architecture docs listed a "PDF Redactor"
// among four working redactors (#686).
//
// # Why a declaration rather than a probe
//
// The honest alternative is to attempt a redaction of every declared type and see what happens. That
// needs a valid fixture for each of 25 declared extensions — including WEBP, legacy OLE and three
// video containers — which is more fixture engineering than the question deserves. So capability is
// DECLARED here and CROSS-CHECKED empirically for every type a cheap fixture can be built for, which
// catches drift in both directions: a type declared unimplemented that starts working, and a type
// declared working that starts refusing. See cmd/documented_redaction_test.go.
//
// A redactor that implements every type it declares does not need to do anything; the interface is
// optional and its absence means "all declared types are implemented".

// UnimplementedTypeDeclarer is implemented by a redactor that is registered for file types it cannot
// actually rewrite.
//
// Returning a reason rather than a bool is deliberate: the reason is the thing an operator and a
// reviewer both need, it keeps the explanation next to the code that refuses, and it means the
// docs guard can quote WHY a documented claim is false rather than only that it is.
type UnimplementedTypeDeclarer interface {
	// UnimplementedTypes maps each declared file type this redactor cannot redact to the reason.
	// Keys are matched case-insensitively and with or without a leading dot, exactly as
	// RegisterRedactor normalises them. An empty map means every declared type works.
	UnimplementedTypes() map[string]string
}

// NormalizeType renders a file type the way RegisterRedactor indexes it: lowercased, with exactly one
// leading dot. Exported so a declaration, the registry and a guard cannot disagree about spelling —
// "PDF", "pdf" and ".pdf" are one type, and a redactor that declares both spellings (most do) must
// not appear to have two different capabilities.
func NormalizeType(fileType string) string {
	t := strings.ToLower(strings.TrimSpace(fileType))
	if t == "" {
		return ""
	}
	if !strings.HasPrefix(t, ".") {
		t = "." + t
	}
	return t
}

// Capabilities is the redaction capability of a registry, split by whether a declared type can
// actually be redacted.
type Capabilities struct {
	// Redactable are the normalised types a registered redactor both declares AND implements.
	Redactable []string
	// Unimplemented maps a normalised type a redactor declares but cannot rewrite to its reason.
	Unimplemented map[string]string
}

// IsRedactable reports whether fileType can actually be redacted. Any spelling is accepted.
func (c Capabilities) IsRedactable(fileType string) bool {
	t := NormalizeType(fileType)
	if _, no := c.Unimplemented[t]; no {
		return false
	}
	for _, r := range c.Redactable {
		if r == t {
			return true
		}
	}
	return false
}

// ReasonUnimplemented returns why fileType cannot be redacted, or "" if it can be (or is unknown).
func (c Capabilities) ReasonUnimplemented(fileType string) string {
	return c.Unimplemented[NormalizeType(fileType)]
}

// Capabilities reports what this manager's registered redactors can actually do.
//
// Derived from the live registry rather than from a list kept beside it, so a redactor added,
// removed or re-declared is reflected without anyone remembering to update a second place. That is
// the whole point: the previous arrangement had the capability implied by code in one package and
// asserted by prose in four files, with nothing connecting them.
func (rm *RedactionManager) Capabilities() Capabilities {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	caps := Capabilities{Unimplemented: map[string]string{}}
	for fileType, redactor := range rm.redactors {
		t := NormalizeType(fileType)
		if decl, ok := redactor.(UnimplementedTypeDeclarer); ok {
			if reason, unimplemented := lookupReason(decl.UnimplementedTypes(), t); unimplemented {
				caps.Unimplemented[t] = reason
				continue
			}
		}
		caps.Redactable = append(caps.Redactable, t)
	}
	sort.Strings(caps.Redactable)
	return caps
}

// lookupReason finds t in a declaration map, tolerating either spelling on either side so a
// declaration written as "pdf" still matches a registry key of ".pdf".
func lookupReason(declared map[string]string, t string) (string, bool) {
	for k, reason := range declared {
		if NormalizeType(k) == t {
			return reason, true
		}
	}
	return "", false
}

// Declared strategy support: which of the three strategies a redactor can honour (#863).
//
// GetSupportedStrategies has been on the Redactor interface since the interface existed, and until
// this nothing outside a test ever called it. Three redactors -- audio, video and legacy OLE --
// rewrite a value in place at its own byte length, so they leave synthetic out of their declaration
// and their comments say the strategy "is declined" so "the caller can choose another". Nothing
// declined it. Measured on main at b0a9163 with --checks EMAIL,PHONE,CREDIT_CARD on all twelve of
// their extensions: --redaction-strategy synthetic wrote a same-length '*' mask at exit 0 with an
// empty stderr, a rendering no document describes, while the audit log and
// RedactFileResult.Strategy recorded "synthetic".
//
// CheckStrategy is the one place a declaration is enforced. RedactorFor applies it where this
// package dispatches a file, and the same-length redactors apply it again at their own entry point,
// so a strategy a redactor does not declare is refused -- disclosed, nothing written -- instead of
// being rendered as something else.

// ErrStrategyNotSupported is wrapped by the error returned when a file's redactor does not declare
// the requested strategy. Nothing was written for that file.
var ErrStrategyNotSupported = errors.New("redaction strategy not supported for this file type")

// SupportsStrategy reports whether r declares s in GetSupportedStrategies.
func SupportsStrategy(r Redactor, s RedactionStrategy) bool {
	for _, d := range r.GetSupportedStrategies() {
		if d == s {
			return true
		}
	}
	return false
}

// CheckStrategy returns nil when matches may be handed to r under s, and otherwise an error wrapping
// ErrStrategyNotSupported that names s and the strategies r declares, so the operator can pick one.
//
// A dispatch with no matches is never refused. Nothing would be rendered, so no strategy is being
// applied, and refusing would report a clean or fully suppressed file as unredacted.
func CheckStrategy(r Redactor, s RedactionStrategy, matches []detector.Match) error {
	if len(matches) == 0 || SupportsStrategy(r, s) {
		return nil
	}
	declared := r.GetSupportedStrategies()
	names := make([]string, 0, len(declared))
	for _, d := range declared {
		names = append(names, d.String())
	}
	return fmt.Errorf("%w: %s supports %s, not %s", ErrStrategyNotSupported,
		r.GetName(), strings.Join(names, " and "), s)
}

// RedactorFor selects the redactor for a dispatch of matches under strategy: GetRedactorForFile's
// choice, refused with an error wrapping ErrStrategyNotSupported when that redactor does not declare
// strategy. A selection failure is returned exactly as GetRedactorForFile returns it, so a caller can
// still tell "no redactor for this type" from "this type cannot take this strategy".
func (rm *RedactionManager) RedactorFor(filePath string, strategy RedactionStrategy, matches []detector.Match) (Redactor, error) {
	r, err := rm.GetRedactorForFile(filePath)
	if err != nil {
		return nil, err
	}
	if err := CheckStrategy(r, strategy, matches); err != nil {
		return nil, err
	}
	return r, nil
}
