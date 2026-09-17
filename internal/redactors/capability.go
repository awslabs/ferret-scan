// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"sort"
	"strings"
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
