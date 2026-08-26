// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package coverage holds the reason a file was not fully examined, shared by the two halves that
// cannot import each other.
//
// It is a leaf package with no internal dependencies, for the same structural reason internal/embedded
// is one: the PRODUCER of a coverage-loss record is a preprocessor, and the CONSUMER that reports it
// is internal/parallel — and internal/parallel already imports internal/preprocessors, so the reverse
// edge would be a cycle. Verified with go list -deps rather than assumed.
//
// Keeping one definition also makes the failure this fixes unrepresentable rather than merely
// detected: while each layer owned its own idea of the cause, the layers could disagree, and they did.
package coverage

// A coverage-loss record used to carry only prose, and every consumer recovered the CAUSE by
// pattern-matching that prose. That is the shared root of four defects:
//
//   - internal/core/scanner.go stamped "no document text extracted from %s" on every
//     EmptyExtractionFiles entry, because the prefix came from the BUCKET NAME rather than from what
//     the producer meant. A file whose text WAS read but whose coverage was cut short was therefore
//     described as having no text (#432).
//   - cmd/unscanned_report.go's classifyReason matches substrings and its default arm returns
//     "coverage cut short", so any reason string it does not recognise is labelled with a cause that
//     may be wrong — including a router size refusal filed as an unsupported TYPE (#412).
//   - pkg/scan gave a library consumer one bool and a prose string where the CLI had six causes
//     (#391), and the web UI re-derived its own partial view of the same thing (#417).
//
// The taxonomy started as the same six causes
// cmd/unscanned_report.go already defined, with the same user-facing strings — those strings are a
// tested contract (`cannot read` alone is asserted in ten test files) and a documented one. What
// changed first was WHERE a cause comes from: the producer states it, instead of every consumer
// guessing it back out of English.
//
// A seventh, CauseNotRegular, was added for #485: a non-regular directory entry was dropped from the
// walk with no record at all, so a directory holding a named pipe was indistinguishable from one
// without it.

// Cause is why a file was not examined, as the producer of the record knew it.
type Cause int

const (
	// CauseUnset is the zero value, and it deliberately does NOT mean "cannot read".
	//
	// This matters more than it looks. The cmd-side enum starts its iota at causeUnreadable, so if
	// this one did the same, every producer not yet updated would silently claim the file could not be
	// read — asserting a failure that did not happen, which is the most misleading of the six. Unset
	// instead routes the record to the prose fallback, which is exactly the behaviour it had before.
	CauseUnset Cause = iota

	// CauseUnreadable: permissions, a vanished path, an I/O error. Nothing about the file is known.
	CauseUnreadable
	// CauseUnparseable: the bytes do not match the declared type, so no text was recovered.
	CauseUnparseable
	// CauseNoText: opened and parsed, no body text found. Metadata on the same file IS still scanned
	// and may already have produced findings, which is why the rendered string says so.
	CauseNoText
	// CauseCutShort: a budget, size cap or timeout fired, so the file is PARTLY scanned.
	CauseCutShort
	// CauseNotFollowed: a link the walk deliberately did not follow — dangling, looping, naming a
	// directory or device, or resolving outside the scanned tree. Distinct from CauseUnreadable
	// because for most of these the file could have been read and the tool chose not to.
	CauseNotFollowed
	// CauseTooLarge: over the size limit and therefore never opened, and of a type the tool WOULD
	// otherwise have processed. An unprocessable type refused for size is a genuine skip and gets no
	// record at all.
	CauseTooLarge
	// CauseNotRegular: the directory entry itself is not a regular file — a named pipe, a socket, a
	// device node, or on Windows a junction, mount point or other non-symlink reparse point.
	//
	// Distinct from CauseNotFollowed, which is about a LINK the walk declined: here there is no link,
	// the entry IS the object. Reusing that cause would render "symlink not followed" for a FIFO, and
	// a true disclosure under a false heading is only half a fix. Distinct from CauseUnreadable for
	// the reason CauseNotFollowed is: the bytes were not unreadable, the tool declined to read them.
	//
	// Appended rather than inserted so the existing values keep their numbers.
	CauseNotRegular
)

// String renders the cause as the operator sees it.
//
// These strings are copied deliberately from cmd/unscanned_report.go rather than reworded: they are
// asserted across the test suite and documented in docs/COVERAGE_DISCLOSURE.md, so they are part of
// the tool's contract. A test pins them against that file so the two cannot drift.
func (c Cause) String() string {
	switch c {
	case CauseUnreadable:
		return "cannot read"
	case CauseUnparseable:
		return "cannot parse"
	case CauseNoText:
		return "no body text (metadata still scanned)"
	case CauseCutShort:
		return "coverage cut short"
	case CauseNotFollowed:
		return "symlink not followed"
	case CauseTooLarge:
		return "file too large to scan"
	case CauseNotRegular:
		return "not a regular file"
	default:
		return "unknown"
	}
}

// Known reports whether the producer stated a cause.
//
// A consumer calls this to decide between the stated cause and the prose fallback. Written as a
// method rather than an `== CauseUnset` comparison at each call site so that adding a second
// not-really-known value later is one edit instead of a search.
func (c Cause) Known() bool { return c != CauseUnset }

// Reduce combines the causes of several warnings about ONE file into the single cause a report shows.
//
// A container is read by more than one preprocessor — an .docx goes through office_text and
// office_metadata — and each may warn for its own reason. The router joins their notes with "; ", and
// before causes were typed the consumer inferred one cause from that joined string: it returned
// no-body-text only when EVERY segment carried the no-body-text marker, and otherwise cut-short.
//
// This reproduces that rule with types instead of substrings:
//
//   - nothing stated            -> unset, so the caller keeps its prose fallback
//   - one cause, or all agree   -> that cause, which is the common case and is exact
//   - disagreement              -> CauseCutShort
//
// Cut-short is the right answer for a mixed set because it is the only member that describes a
// PARTIAL result, and disagreement means exactly that: one reader got something, another did not. The
// alternative — picking the first, or the most severe — would report one reader's experience as though
// it were the file's.
func Reduce(causes []Cause) Cause {
	out := CauseUnset
	for _, c := range causes {
		if !c.Known() {
			continue
		}
		switch {
		case !out.Known():
			out = c
		case out != c:
			return CauseCutShort
		}
	}
	return out
}
