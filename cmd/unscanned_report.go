// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// One report for every file the tool could not examine, grouped by cause.
//
// Before this, the four failure modes each printed their own WARNING block in
// whatever order they were emitted, and each line repeated the path and then
// appended a raw Go error:
//
//	WARNING: scan incomplete — 1 of 1 file(s) could not be opened, so they were
//	not scanned at all; any sensitive data they contain was NOT detected:
//	  /tmp/x/noperm.txt: Unreadable: open /tmp/x/noperm.txt: permission denied
//
// The path appears three times (prefix, wrapper, *PathError), "Unreadable:" is
// internal vocabulary, and a directory with several kinds of failure produced
// several unrelated banners. The consequence — these files are NOT clean — is
// buried in a subordinate clause of a sentence the reader has already skipped.
//
// The replacement states the consequence first, groups by cause, prints each path
// once, and translates the error into something a person can act on.

// unscannedCause is a coarse, user-facing reason a file was not examined.
//
// Deliberately coarse: the point is what the operator must DO about it, not which
// internal component reported it. "cannot read" means fix permissions or the path;
// "cannot parse" means the bytes do not match the extension; "no text extracted"
// means the file is a container or image the tool opened but found nothing readable
// in; "coverage cut short" means a budget or timeout fired and the file is only
// partly scanned.
type unscannedCause int

const (
	causeUnreadable unscannedCause = iota
	causeUnparseable
	causeNoText
	causeCutShort
	// causeNotFollowed is a link the walk deliberately did not follow: it dangles or
	// loops, names a directory, names a device, or resolves outside the scanned tree.
	//
	// Distinct from causeUnreadable because for most of these the file COULD be read —
	// the tool chose not to. Filing them under "cannot read" would assert a failure
	// that did not happen, and the operator's action differs: a permission problem is
	// fixed with chmod, a link out of the tree is fixed by scanning the target directly
	// or passing it explicitly. See #326.
	causeNotFollowed
	// causeTooLarge is a file that exceeds the size limit and was therefore never
	// opened, whose TYPE the tool would otherwise have processed.
	//
	// A size-refused file was previously recorded as "skipped", which is the wrong
	// half of a distinction ScanStats itself draws: a skipped file is an unsupported
	// type nobody expected a result for, an unexamined one was expected to produce
	// something and did not. Worse, a size refusal reached no counter at all — not
	// total_files, not files_skipped, not files_not_examined — so a directory holding
	// a 105MB document reported a complete, clean scan and --fail-on-incomplete
	// exited 0. See #324.
	//
	// An UNPROCESSABLE type refused for size gets no entry here at all; it is a
	// genuine skip, because no finding was ever possible from it.
	causeTooLarge
)

func (c unscannedCause) String() string {
	switch c {
	case causeUnreadable:
		return "cannot read"
	case causeUnparseable:
		return "cannot parse"
	case causeNoText:
		// Names the BODY specifically: metadata on the same file is extracted and
		// scanned through a separate channel, so "no text" without that qualifier
		// reads as "nothing was scanned" on a file that may have produced findings.
		return "no body text (metadata still scanned)"
	case causeCutShort:
		return "coverage cut short"
	case causeNotFollowed:
		return "symlink not followed"
	case causeTooLarge:
		return "file too large to scan"
	default:
		return "unknown"
	}
}

// unscannedEntry is one file and why it was not examined.
type unscannedEntry struct {
	Path   string
	Cause  unscannedCause
	Detail string
}

// toFormatterNotExamined converts the cmd-side entries into the formatter-facing
// type, so machine formats can carry the disclosure as DATA.
//
// The classification stays HERE rather than moving into internal/formatters. The
// reason is not tidiness: classifyReason and describeUnparseable perform filesystem
// I/O (describeUnparseable calls os.Open to sniff a file's real magic bytes), and
// the formatters package is reachable from the web server's /export handler with
// user-supplied filenames. Moving path-touching code into it would put file reads
// behind an HTTP surface. Only this small pure mapping crosses the boundary.
//
// The two cause enums are mapped explicitly rather than by numeric conversion.
// unscannedCause and formatters.NotExaminedCause happen to share an order today, so
// int(c) would compile and pass — and would silently mis-label every file the day
// either list grows a member. The switch fails to compile on a new cmd-side cause
// only if the default is removed, so the default deliberately maps to the most
// conservative option: "cannot read" claims the least about what was scanned.
func toFormatterNotExamined(entries []unscannedEntry) []formatters.NotExaminedFile {
	if len(entries) == 0 {
		return nil
	}
	out := make([]formatters.NotExaminedFile, 0, len(entries))
	for _, e := range entries {
		var cause formatters.NotExaminedCause
		switch e.Cause {
		case causeUnreadable:
			cause = formatters.NotExaminedUnreadable
		case causeUnparseable:
			cause = formatters.NotExaminedUnparseable
		case causeNoText:
			cause = formatters.NotExaminedNoText
		case causeCutShort:
			cause = formatters.NotExaminedCutShort
		case causeNotFollowed:
			cause = formatters.NotExaminedNotFollowed
		case causeTooLarge:
			cause = formatters.NotExaminedTooLarge
		default:
			cause = formatters.NotExaminedUnreadable
		}
		out = append(out, formatters.NotExaminedFile{
			Path:   e.Path,
			Cause:  cause,
			Detail: e.Detail,
		})
	}
	return out
}

// humanizeReason turns an internal reason string into something actionable.
//
// The transformations are all subtractive — remove the path, remove the internal
// prefix, unwrap Go's error decoration — because inventing new prose risks
// describing a failure mode that did not happen. What is left is the part the
// operator can act on.
func humanizeReason(path, reason string) string {
	r := reason

	// The reason frequently embeds the path once or twice; the caller already
	// prints it, so strip every occurrence.
	if path != "" {
		r = strings.ReplaceAll(r, path, "")
	}

	// Drop internal prefixes that name a component rather than a problem.
	for _, prefix := range []string{
		"Unreadable:",
		"could not process :",
		"could not process:",
		"all preprocessors failed for file:",
		"all preprocessors failed for file",
	} {
		r = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r), prefix))
	}

	// Unwrap Go's "open <path>: " decoration left behind by *PathError.
	r = strings.TrimSpace(r)
	r = strings.TrimPrefix(r, "open :")
	r = strings.TrimPrefix(r, "open ")
	r = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r), ":"))

	// Collapse the whitespace the removals left behind.
	r = strings.Join(strings.Fields(r), " ")

	if r == "" {
		return ""
	}
	return r
}

// describeUnparseable explains WHY a file could not be parsed, by checking the bytes
// rather than trusting the extension.
//
// The distinction matters: reading the first four bytes tells us whether a .docx
// really begins with a zip signature. "starts with a zip header but could not be
// opened" is an observation; "corrupt Office document" inferred from the extension
// alone would be a guess, and a wrong guess sends the operator looking in the wrong
// place. Where nothing can be verified it says so plainly instead of inventing a
// cause.
func describeUnparseable(path string) string {
	f, err := os.Open(path) //nolint:gosec // path came from the scan target list
	if err != nil {
		return "could not be re-opened to diagnose"
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err == nil && fi.Size() == 0 {
		return "file is empty (0 bytes)"
	}

	var head [8]byte
	n, _ := io.ReadFull(f, head[:])
	sig := head[:n]

	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case bytes.HasPrefix(sig, []byte("PK\x03\x04")):
		return "zip signature present but the archive could not be opened (truncated or corrupt)"
	case bytes.HasPrefix(sig, []byte("%PDF")):
		return "PDF header present but no readable pages"
	case bytes.HasPrefix(sig, []byte{0xd0, 0xcf, 0x11, 0xe0}):
		return "legacy Office signature present but the streams could not be read"
	case ext != "":
		return fmt.Sprintf("contents do not match the %s format", ext)
	default:
		return "format not recognised"
	}
}

// noBodyTextPrefix is the wording every producer of a "the body held no text" warning uses,
// and it is the CONTRACT that lets this side tell the two meanings of an extraction warning
// apart. See classifyExtractionWarning.
const noBodyTextPrefix = "no text extracted from"

// classifyExtractionWarning maps an ExtractionWarning to a user-facing cause.
//
// The ExtractionWarning channel carries two different statements, and this side used to file
// every one of them under causeNoText:
//
//	"no text extracted from .docx: no document body part was found"      <- the body was empty
//	"embedded part %q was not examined: declares N bytes, over the cap"  <- the body was fine
//
// Reporting the second as "no body text (metadata still scanned)" asserts something untrue
// about a document whose body text was read and scanned normally, and it is exactly the
// mislabelling the cause taxonomy warns about: an operator cannot act on a reason that
// describes a different failure. A container with an oversize embedded part is PARTLY
// scanned, which is what causeCutShort means.
//
// The discriminator is the prefix rather than a keyword grab-bag, because every no-text
// producer builds its message from one helper and shares that prefix — the office text
// extractor, both PDF paths. Anything else on this channel is a coverage note: a WAV whose
// chunk layout could not be walked to the end, an embedded part refused for size, an embedded
// container past the nesting bound. Those are all partial coverage.
//
// A structured cause travelling with the diagnostic would be better than matching on prose,
// and would mean threading a field from every preprocessor through worker_pool and
// parallel_processor into FileDiagnostic. That is worth doing and is not this change; the
// prefix is asserted by a test that enumerates every producer, so a new wording that lands in
// the wrong bucket fails there rather than in a report.
// A file can carry BOTH statements at once, joined with "; " by the router or by the Office
// preprocessor. It is then only a no-text case if EVERY segment says so: one segment about an
// unexamined part means coverage really was cut short, and that is the fact the operator has to
// act on. Segment-wise rather than a whole-string match, because a substring test would let a
// leading no-text warning hide an unexamined embedded document behind it.
func classifyExtractionWarning(reason string) unscannedCause {
	segments := strings.Split(reason, "; ")
	for _, seg := range segments {
		seg = strings.ToLower(strings.TrimSpace(seg))
		if seg == "" {
			continue
		}
		// The router and the Office preprocessor prefix a segment with the producing
		// preprocessor's name ("office_metadata: no text extracted from ..."), so the
		// marker can sit after a prefix rather than at the start of the segment.
		if !strings.Contains(seg, noBodyTextPrefix) {
			return causeCutShort
		}
	}
	return causeNoText
}

// classifyReason maps a diagnostic to a user-facing cause.
func classifyReason(reason string) unscannedCause {
	l := strings.ToLower(reason)
	switch {
	case strings.Contains(l, "permission denied"),
		strings.Contains(l, "unreadable"),
		strings.Contains(l, "no such file"):
		return causeUnreadable
	case strings.Contains(l, "preprocessors failed"),
		strings.Contains(l, "not a valid"),
		strings.Contains(l, "corrupt"):
		return causeUnparseable
	case strings.Contains(l, "no extractable text"),
		strings.Contains(l, "empty extraction"),
		strings.Contains(l, "no text"):
		return causeNoText
	default:
		return causeCutShort
	}
}

// collectUnscanned merges the four diagnostic channels into one ordered list.
//
// Order is by cause then path so the output is deterministic: this is stderr a
// human reads and a script may diff, and a set iterated in map order would shuffle
// between runs for no reason.
func collectUnscanned(
	unreadable []string,
	emptyExtraction []parallel.FileDiagnostic,
	failed []parallel.FileDiagnostic,
	incomplete []parallel.FileDiagnostic,
	discovery []unscannedEntry,
) []unscannedEntry {
	var out []unscannedEntry

	// Coverage losses found while DISCOVERING files rather than while scanning them:
	// a symlink the walk refused (#326), a file refused for size (#324). Before those
	// they reached no channel at all — dropped with no record anywhere, so the content
	// was neither scanned nor disclosed.
	//
	// These arrive already classified, because discovery is the only place that knows
	// WHY it declined. Forcing them all to one cause is what made every refused
	// symlink and every oversize file share a label.
	out = append(out, discovery...)

	// The unreadable channel is a pre-formatted "path: reason" string rather than
	// a struct, so it needs splitting on the first colon that follows the path.
	for _, s := range unreadable {
		path, reason := s, ""
		if i := strings.Index(s, ": "); i > 0 {
			path, reason = s[:i], s[i+2:]
		}
		out = append(out, unscannedEntry{
			Path:   path,
			Cause:  causeUnreadable,
			Detail: firstNonEmpty(humanizeReason(path, reason), "could not be opened"),
		})
	}

	for _, fd := range emptyExtraction {
		d := humanizeReason(fd.FilePath, fd.Reason)
		if d == "" {
			d = "no readable text found"
		}
		out = append(out, unscannedEntry{fd.FilePath, classifyExtractionWarning(fd.Reason), d})
	}
	for _, fd := range failed {
		cause := classifyReason(fd.Reason)
		detail := humanizeReason(fd.FilePath, fd.Reason)
		if cause == causeUnparseable && detail == "" {
			// The internal reason ("all preprocessors failed for file: <path>") carries
			// no information once the path is stripped, so look at the bytes.
			detail = describeUnparseable(fd.FilePath)
		}
		if detail == "" {
			detail = "no further detail"
		}
		out = append(out, unscannedEntry{fd.FilePath, cause, detail})
	}
	for _, fd := range incomplete {
		d := humanizeReason(fd.FilePath, fd.Reason)
		if d == "" {
			d = "scan stopped before the file was finished"
		}
		out = append(out, unscannedEntry{fd.FilePath, causeCutShort, d})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Cause != out[j].Cause {
			return out[i].Cause < out[j].Cause
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// inlineDetailLimit is how many individual paths the report prints before it
// collapses to per-cause counts.
//
// Chosen from what the output actually looks like: a directory of 40 broken .docx
// files produced 54 lines of stderr, 40 of them identical apart from the filename,
// which buries both the findings table and the one line that matters. Below the
// limit the full list is more useful than a count; above it, the count is more
// useful than a wall of text, and the paths belong in a file.
const inlineDetailLimit = 8

// writeUnscannedReport renders the grouped report. It returns true if anything was
// written.
//
// Wording note: the block does NOT say "NOT clean". A reviewer read that as a
// verdict on the file's contents, when the actual meaning is the opposite — we
// never saw the contents, so we cannot vouch either way. It now states that
// plainly: the files were not read, so findings may be missing.
//
// Framing note: this writes NO rules of its own. The text formatter renders it
// inside the summary block (FormatterOptions.NotExaminedFooter), so the summary's
// closing double rule sits above it and a single rule closes it below — one footer
// instead of two floating boxes on two different streams.
func writeUnscannedReport(w io.Writer, entries []unscannedEntry, totalFiles int, failOnIncomplete, debug bool) bool {
	if len(entries) == 0 {
		return false
	}

	// "1 file" / "N files" — the plural was wrong on single-file runs, which is the
	// most common way this report is seen.
	// The noun agrees with totalFiles, which is the number it FOLLOWS. Choosing it
	// from len(entries) produced "1 of 2 file" whenever one of two files was
	// unexamined.
	noun := "files"
	if totalFiles == 1 {
		noun = "file"
	}

	// "not fully examined", not "contents were never read".
	//
	// The stronger claim was false for one of the four causes. A body-empty .docx
	// whose metadata DOES carry PII is reported here under "no text extracted" — but
	// its metadata was read and scanned, and measured, it produced 4 findings
	// (AUTHOR_INFO, LAST_MODIFIED_BY, plus the SSN and PERSON_NAME inside them).
	// Telling the operator its contents were never read, on the same run that
	// reported findings from it, is a contradiction they cannot resolve.
	//
	// The per-cause lines below carry the precise claim; this header only promises
	// what is true of all four: something was not covered, so findings may be missing.
	fmt.Fprintf(w, "NOT FULLY EXAMINED: %d of %d %s — findings may be missing\n",
		len(entries), totalFiles, noun)

	count := map[unscannedCause]int{}
	for _, e := range entries {
		count[e.Cause]++
	}

	hint := func() {
		if !failOnIncomplete {
			fmt.Fprintf(w, "  Add --fail-on-incomplete to make this a non-zero exit (3).\n")
		}
	}

	if len(entries) > inlineDetailLimit {
		// Too many to list. Give the per-cause tally and stop; the paths go to a
		// file in a follow-up change, and until then --debug still lists them.
		var parts []string
		// Derived from the causes actually PRESENT, never from a hardcoded list.
		//
		// This loop used to name the four original causes explicitly while the header
		// two lines above printed len(entries), which counts them all. Every cause added
		// since was therefore counted in the header and given no bucket line:
		// causeNotFollowed (refused symlinks) and causeTooLarge (oversize files) both
		// vanished from the breakdown. Measured on a ~1,870-file scan, the header read 65
		// while the buckets summed to 64 — and the file missing from the breakdown was
		// exactly the oversize file this report exists to disclose.
		//
		// Sorting by the cause's numeric value preserves the deliberate presentation
		// order, because the enum is declared least-to-most partial coverage.
		present := make([]unscannedCause, 0, len(count))
		for c := range count {
			present = append(present, c)
		}
		sort.Slice(present, func(i, j int) bool { return present[i] < present[j] })
		for _, c := range present {
			if count[c] > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", c, count[c]))
			}
		}
		fmt.Fprintf(w, "  %s\n", strings.Join(parts, "  ·  "))
		// Do not advise a flag that is already set: under --debug the per-file
		// diagnostics are on stderr already, so telling the operator to re-run reads
		// as though the tool did not notice what it was asked to do.
		if !debug {
			fmt.Fprintf(w, "  Re-run with --debug to list the files.\n")
		}
		hint()
		return true
	}

	// Longest path in this run, so the detail column lines up without a fixed
	// width that truncates or over-pads.
	width := 0
	for _, e := range entries {
		if len(e.Path) > width {
			width = len(e.Path)
		}
	}
	if width > 60 {
		width = 60
	}

	var lastCause unscannedCause = -1
	for _, e := range entries {
		if e.Cause != lastCause {
			fmt.Fprintf(w, "  %s (%d)\n", e.Cause, count[e.Cause])
			lastCause = e.Cause
		}
		fmt.Fprintf(w, "    %-*s  %s\n", width, e.Path, e.Detail)
	}

	hint()
	return true
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
