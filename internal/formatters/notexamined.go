// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import "fmt"

// The not-examined disclosure, as DATA rather than prose.
//
// A file the tool could not read is not a file with no findings, but on four of the
// six output formats those two states were byte-identical. Measured on a directory
// holding one findings-bearing .txt, one unreadable file and one body-less .docx:
//
//	format       in-band signal on stdout
//	text         "NOT FULLY EXAMINED: 2 of 3 files" inside the summary block
//	json         stats.files_not_examined = 2
//	yaml         filesnotexamined: 2
//	csv          NONE
//	junit        NONE
//	sarif        NONE
//	gitlab-sast  NONE
//
// The human-readable report IS produced for the machine formats — it goes to
// STDERR, which pipelines routinely discard. So a CI job parsing stdout concludes
// those files are clean. They were never opened.
//
// That is the same class of harm as a missed detection: only reported facts reach
// the consumer, and an undisclosed gap reads as a pass.
//
// This file carries the STRUCTURED form into the formatters. FormatterOptions
// already had NotExaminedFooter, but that is a rendered string with box-drawing
// characters and column alignment — useless to a machine format, which needs the
// path and the cause as separate fields.

// NotExaminedCause is a coarse, user-facing reason a file was not examined.
//
// An INT enum, not a string, for two reasons found while designing this:
//
//  1. The four causes have a deliberate presentation ORDER (unreadable, unparseable,
//     no-text, cut-short — least to most partial coverage). String values would sort
//     lexicographically and permute it.
//  2. The zero value of a string is "", and the GitLab SAST schema requires
//     minLength 1 on the message value. An int zero is a VALID cause, so a
//     partially-populated struct cannot emit a schema-invalid document.
//
// Deliberately coarse: the point is what the operator must DO, not which internal
// component reported the failure. It mirrors the cmd-side taxonomy exactly; see
// cmd/unscanned_report.go, which keeps the classification logic because it does
// filesystem I/O that must not migrate into a package the web export handler calls.
type NotExaminedCause int

const (
	// NotExaminedUnreadable — the bytes could not be read at all (permissions,
	// vanished path, I/O error). Nothing about this file is known.
	NotExaminedUnreadable NotExaminedCause = iota

	// NotExaminedUnparseable — the file was read but its bytes do not match its
	// declared type, so no text could be recovered.
	NotExaminedUnparseable

	// NotExaminedNoText — opened and parsed, but no body text was found. NOTE: the
	// file's METADATA was still extracted and scanned through a separate channel and
	// may already have produced findings in this same report. Never claim this file
	// was unread.
	NotExaminedNoText

	// NotExaminedCutShort — a budget, size cap or timeout fired, so the file is
	// PARTLY scanned. Findings from it may be present and incomplete.
	NotExaminedCutShort

	// NotExaminedNotFollowed — a symlink the walk deliberately did not follow: it
	// dangles or loops, names a directory or a device, or resolves outside the
	// scanned tree.
	//
	// Distinct from NotExaminedUnreadable because for most of these the file COULD
	// have been read — the tool declined. Reporting them as "cannot read" asserts a
	// failure that did not happen, and the operator's remedy differs: a permission
	// problem is fixed with chmod, a link out of the tree by scanning the target
	// directly.
	//
	// The cmd side has had this cause since #326, but it was never mapped here and
	// fell through to NotExaminedUnreadable, so machine formats said "cannot read"
	// for every refused symlink while the text report said "symlink not followed" —
	// the exact mislabelling the cmd-side comment warns a new cause would cause.
	NotExaminedNotFollowed

	// NotExaminedTooLarge — the file exceeds the size limit, so it was never opened.
	//
	// Its type WAS one the tool would have processed; an unprocessable type refused
	// for size is not reported at all, because nobody expected a finding from it.
	NotExaminedTooLarge

	// NotExaminedNotRegular — the directory entry is not a regular file: a named pipe,
	// a socket, a device node, or on Windows a junction, mount point or other
	// non-symlink reparse point.
	//
	// Mapped here explicitly rather than left to the default arm. The comment on
	// NotExaminedNotFollowed above records what happens otherwise: that cause existed
	// on the cmd side since #326 but was never mapped here, so every machine format
	// said "cannot read" for a refused symlink while the text report said "symlink not
	// followed". This is the same trap one cause later. See #485.
	NotExaminedNotRegular

	// NotExaminedRefusedTraversal — the path was declined by the traversal gate: once
	// cleaned it still climbs above the directory it is relative to, or a walked entry
	// resolved outside the tree being scanned.
	//
	// Mapped here from the moment the cmd-side cause exists, because the two causes above
	// both record what happens otherwise: a cmd cause with no mapping falls to the default
	// arm and every machine format says "cannot read" for a file nobody tried to read. For
	// this cause that mislabelling would be doubly wrong — the refusal was a POLICY
	// decision, and sending the operator to chmod hides the actual remedy (name the path
	// absolutely). See #562.
	NotExaminedRefusedTraversal
)

// String returns the operator-facing cause label.
//
// These strings are consumed by machine formats, so they are part of the output
// contract; changing one changes every report. They match the text renderer's
// wording exactly, because an operator comparing a human report against a JUnit
// artifact from the same run must not have to translate.
func (c NotExaminedCause) String() string {
	switch c {
	case NotExaminedUnreadable:
		return "cannot read"
	case NotExaminedUnparseable:
		return "cannot parse"
	case NotExaminedNoText:
		// Names the BODY specifically. "no text" alone reads as "nothing was
		// scanned" on a file whose metadata may have produced findings in this very
		// report — a contradiction the reader cannot resolve.
		return "no body text (metadata still scanned)"
	case NotExaminedCutShort:
		return "coverage cut short"
	case NotExaminedNotFollowed:
		return "symlink not followed"
	case NotExaminedTooLarge:
		return "file too large to scan"
	case NotExaminedNotRegular:
		return "not a regular file"
	case NotExaminedRefusedTraversal:
		// Word-for-word the cmd-side label. An operator comparing the human report
		// against a SARIF or JUnit artifact from the same run must not have to translate.
		return "path refused as traversal"
	default:
		return "unknown"
	}
}

// NotExaminedFile is one file that was not fully examined.
type NotExaminedFile struct {
	// Path is the file as the user named it.
	Path string
	// Cause is the coarse reason.
	Cause NotExaminedCause
	// Detail is a short actionable explanation ("permission denied"), already
	// stripped of internal vocabulary and of the redundant path. May be empty;
	// Message() supplies a fallback so no format can emit an empty string into a
	// field whose schema requires minLength 1.
	Detail string
}

// Message renders one entry as a single self-describing line.
//
// Shared by every machine format so the wording cannot drift between them, and so
// the minLength-1 guarantee lives in exactly one place. The leading claim is the
// consequence, not the cause: a consumer that truncates the string still learns
// that coverage is incomplete.
func (f NotExaminedFile) Message() string {
	detail := f.Detail
	if detail == "" {
		detail = "no further detail available"
	}
	return fmt.Sprintf("NOT EXAMINED (%s): %s — %s", f.Cause, f.Path, detail)
}

// NotExaminedSummary is the aggregate line, used when per-file entries are capped.
//
// Truncation is never silent: the count of what was dropped is stated. This is the
// same idiom the --limit disclosure uses.
func NotExaminedSummary(shown, total int) string {
	if total <= shown {
		return fmt.Sprintf("NOT FULLY EXAMINED: %d file(s) — findings may be missing", total)
	}
	return fmt.Sprintf("NOT FULLY EXAMINED: %d file(s) — findings may be missing; "+
		"%d listed here, %d omitted", total, shown, total-shown)
}

// MaxNotExaminedEntries caps how many per-file entries a machine format emits.
//
// Larger than the terminal renderer's inlineDetailLimit (8), which is tuned for
// something a person reads: a machine artifact can carry more, and the consumer
// usually wants the list. Capped at all because an unbounded list is a denial of
// service against the consumer — a tree with 10,000 unreadable files would push a
// SARIF upload toward GitHub's 10 MB gzipped rejection limit, which would lose the
// whole report and so defeat the purpose of disclosing anything.
//
// When the cap bites, NotExaminedSummary states the total, so the disclosure remains
// complete even when the enumeration is not.
const MaxNotExaminedEntries = 50

// CapNotExamined returns the entries to enumerate plus the full total, keeping EVERY CAUSE PRESENT
// represented rather than taking a flat prefix.
//
// It used to return files[:MaxNotExaminedEntries]. The input arrives sorted cause-then-path, so a
// flat prefix silently dropped whole CAUSES: measured on a tree of 60 unreadable files plus 3
// unparseable PDFs, the SARIF report carried 50 notifications, every one of them "cannot read", and
// one summary line reading "63 file(s) ... 50 listed here, 13 omitted". A consumer therefore learned
// that 13 files were omitted and had no way to know that some of them failed for a reason with a
// COMPLETELY DIFFERENT REMEDY -- fix the permissions, versus the file is not a PDF.
//
// That is the defect this repository already names elsewhere: a count is not a disclosure. The
// output was byte-identical whether the omitted files were more of the same or an entire class of
// miss nobody had been told about.
//
// The cap itself is unchanged and still bounds the enumeration, because the reason for it is
// unchanged: an unbounded list is a denial of service against the consumer. What changed is HOW the
// budget is spent -- every cause present gets at least one slot, and the remainder is distributed
// evenly -- so no class of miss can disappear entirely while the total says only that something did.
//
// Order is preserved. The result is a subsequence of the input, so the cause-then-path ordering the
// caller established still holds and a byte comparison of two reports of the same scan is stable.
func CapNotExamined(files []NotExaminedFile) (shown []NotExaminedFile, total int) {
	total = len(files)
	if total <= MaxNotExaminedEntries {
		return files, total
	}

	// Distinct causes in first-appearance order. The input is sorted by cause, so this is also their
	// sort order, but not relying on that keeps the function correct for any caller.
	var causes []NotExaminedCause
	counts := make(map[NotExaminedCause]int)
	for _, f := range files {
		if _, seen := counts[f.Cause]; !seen {
			causes = append(causes, f.Cause)
		}
		counts[f.Cause]++
	}

	quota := allocateCauseQuotas(causes, counts, MaxNotExaminedEntries)

	shown = make([]NotExaminedFile, 0, MaxNotExaminedEntries)
	taken := make(map[NotExaminedCause]int, len(causes))
	for _, f := range files {
		if taken[f.Cause] < quota[f.Cause] {
			shown = append(shown, f)
			taken[f.Cause]++
		}
	}
	return shown, total
}

// allocateCauseQuotas divides budget among causes so that each gets at least one slot where possible,
// no cause is given more entries than it has, and any slack is redistributed.
//
// Written as a separate pure function because the interesting cases are arithmetic -- more causes than
// budget, one cause holding almost everything, a cause with fewer entries than its share -- and those
// are far cheaper to test directly than through a formatter and a filesystem.
func allocateCauseQuotas(causes []NotExaminedCause, counts map[NotExaminedCause]int, budget int) map[NotExaminedCause]int {
	quota := make(map[NotExaminedCause]int, len(causes))
	if len(causes) == 0 || budget <= 0 {
		return quota
	}

	// More causes than slots: give one each to as many as fit, in order, rather than zero to all.
	// Preferring the first is deliberate -- the input is cause-sorted, so it is at least deterministic,
	// and there are only eight causes in the model, so this is a defensive branch rather than a
	// live one.
	if len(causes) >= budget {
		for i := 0; i < budget; i++ {
			quota[causes[i]] = 1
		}
		return quota
	}

	// One each first, so presence is guaranteed before fairness is considered.
	remaining := budget
	for _, c := range causes {
		quota[c] = 1
		remaining--
	}

	// Then hand out the rest a slot at a time, cycling through the causes. Round-robin rather than
	// proportional: proportional would give a cause with 5,000 entries almost the whole budget and
	// reduce a cause with 3 back to its single guaranteed slot, which is the imbalance that made a
	// flat prefix wrong in the first place. Cycling stops when nothing can take more.
	for remaining > 0 {
		progressed := false
		for _, c := range causes {
			if remaining == 0 {
				break
			}
			if quota[c] < counts[c] {
				quota[c]++
				remaining--
				progressed = true
			}
		}
		if !progressed {
			break // every cause is fully enumerated; the budget was larger than the input
		}
	}
	return quota
}
