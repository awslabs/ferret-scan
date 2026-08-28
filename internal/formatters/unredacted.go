// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"fmt"
	"github.com/awslabs/ferret-scan/v2/internal/displaytext"
	"sort"
	"strings"
)

// The unredacted disclosure, as DATA rather than prose.
//
// A file whose findings were reported but NOT redacted is the one outcome the sink
// rule forbids passing off as success: the values are still in cleartext, and the
// consumer has been handed a report that looks complete. Measured at main @ 3c4e10b
// on a real 14KB PDF that extracts cleanly and yields 3 findings, scanned with
// --enable-redaction:
//
//	format       in-band signal on stdout
//	text         NONE
//	json         NONE
//	yaml         NONE
//	csv          NONE
//	junit        NONE
//	sarif        NONE
//	gitlab-sast  NONE
//
// Seven of seven. The human-readable warning IS produced —
//
//	WARNING: redaction incomplete — 1 of 1 file(s) have findings but no redacted
//	copy was written; the original values remain in cleartext
//
// — but it goes to STDERR, which pipelines routinely discard, and the exit code was
// 0. So a scheduled sanitization job shipped nothing for that file, reported success,
// and the only record was a log line nobody reads (#441).
//
// This mirrors NotExaminedFile deliberately, because it is the same class of harm
// reached one step later: not-examined means "we never looked", unredacted means "we
// looked, we found, and we could not clean it". Both are gaps that read as a pass.
// Where the two differ is what a consumer can do about it, which is why the causes
// are a separate enum rather than extra NotExaminedCause values.

// UnredactedCause is a coarse, user-facing reason a reported value was not redacted.
//
// An INT enum for the same two reasons NotExaminedCause is: the causes have a
// deliberate presentation order, and the zero value must be a VALID cause so that a
// partially-populated struct cannot emit an empty string into a field whose schema
// requires minLength 1 (GitLab SAST).
type UnredactedCause int

const (
	// UnredactedRefused — the redactor declined to write a copy, cause not narrowed.
	//
	// The ZERO VALUE is deliberately the generic one, because the cause is recovered
	// by matching substrings of a redactor's error string (see cmd's classifier) and
	// that matching WILL drift when an error is reworded. When it drifts, the entry
	// falls here — and this label is true of every refusal, so a misclassification
	// degrades the detail without ever asserting a wrong remedy. The alternative
	// orderings all had a specific cause as the zero value, which meant a reworded
	// error would confidently tell an operator to raise a limit that was never hit.
	//
	// It also sorts first, which reads slightly oddly next to the specific causes but
	// costs nothing: presentation order among causes carries no meaning here, unlike
	// NotExaminedCause where it tracks how partial the coverage was.
	UnredactedRefused UnredactedCause = iota

	// UnredactedNoRedactor — no redactor is implemented for this file type, so no
	// output was written at all. PDF today, and .tiff/.gif/.bmp/.webp, whose
	// extensions are accepted by the image redactor but reach an unimplemented arm.
	//
	// The most complete failure: nothing about the file was cleaned, and the remedy is
	// a tool change rather than anything the operator can adjust.
	UnredactedNoRedactor

	// UnredactedOverBudget — the file was refused by a resource limit before it could
	// be redacted, e.g. an image whose declared pixel count is over the redactor's
	// budget (#378). The operator CAN act: the value is a documented limit.
	UnredactedOverBudget

	// UnredactedValueNotLocated — the redactor ran but could not find a reported
	// value in the bytes it is allowed to rewrite, so it refused rather than write a
	// partly-handled file. The audio and video redactors do this: replacements must
	// be the same length as the value they replace, so a value they cannot locate
	// cannot be overwritten without moving every subsequent offset.
	UnredactedValueNotLocated

	// UnredactedWriteFailed — redaction itself failed (permissions, disk, an I/O
	// error). Distinct from the three above because the tool WOULD have redacted it;
	// the environment stopped it, and the remedy is environmental.
	UnredactedWriteFailed
)

// String returns the operator-facing cause label.
//
// These strings are consumed by machine formats, so they are part of the output
// contract; changing one changes every report. They match the text renderer's
// wording exactly, because an operator comparing a human report against a JUnit
// artifact from the same run must not have to translate.
func (c UnredactedCause) String() string {
	switch c {
	case UnredactedRefused:
		return "redaction refused"
	case UnredactedNoRedactor:
		return "no redactor for this file type"
	case UnredactedOverBudget:
		return "refused by a resource limit"
	case UnredactedValueNotLocated:
		return "reported value not found in the writable bytes"
	case UnredactedWriteFailed:
		return "could not write the redacted copy"
	default:
		return "unknown"
	}
}

// UnredactedFile is one file whose reported findings were not redacted.
type UnredactedFile struct {
	// Path is the file as the user named it.
	Path string
	// Cause is the coarse reason.
	Cause UnredactedCause
	// Detail is a short actionable explanation, already stripped of internal
	// vocabulary and of the redundant path. May be empty; Message() supplies a
	// fallback so no format can emit an empty string into a field whose schema
	// requires minLength 1.
	Detail string
	// ReportedValues is how many findings for this file remain in cleartext.
	//
	// Carried per file because it is the number that sizes the exposure, and a
	// consumer cannot recover it from the findings list alone: that list does not say
	// which findings were written out redacted.
	ReportedValues int
}

// Message renders one entry as a single self-describing line.
//
// Shared by every machine format so the wording cannot drift between them, and so
// the minLength-1 guarantee lives in exactly one place. The leading claim is the
// CONSEQUENCE, not the cause: a consumer that truncates the string still learns that
// values are in cleartext, which is the part that matters.
func (f UnredactedFile) Message() string {
	detail := f.Detail
	if detail == "" {
		detail = "no further detail available"
	}
	return fmt.Sprintf("NOT REDACTED (%s): %s — %d reported value(s) remain in cleartext; %s",
		f.Cause, f.Path, f.ReportedValues, detail)
}

// UnredactedSummary is the aggregate line, used when per-file entries are capped.
//
// Truncation is never silent: the count of what was dropped is stated, the same idiom
// NotExaminedSummary and the --limit disclosure use.
func UnredactedSummary(shown, total, values int) string {
	if total <= shown {
		return fmt.Sprintf("VALUES LEFT IN CLEARTEXT: %d file(s), %d reported value(s) — "+
			"no redacted copy was written", total, values)
	}
	return fmt.Sprintf("VALUES LEFT IN CLEARTEXT: %d file(s), %d reported value(s) — "+
		"no redacted copy was written; %d listed here, %d omitted",
		total, values, shown, total-shown)
}

// MaxUnredactedEntries caps how many per-file entries a machine format emits.
//
// Same value and same reasoning as MaxNotExaminedEntries: an unbounded list is a
// denial of service against the consumer, and a SARIF upload that exceeds GitHub's
// size limit is rejected whole, which would lose the very disclosure this exists to
// carry. When the cap bites, UnredactedSummary states the total, so the disclosure
// stays complete even when the enumeration does not.
const MaxUnredactedEntries = MaxNotExaminedEntries

// CapUnredacted returns the entries to emit and the true total.
//
// CAUSE-FAIR, not first-N. A flat prefix loses whole causes: measured on a directory of
// 150 PDFs, 12 TIFFs and 3 oversize JPEGs, taking the first 50 in path order emitted
// "no redactor for this file type" 50 times and the resource-limit refusals NOT AT ALL,
// so a consumer could not learn that cause had occurred. Which cause survives depended
// on nothing but filename sort order — naming the JPEGs "zzz-*" was enough to erase
// them.
//
// That matters because the causes are not interchangeable. "No redactor for this type"
// is a tool limitation the operator cannot act on; "refused by a resource limit" is a
// documented number they can raise. Hiding the rare, actionable cause behind the common,
// inert one is the worst possible allocation of a budget that exists to keep the report
// readable.
//
// So every cause present gets at least one slot, remaining slots are shared, and the
// selection is re-sorted into the caller's original order so grouping and path sort are
// preserved. The totals are unaffected: stats.files_not_redacted and
// stats.values_not_redacted are computed over the full set.
func CapUnredacted(files []UnredactedFile) (shown []UnredactedFile, total int) {
	return selectFairlyByCause(files, MaxUnredactedEntries), len(files)
}

// selectFairlyByCause picks up to limit entries so that every cause present is
// represented, preserving the input order of whatever it selects.
//
// Guarantees, in order of importance:
//
//  1. If limit >= the number of distinct causes, EVERY cause appears at least once.
//  2. No more than limit entries are returned.
//  3. The result is in the same relative order as the input, so a caller that sorted by
//     path still sees sorted paths.
//
// When limit is smaller than the number of causes the first guarantee cannot hold; the
// causes that fit are taken in enum order, which is deterministic. That case does not
// arise today (five causes, a limit of 50 for machine formats and 8 for the terminal).
func selectFairlyByCause(files []UnredactedFile, limit int) []UnredactedFile {
	if len(files) <= limit || limit <= 0 {
		return files
	}

	// Indices per cause, in input order.
	order := make([]UnredactedCause, 0, 4)
	byCause := make(map[UnredactedCause][]int)
	for i, f := range files {
		if _, seen := byCause[f.Cause]; !seen {
			order = append(order, f.Cause)
		}
		byCause[f.Cause] = append(byCause[f.Cause], i)
	}
	// Enum order rather than first-appearance order, so the selection does not depend on
	// which file the walk happened to reach first.
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })

	quota := limit / len(order)
	if quota < 1 {
		quota = 1
	}

	picked := make(map[int]struct{}, limit)
	take := func(c UnredactedCause, n int) {
		for _, idx := range byCause[c] {
			if n <= 0 || len(picked) >= limit {
				return
			}
			if _, already := picked[idx]; already {
				continue
			}
			picked[idx] = struct{}{}
			n--
		}
	}

	// Pass one: the guaranteed share for each cause.
	for _, c := range order {
		take(c, quota)
	}
	// Pass two: hand out whatever is left to causes that still have entries, so a small
	// number of causes does not leave the budget unspent.
	for len(picked) < limit {
		before := len(picked)
		for _, c := range order {
			take(c, 1)
			if len(picked) >= limit {
				break
			}
		}
		if len(picked) == before {
			break // every cause exhausted
		}
	}

	out := make([]UnredactedFile, 0, len(picked))
	for i, f := range files {
		if _, ok := picked[i]; ok {
			out = append(out, f)
		}
	}
	return out
}

// UnredactedValueCount sums the cleartext values across every entry.
//
// Computed over the FULL slice, not the capped one, so the headline number is right
// even when the enumeration is truncated.
func UnredactedValueCount(files []UnredactedFile) int {
	n := 0
	for _, f := range files {
		n += f.ReportedValues
	}
	return n
}

// UnredactedPaths is the set of files with unredacted values, for formats that decide
// per FINDING rather than per file.
//
// CSV is the case this exists for: its grain is one row per finding, so it expresses
// the same fact as two columns on each row rather than as a file-level block. Every
// unredacted value HAS a finding row by construction — the disclosure counts reported
// values — so the per-row form is complete for this disclosure, unlike not-examined,
// where a file with no findings has no row to carry it.
func UnredactedPaths(files []UnredactedFile) map[string]UnredactedFile {
	if len(files) == 0 {
		return nil
	}
	byPath := make(map[string]UnredactedFile, len(files))
	for _, f := range files {
		byPath[f.Path] = f
	}
	return byPath
}

// RenderBlock renders the operator-facing block for the text format.
//
// Lives HERE, not in cmd, so it is derived from the structured disclosure rather than
// from prose a caller happened to build. The not-examined disclosure does it the other
// way round -- cmd renders NotExaminedFooter and the text formatter prints whatever it
// is given -- and that shape has a hole: any caller that populates the structured field
// but not the footer gets a text report with no disclosure at all. The web UI and every
// library consumer of formatters.Export are exactly such callers, so copying that shape
// would have reintroduced #441 on those surfaces while the CLI looked fixed.
//
// totalFiles is only used for the "N of M" headline; zero renders the count alone.
//
// includeExitHint suppresses the trailing --fail-on-incomplete line. The caller sets it
// false when another disclosure block in the SAME summary frame already carries that
// line: the escalation now covers both coverage gaps and redaction refusals, so stating
// it once is correct and stating it twice reads as two different policies.
func RenderBlock(files []UnredactedFile, totalFiles int, failOnIncomplete, includeExitHint bool) string {
	if len(files) == 0 {
		return ""
	}

	var w strings.Builder
	values := UnredactedValueCount(files)
	if totalFiles > 0 {
		fmt.Fprintf(&w, "VALUES LEFT IN CLEARTEXT: %d of %d file(s), %d reported value(s) — no redacted copy was written\n",
			len(files), totalFiles, values)
	} else {
		fmt.Fprintf(&w, "VALUES LEFT IN CLEARTEXT: %d file(s), %d reported value(s) — no redacted copy was written\n",
			len(files), values)
	}

	// Grouped by cause so an operator sees the SHAPE before the list: one unimplemented
	// type across forty files is one decision to make, forty different causes are forty.
	byCause := make(map[UnredactedCause][]UnredactedFile)
	for _, f := range files {
		byCause[f.Cause] = append(byCause[f.Cause], f)
	}
	causes := make([]int, 0, len(byCause))
	for c := range byCause {
		causes = append(causes, int(c))
	}
	sort.Ints(causes)

	// Bounded for the same reason the machine formats are: a tree of thousands of PDFs
	// would bury the headline. What is dropped is always counted.
	//
	// The examples are chosen CAUSE-FAIRLY. Taking the first eight in path order showed
	// eight PDFs and left "refused by a resource limit (3)" with its count but not one
	// example path — the count told the operator a cause existed and the report then
	// refused to say which files, which is the least useful place to spend a budget.
	// Every cause's own count is still the FULL count, whatever is listed beneath it.
	const inlineDetailLimit = 8
	examples := make(map[UnredactedCause][]UnredactedFile, len(byCause))
	for _, f := range selectFairlyByCause(files, inlineDetailLimit) {
		examples[f.Cause] = append(examples[f.Cause], f)
	}

	shown := 0
	for _, ci := range causes {
		c := UnredactedCause(ci)
		fmt.Fprintf(&w, "  %s (%d)\n", c, len(byCause[c]))
		for _, f := range examples[c] {
			fmt.Fprintf(&w, "    %s  %d value(s) in cleartext\n", displaytext.SanitizeDisplayText(f.Path), f.ReportedValues)
			shown++
		}
	}
	if len(files) > shown {
		fmt.Fprintf(&w, "  %d more file(s) not listed\n", len(files)-shown)
	}

	// Shown only when the escalation is NOT already enabled, which is exactly what the
	// not-examined report does. It is a "how to gate on this" nudge; once the flag is set
	// the non-zero exit says it, and repeating it adds a line to every failing CI log.
	//
	// A draft printed "Exit code 3: --fail-on-incomplete is set …" in that case instead.
	// Combined with suppressing this line when the not-examined block is present, the
	// result was that a run with BOTH disclosures and the flag set stated the consequence
	// NOWHERE — the two suppressions cancelled. Matching the existing convention removes
	// the interaction rather than adding a third rule to reason about.
	if includeExitHint && !failOnIncomplete {
		fmt.Fprint(&w, "  Add --fail-on-incomplete to make this a non-zero exit (3).\n")
	}
	return w.String()
}
