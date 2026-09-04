// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package rtf

import (
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	rtfextract "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-rtftextlib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// edit is one source-byte range to overwrite.
type edit struct {
	start, end int
	with       string
}

// redactViaSpans rewrites reported values in the ORIGINAL RTF bytes using the extractor's span map,
// and reports which match texts it handled.
//
// This is what lets a SPLIT value be redacted. A producer writes `452-11-9384` as
// `452-11-\f1\b 9384`, so the reassembled value occurs nowhere literally and the plain byte
// substitution finds nothing — which is why redaction of such a file used to be refused outright. The
// span map says which source bytes produced the value, so those bytes can be rewritten even though the
// value never appears contiguously.
//
// # What it does with the control words in between
//
// It leaves them alone. The replacement goes into the FIRST mapped range and the remaining ranges are
// deleted, so `Employee SSN: 452-11-\f1\b 9384\b0\par` becomes
// `Employee SSN: [SSN-REDACTED]\f1\b \b0\par` — the formatting runs, and the document's structure,
// survive. Collapsing the whole span instead would delete `\f1\b` and change how the rest of the
// paragraph renders, which is data loss of a different kind.
//
// # What it refuses
//
// A value whose window is not fully covered by the map (it crosses a paragraph separator, or came from
// an escape that cannot be sliced) is left for the caller to handle. Refusing one value is not
// refusing the file: the caller still runs the byte-substitution path, and the residue check at the
// sink is what turns anything genuinely unremovable into a loud failure. Guessing at a partial mapping
// would leave part of a value behind while reporting success.
func redactViaSpans(src string, matches []detector.Match,
	strategy redactors.RedactionStrategy) (out string, handled map[string]bool) {

	handled = map[string]bool{}
	if len(matches) == 0 {
		return src, handled
	}

	// Extraction and spans are derived from the bytes being edited, not passed in. That is what lets
	// this compose AFTER the inner redactor has already rewritten the verbatim occurrences: offsets
	// taken against the original file would be stale by exactly the length change of every
	// substitution already applied.
	tc, err := rtfextract.ExtractFromBytes("redact.rtf", []byte(src))
	if err != nil || tc == nil || tc.NotRTF {
		return src, handled
	}
	text, spans := tc.Text, tc.Spans
	if len(spans) == 0 {
		return src, handled
	}

	var edits []edit
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		// Every occurrence, not just the first: the same value can appear more than once, and leaving a
		// later one behind is the leak this package exists to prevent.
		for from := 0; ; {
			at := strings.Index(text[from:], m.Text)
			if at < 0 {
				break
			}
			at += from
			from = at + len(m.Text)

			ranges := rtfextract.SourceRanges(spans, at, at+len(m.Text))
			if ranges == nil {
				continue // not fully mapped; the caller's other paths deal with it
			}
			with := replacement.Generate(m.Text, m.Type, strategy)
			for i, r := range ranges {
				e := edit{start: r[0], end: r[1]}
				if i == 0 {
					e.with = with
				}
				edits = append(edits, e)
			}
			handled[m.Text] = true
		}
	}
	if len(edits) == 0 {
		return src, handled
	}

	// Apply right-to-left so earlier offsets stay valid, and drop any edit that overlaps one already
	// applied — two matches claiming the same bytes (an overlapping detection) would otherwise corrupt
	// the document by splicing into a region that has already moved.
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	var b strings.Builder
	b.Grow(len(src))
	prevStart := len(src)
	var applied []edit
	for _, e := range edits {
		if e.end > prevStart {
			continue
		}
		applied = append(applied, e)
		prevStart = e.start
	}
	// applied is in descending order; rebuild left-to-right.
	last := 0
	for i := len(applied) - 1; i >= 0; i-- {
		e := applied[i]
		b.WriteString(src[last:e.start])
		b.WriteString(e.with)
		last = e.end
	}
	b.WriteString(src[last:])
	return b.String(), handled
}
