// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"bytes"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Which zip members may hold text, decided by INVERSION.
//
// The redactor used to answer this with an allowlist per format — "word/" plus a name containing
// document|header|footer|footnote|endnote|comment, or "xl/worksheets/", or "ppt/slides/" — and that
// allowlist had been extended five separate times, once per part somebody noticed was missing. A
// sixth was outstanding when this was written (#670: OOXML relationship parts are named *.rels, not
// *.xml, so a value in a hyperlink target was in no predicate at all). An allowlist of the parts
// someone thought of cannot be complete; a denylist of the parts that are provably NOT text can be,
// because the set of binary media formats is small, closed and slow-moving.
//
// So: everything is treated as text-bearing unless its extension says otherwise. A member type
// nobody anticipated gets examined rather than skipped, which is the fail-closed direction — a
// spurious look at a part costs a wasted XML parse, a missed look costs a cleartext value.
//
// # The list is measured, not imagined
//
// Every member of 403 real Office/ODF documents was enumerated. The complete non-XML universe was:
//
//	.png 1711   .svg 407   .fntdata 176   .jpeg 131   .emf 37   .bin 28   .dat 22
//	.wdp 17     .jpg 15    .vml 12        .gif 6      .odttf 3  .ttf 2    .tiff 1
//	plus .rels 4659 and bare "mimetype", "metadata", "commentsmeta0"
//
// Two of those are TEXT and were outside every previous predicate: .svg (407 members — SVG is XML
// and this repo has already shipped a fix for PII in standalone SVG) and .vml (legacy drawing
// markup). They are covered now by not being on the list below, which is exactly the point of
// inverting: they needed no thought.
//
// Extensions absent from the corpus are still listed where they are unambiguously binary media a
// producer may emit (.bmp, .wmf, .mp4, ...). Listing an extension that never appears costs nothing;
// omitting one that does would send a JPEG through an XML parser.
var provablyBinaryPartExts = map[string]struct{}{
	// Raster and vector images. NOT .svg — that is XML text.
	".png": {}, ".jpeg": {}, ".jpg": {}, ".jpe": {}, ".gif": {}, ".bmp": {}, ".tiff": {}, ".tif": {},
	".ico": {}, ".webp": {}, ".heic": {}, ".jfif": {},
	// Windows metafiles and their compressed forms.
	".emf": {}, ".wmf": {}, ".emz": {}, ".wmz": {}, ".wdp": {},
	// Fonts, including the two obfuscated embedding formats.
	".fntdata": {}, ".odttf": {}, ".ttf": {}, ".otf": {}, ".eot": {}, ".woff": {}, ".woff2": {},
	// Opaque blobs: OLE objects, printer settings, thumbnails, signatures.
	".bin": {}, ".dat": {}, ".p7s": {}, ".p7b": {}, ".der": {}, ".pfx": {},
	// Audio/video/other documents that may be embedded whole.
	".mp3": {}, ".mp4": {}, ".m4a": {}, ".wav": {}, ".wma": {}, ".wmv": {}, ".avi": {}, ".mov": {},
	".pdf": {}, ".zip": {}, ".gz": {},
}

// isProvablyBinaryPart reports whether a zip member is a binary format that must never be treated
// as text.
//
// Anything it cannot prove binary is text-bearing. A member with no extension at all — real
// examples from the corpus: ODF's "mimetype", and "metadata"/"commentsmeta0" emitted by some Word
// producers — is therefore text-bearing, which is correct for mimetype (it is a plain ASCII media
// type) and harmless for the others: a part that does not tokenize as XML is skipped downstream on
// its content rather than its name, so nothing has to guess right here.
func isProvablyBinaryPart(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	if ext == "" {
		return false
	}
	_, binary := provablyBinaryPartExts[ext]
	return binary
}

// recordCoverageForRemainingParts records the rewrite of every reported value against every
// text-bearing part that still holds it.
//
// # The defect this closes
//
// Removal ran by two routes with DIFFERENT part scopes, and the broad one only ran when the narrow
// one found nothing:
//
//	located route   parts come from textPositions, gated by isTextContainingFile -> NARROW
//	split-run route recordSplitRunValue searches every member of zipContents.Files -> BROAD
//
// redactMatch tries to locate the value first and only falls back to the broad search when
// locateMatch returns -1. So the reachable set depended on whether the value happened to be
// locatable, and the consequence was backwards. Measured on a soffice-produced .pptx:
//
//	SSN in the speaker notes ONLY   -> not locatable -> broad search -> redacted clean
//	SAME SSN in the slide AND notes -> located in the slide -> broad search never runs ->
//	                                   notesSlide1.xml keeps it -> the whole document is REFUSED
//
// A name on a slide and again in its speaker notes is ordinary, and it made the document
// un-redactable while the rarer case succeeded. This pass removes the asymmetry: after every match
// has been resolved by whichever route found it, each text-bearing part is asked once whether it
// still holds any reported value, and anything found is recorded like any other rewrite.
//
// # Cost
//
// Deliberately the two-stage shape parentPartResidue uses, and for the same measured reason. One
// strings.Replacer trie over all values scans each part ONCE, independent of how many values there
// are; the per-value attribution loop runs only for a part the trie already proved holds something.
// The naive alternative — one strings.Contains per value per part — is O(values x parts x text),
// the shape this repo has been bitten by repeatedly, and it would run on every successful redaction
// rather than only when about to fail.
//
// # Replacements are REUSED, never regenerated
//
// The replacement for a value is taken from what the located route already recorded. Regenerating
// would break the synthetic strategy, whose generator is nondeterministic by design: the same SSN
// would be replaced by one synthetic value in the slide and a different one in the notes, which
// reads as two distinct values to anyone reading the redacted document.
func (or *OfficeRedactor) recordCoverageForRemainingParts(
	contents *OfficeZipContents,
	matches []detector.Match,
	strategy redactors.RedactionStrategy,
	pending map[string]*partReplacements,
) {
	if contents == nil || len(matches) == 0 {
		return
	}

	// Replacements already chosen by the located/split routes, so a value is masked identically
	// everywhere it appears.
	chosen := make(map[string]string, len(matches))
	for _, pr := range pending {
		if pr == nil {
			continue
		}
		for value, repl := range pr.repl {
			if _, seen := chosen[value]; !seen {
				chosen[value] = repl
			}
		}
	}

	// The values worth searching for: long enough to mean something, and de-duplicated. Short
	// values produce coincidental hits, the same reason parentPartResidue has a floor.
	values := make([]string, 0, len(matches))
	seenValue := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		v := m.Text
		if len(v) < minResidueValueLen {
			continue
		}
		if _, dup := seenValue[v]; dup {
			continue
		}
		seenValue[v] = struct{}{}
		values = append(values, v)
	}
	if len(values) == 0 {
		return
	}

	// Stage 1: one trie pass per part. Replacing every value with nothing and comparing is a
	// presence oracle whose cost does not grow with the number of values.
	probeArgs := make([]string, 0, len(values)*2)
	for _, v := range values {
		probeArgs = append(probeArgs, v, "")
	}
	probe := strings.NewReplacer(probeArgs...)

	replacementFor := func(value string) (string, bool) {
		if repl, ok := chosen[value]; ok {
			return repl, true
		}
		// A value no route recorded: generate once and remember it, so every part that holds it
		// gets the same mask.
		for _, m := range matches {
			if m.Text != value {
				continue
			}
			repl, err := or.generateReplacement(value, m.Type, strategy)
			if err != nil {
				return "", false
			}
			chosen[value] = repl
			return repl, true
		}
		return "", false
	}

	for _, name := range contents.orderedNames() {
		if isProvablyBinaryPart(name) {
			continue
		}
		content := contents.Files[name]
		if len(content) == 0 {
			continue
		}
		// The view must match what may actually be REWRITTEN, in both directions.
		//
		// Character data is restricted to the elements rewritableText accepts, because some
		// character data must never be rewritten in place: docProps carries base64 in vt:blob, and
		// a same-length replacement inside base64 produces invalid base64, so a value found there
		// has to be REFUSED instead. An earlier cut of this pass used decodedPartText, which is
		// unfiltered by design for residue purposes, and it duly rewrote a vt:blob and wrote a file
		// that must not be written — caught by TestResidueRefusalNamesTypesNotValues, which exists
		// for precisely that mistake and has now caught it twice.
		//
		// Attribute values are added on top, because that is where a relationship target lives
		// (Target="mailto:...") and no character-data view can see it. This is also why the .rels
		// allowance already present in partsHoldingRunJoined was dead code: the NAME passed its
		// filter, and partSpans then returned empty text for a part that has no character data at
		// all, so the Contains check could never fire.
		runText, _, ok := partSpans(content, coverageRewritableElement)
		if !ok {
			// Not XML. Its content decides, not its name — the same choice parentPartResidue
			// makes, so a binary part that slipped past the extension check is skipped here too
			// rather than being rewritten as if it were markup.
			continue
		}
		attrText, attrOK := attributeValuesText(content)
		if !attrOK {
			continue
		}
		if probe.Replace(runText) == runText && probe.Replace(attrText) == attrText {
			continue // stage 1 says this part holds nothing; no per-value work
		}

		// Stage 2: only now, and only for this part, attribute the hit to values.
		for _, v := range values {
			if !strings.Contains(runText, v) && !strings.Contains(attrText, v) {
				continue
			}
			pr := pending[name]
			if pr != nil {
				if _, already := pr.repl[v]; already {
					continue // this route already covers it
				}
			}
			repl, ok := replacementFor(v)
			if !ok {
				continue // no replacement: leave it reported, and let the residue guard refuse
			}
			// A replacement carrying XML markup characters cannot be written into a part whose
			// occurrence may be inside an attribute: rewritePartText escapes character data but
			// passes markup spans through the raw replacer, so an unescaped '&' or '"' there
			// would produce a document that no longer parses. Refusing is the honest outcome —
			// the value stays reported and the residue guard declines the write, which is a loud
			// failure instead of a corrupted file.
			if strings.ContainsAny(repl, `&<>"'`) {
				continue
			}
			if pr == nil {
				pr = &partReplacements{}
				pending[name] = pr
			}
			// addSplit rather than add: the value may be spread across adjacent runs in this
			// part, and the split pass runs before the per-token one and handles both.
			pr.addSplit(v, repl)
		}
	}
}

// attributeValuesText returns every attribute value in an XML part, newline-separated.
//
// Separate from partSpans rather than folded into it, because the two views must not be mixed. Tokens
// arrive in document order, so an attribute contributes its value BETWEEN two adjacent character-data
// runs: a single combined view of `<w:t>449-87-</w:t>` `<w:t xml:space="preserve">` `<w:t>4100</w:t>`
// reads "449-87-" + "preserve" + "4100" and can no longer find the value that spans the two runs.
// decodedPartText carries a comment recording that exact failure. Keeping attributes in their own
// string means neither view can corrupt the other.
//
// Newline-separated for the same reason: two adjacent attribute values must not concatenate into a
// value that is in neither of them.
//
// ok is false only when the part does not tokenize as XML, so callers can skip it on its content
// rather than guessing from its name.
func attributeValuesText(content []byte) (string, bool) {
	var out strings.Builder
	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false
		}
		if se, isStart := tok.(xml.StartElement); isStart {
			for _, a := range se.Attr {
				out.WriteString(a.Value)
				out.WriteByte('\n')
			}
		}
	}
	return out.String(), true
}

// base64ElementFamilies are the element local names whose character data is base64 or otherwise
// opaque, and which therefore must NEVER be rewritten in place.
//
// Taken verbatim from the exclusion note on docPropsValueElements, which is where this constraint was
// first written down: a same-length text replacement inside base64 produces invalid base64, so a value
// reported from one of these has to be REFUSED rather than masked. binData (VML) and binary-data (ODF)
// are added because they are the same hazard in the other two markup families.
var base64ElementFamilies = map[string]bool{
	"blob": true, "oblob": true,
	"storage": true, "ostorage": true,
	"stream": true, "ostream": true, "vstream": true,
	"cf":          true,
	"binData":     true,
	"binary-data": true,
}

// coverageRewritableElement reports whether character data under path may be rewritten, by INVERSION:
// anything that is not an opaque family.
//
// The redactor's own isTextElement is an ALLOWLIST — "t" or "delText" for Word, "t"/"v"/"f" for Excel,
// "t" for PowerPoint — and it is correct for its job, which is deciding where the located route may
// place a rewrite in a body part. It is the wrong predicate for asking "does this part still hold a
// reported value anywhere", because a value can sit in perfectly ordinary character data under an
// element nobody enumerated. Measured on 383 real containers, exactly 106 distinct element names hold
// character data at all, and the ones holding 8+ characters are almost entirely content:
//
//	t 110435   v 11684   f 10249   Cell 3527   lpwstr 1724   instrText 1256   Prompt 951
//	StaticSelection 574   Definition 383   AuthorNote 295   Guidance 273   PrefillValue 135
//
// Cell/Prompt/StaticSelection/AuthorNote/Guidance/PrefillValue are customXml — user-defined document
// metadata, present in 140 of 330 real .docx, and pure data. instrText is a Word field instruction,
// which is where a HYPERLINK target's text lives.
//
// Why inverting is safe here rather than reckless: in OOXML and ODF, structural elements carry their
// structure in ATTRIBUTES and hold no character data at all, so "accept any element" can only ever
// reach text. The measurement bears that out — the only structure-sensitive holders in the whole corpus
// are sqref (a cell range like "A1:B10") and definedName, and both hold SHORT values that no reported
// PII value will equal. A value must also clear minResidueValueLen before this pass considers it.
//
// The alternative is not "leave it alone", it is REFUSE: parentPartResidue declines to write any
// document still holding a reported value, so an element family missing from an allowlist does not
// produce a quiet leak, it produces an un-redactable document. Inverting turns that refusal back into
// a successful redaction.
func coverageRewritableElement(path []string) bool {
	if len(path) == 0 {
		return false
	}
	return !base64ElementFamilies[path[len(path)-1]]
}
