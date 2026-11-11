// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"bytes"
	"encoding/xml"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Rewriting a value the scanner read ACROSS a node boundary (#914).
//
// The scanner's Office reader joins text nodes with a separator that is in no node: a space after every
// DrawingML run (a:t) of a slide, notes page or master; a space after every OpenDocument paragraph
// (text:p), which is also how it joins spreadsheet cells; a tab after every non-empty worksheet cell and a
// newline after every non-empty row. A value it reports across such a join -- "<first> <last>" in one
// paragraph and "English ..." in the next, "600", "600" and "1250" in three adjacent cells -- is in no
// single node, so the per-node rewrite cannot reach it, and the run-joined rewrite of #627 cannot either,
// because that view joins nodes with nothing.
//
// This builds, per part, the text the scanner reads with the scanner's separators, maps every byte of it
// back to the node it came from, and rewrites each occurrence of a reported value in every node it covers:
// with the simple strategy, the replacement in the first node and the rest of the value removed from the
// others; with a replacement as long as the value (format-preserving, and a same-length synthetic), each
// node gets its own slice of it, so a masked cell stays a cell of the same width. The separator itself is
// not in any node and needs no rewrite.
//
// The views are a MODEL of the reader, and they are not the check. scannerview.go reads the copy back
// through the reader itself and refuses the write if a reported value is still there, so a shape this
// model does not cover becomes a disclosed refusal rather than a silent survivor.

// boundaryToken is one node of a view: the bytes a rewrite replaces and the text the scanner reads there.
type boundaryToken struct {
	part       string
	start, end int    // [start,end) of the part's bytes that the rewrite replaces
	decoded    string // the text the scanner reads from those bytes

	// cell is set for a worksheet cell whose text the scanner takes from its <v> value: a shared-string
	// index or a literal. Such a cell is rewritten as an inline string (or, with a formula, as a string
	// result), so the copy stays a valid sheet whatever the replacement looks like, and a shared string --
	// which other cells may show -- is never edited for a value that only some of them are part of.
	cell *xlsxCell
}

// xlsxCell locates the two pieces of a <c> element a rewrite touches.
type xlsxCell struct {
	tagStart, tagEnd int  // the <c ...> start tag
	vStart, vEnd     int  // the <v>...</v> element, tags included
	formula          bool // the cell has an <f>; it is kept and the text becomes its cached string result
}

// boundarySpan maps [at,end) of a view's text to the token tok, whose decoded text it reproduces from dec.
// A token is more than one span when the view collapses spaces inside it, as the scanner does for slides
// and OpenDocument text.
type boundarySpan struct {
	at, end int
	tok     int
	dec     int
}

// boundaryView is the scanner's text for one part, with every byte that came from a node mapped back to it.
type boundaryView struct {
	sb    strings.Builder
	spans []boundarySpan
	last  byte

	// collapse folds a run of spaces to one, which is what the scanner does to a slide's or an
	// OpenDocument part's text after joining it (a sheet's text is not folded).
	collapse bool
}

func (v *boundaryView) write(s string) {
	if s == "" {
		return
	}
	v.sb.WriteString(s)
	v.last = s[len(s)-1]
}

// addText appends token tok's text, splitting it into spans wherever a folded space is dropped.
func (v *boundaryView) addText(tok int, s string) {
	from := 0
	flush := func(upto int) {
		if upto > from {
			at := v.sb.Len()
			v.write(s[from:upto])
			v.spans = append(v.spans, boundarySpan{at: at, end: v.sb.Len(), tok: tok, dec: from})
		}
	}
	if v.collapse {
		for i := 0; i < len(s); i++ {
			if s[i] != ' ' {
				continue
			}
			follows := v.last == ' '
			if i > from {
				follows = s[i-1] == ' '
			}
			if follows {
				flush(i)
				from = i + 1
			}
		}
	}
	flush(len(s))
}

// addSeparator appends a byte the scanner writes between nodes and that is in no node.
func (v *boundaryView) addSeparator(sep byte) {
	if v.collapse && sep == ' ' && v.last == ' ' {
		return
	}
	v.sb.WriteByte(sep)
	v.last = sep
}

// elementView builds the view of a part whose text the scanner takes from the character data inside
// every `local` element, with a space after each one: a:t for slides, text:p for OpenDocument.
func elementView(part string, content []byte, local string, toks *[]boundaryToken) (*boundaryView, bool) {
	v := &boundaryView{collapse: true}
	depth := 0
	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == local {
				depth++
			}
		case xml.EndElement:
			if t.Name.Local == local && depth > 0 {
				depth--
				v.addSeparator(' ')
			}
		case xml.CharData:
			if depth > 0 && len(t) > 0 {
				k := len(*toks)
				*toks = append(*toks, boundaryToken{part: part, start: start, end: end, decoded: string(t)})
				v.addText(k, string(t))
			}
		}
	}
	return v, true
}

// sharedCellRe is the scanner's own test for a shared-string cell, applied to the same bytes (the
// cell's start tag), so the two agree on which cells hold an index.
var sharedCellRe = regexp.MustCompile(`\bt="s"`)

// xlsxSharedStrings reads the shared-string table the way the scanner does: one entry per <si>, its
// text every <t> inside it concatenated. Only a bare <si> start tag counts, because that is what the
// scanner's pattern matches, and an entry it skipped would shift every index after it.
func xlsxSharedStrings(content []byte) ([]string, bool) {
	var out []string
	var cur strings.Builder
	inSI, inT := false, 0
	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case t.Name.Local == "si" && string(content[start:end]) == "<si>":
				inSI, inT = true, 0
				cur.Reset()
			case t.Name.Local == "t" && inSI && bytes.HasPrefix(content[start:end], []byte("<t")):
				inT++
			}
		case xml.EndElement:
			switch {
			case t.Name.Local == "t" && inT > 0:
				inT--
			case t.Name.Local == "si" && inSI:
				out = append(out, cur.String())
				inSI = false
			}
		case xml.CharData:
			if inSI && inT > 0 {
				cur.Write(t)
			}
		}
	}
	return out, true
}

// xlsxSheetView builds the view of one worksheet: every non-empty cell's text followed by a tab, every
// non-empty row followed by a newline. A cell's text is its <v> value -- the shared string it indexes
// when the cell is t="s" and the table is not empty, else the value itself -- or failing that the first
// <t> it holds (an inline string). That is the scanner's order of preference, cell by cell.
func xlsxSheetView(part string, content []byte, sst []string, toks *[]boundaryToken) (*boundaryView, bool) {
	v := &boundaryView{}
	type cellState struct {
		active  bool
		cell    xlsxCell
		shared  bool
		hasV    bool
		inV     bool
		vText   strings.Builder
		tCount  int
		inT     bool
		tTokens []boundaryToken
	}
	var c cellState
	rowHasText := false

	emit := func() {
		if c.hasV {
			text := c.vText.String()
			if c.shared && len(sst) > 0 {
				text = ""
				if i, err := strconv.Atoi(strings.TrimSpace(c.vText.String())); err == nil && i >= 0 && i < len(sst) {
					text = sst[i]
				}
			}
			if text == "" || c.cell.vEnd <= c.cell.vStart {
				return
			}
			k := len(*toks)
			cell := c.cell
			*toks = append(*toks, boundaryToken{part: part, start: cell.tagStart, end: cell.vEnd, decoded: text, cell: &cell})
			v.addText(k, text)
			v.addSeparator('\t')
			rowHasText = true
			return
		}
		wrote := false
		for _, tk := range c.tTokens {
			if tk.decoded == "" {
				continue
			}
			k := len(*toks)
			*toks = append(*toks, tk)
			v.addText(k, tk.decoded)
			wrote = true
		}
		if wrote {
			v.addSeparator('\t')
			rowHasText = true
		}
	}

	dec := xml.NewDecoder(bytes.NewReader(content))
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		end := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "row":
				rowHasText = false
			case "c":
				c = cellState{active: true, shared: sharedCellRe.Match(content[start:end])}
				c.cell.tagStart, c.cell.tagEnd = start, end
			case "v":
				if c.active && !c.hasV {
					c.hasV, c.inV = true, true
					c.cell.vStart = start
				}
			case "f":
				if c.active {
					c.cell.formula = true
				}
			case "t":
				if c.active {
					c.tCount++
					c.inT = c.tCount == 1
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "v":
				if c.inV {
					c.inV = false
					c.cell.vEnd = end
				}
			case "t":
				c.inT = false
			case "c":
				if c.active {
					emit()
					c = cellState{}
				}
			case "row":
				if rowHasText {
					v.addSeparator('\n')
				}
				rowHasText = false
			}
		case xml.CharData:
			if c.inV {
				c.vText.Write(t)
			}
			if c.inT && len(t) > 0 {
				c.tTokens = append(c.tTokens, boundaryToken{part: part, start: start, end: end, decoded: string(t)})
			}
		}
	}
	return v, true
}

// cellTypeAttrRe finds a cell's own t attribute (not a prefixed one) in its start tag.
var cellTypeAttrRe = regexp.MustCompile(`(\s)t\s*=\s*("[^"]*"|'[^']*')`)

// withCellType returns a <c ...> start tag with its t attribute set to typ, added if it had none.
func withCellType(tag []byte, typ string) []byte {
	out := make([]byte, 0, len(tag)+16)
	if loc := cellTypeAttrRe.FindSubmatchIndex(tag); loc != nil {
		out = append(out, tag[:loc[4]]...)
		out = append(out, '"')
		out = append(out, typ...)
		out = append(out, '"')
		return append(out, tag[loc[5]:]...)
	}
	end := len(tag) - 1 // a start tag with children ends in '>'
	out = append(out, tag[:end]...)
	out = append(out, ` t="`...)
	out = append(out, typ...)
	out = append(out, '"')
	return append(out, tag[end:]...)
}

// rewriteXLSXCell returns the bytes replacing [tagStart,vEnd) of a cell whose text becomes text.
func rewriteXLSXCell(content []byte, c *xlsxCell, text string) []byte {
	var b bytes.Buffer
	b.Grow(c.vEnd - c.tagStart + len(text) + 48)
	if c.formula {
		b.Write(withCellType(content[c.tagStart:c.tagEnd], "str"))
		b.Write(content[c.tagEnd:c.vStart])
		b.WriteString("<v>")
		escapeCharData(&b, text)
		b.WriteString("</v>")
		return b.Bytes()
	}
	b.Write(withCellType(content[c.tagStart:c.tagEnd], "inlineStr"))
	b.Write(content[c.tagEnd:c.vStart])
	b.WriteString(`<is><t xml:space="preserve">`)
	escapeCharData(&b, text)
	b.WriteString(`</t></is>`)
	return b.Bytes()
}

// boundaryViews builds the views the scanner's reader implies for docType, over every part it reads
// with a separator. DOCX has none here: its reader joins runs inside a paragraph with nothing, which the
// run-joined rewrite already covers, and a value across its paragraph or cell joins is left to the
// refusal.
func boundaryViews(files map[string][]byte, names []string, docType OfficeDocumentType) ([]*boundaryView, []boundaryToken) {
	var views []*boundaryView
	var toks []boundaryToken
	switch docType {
	case DocumentTypePPTX:
		for _, name := range names {
			lower := strings.ToLower(name)
			if !strings.HasSuffix(lower, ".xml") ||
				!(strings.HasPrefix(lower, "ppt/slides/") || strings.HasPrefix(lower, "ppt/notesslides/") ||
					strings.HasPrefix(lower, "ppt/slidemasters/")) {
				continue
			}
			if v, ok := elementView(name, files[name], "t", &toks); ok {
				views = append(views, v)
			}
		}
	case DocumentTypeODF:
		for _, name := range names {
			if lower := strings.ToLower(name); lower != "content.xml" && lower != "styles.xml" {
				continue
			}
			if v, ok := elementView(name, files[name], "p", &toks); ok {
				views = append(views, v)
			}
		}
	case DocumentTypeXLSX:
		var sst []string
		for _, name := range names {
			if strings.EqualFold(name, "xl/sharedStrings.xml") {
				sst, _ = xlsxSharedStrings(files[name])
				break
			}
		}
		for _, name := range names {
			lower := strings.ToLower(name)
			if !strings.HasPrefix(lower, "xl/worksheets/") || !strings.HasSuffix(lower, ".xml") {
				continue
			}
			if v, ok := xlsxSheetView(name, files[name], sst, &toks); ok {
				views = append(views, v)
			}
		}
	}
	return views, toks
}

// boundarySpanRange returns the first and last span of v touched by [a,b), or (-1,-1).
func boundarySpanRange(spans []boundarySpan, a, b int) (int, int) {
	first := sort.Search(len(spans), func(i int) bool { return spans[i].end > a })
	if first == len(spans) || spans[first].at >= b {
		return -1, -1
	}
	last := first
	for last+1 < len(spans) && spans[last+1].at < b {
		last++
	}
	return first, last
}

// boundaryPiece is the part of one occurrence that falls in one token, in that token's coordinates.
type boundaryPiece struct {
	tok    int
	lo, hi int
	with   string
}

// rewriteAcrossBoundaries rewrites every occurrence of values that the views of contents hold across a
// node boundary, and returns, per value rewritten, the parts it was rewritten in.
//
// values must be longest first; an occurrence that overlaps one already taken is left alone, so the
// longer value wins, as in every other rewrite here. repl gives each value's replacement. slice allows a
// replacement as long as its value to be cut at the node boundaries; simple never is, because its token
// belongs whole in one node.
//
// An occurrence inside a single node is skipped: the per-node rewrite has already run, so one there is a
// value that pass chose not to write, and the residue checks own that decision.
func rewriteAcrossBoundaries(contents *OfficeZipContents, docType OfficeDocumentType, values []string, repl map[string]string, slice bool) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	names := contents.orderedNames()
	views, toks := boundaryViews(contents.Files, names, docType)
	if len(views) == 0 {
		return nil
	}

	subs := make(map[int][]subEdit)
	partsFor := make(map[string]map[string]bool)
	for _, v := range views {
		text := v.sb.String()
		covered := make([]bool, len(text))
		for _, val := range values {
			with, ok := repl[val]
			if !ok || val == "" {
				continue
			}
			sliceable := slice && len(with) == len(val)
			for from := 0; from+len(val) <= len(text); {
				i := strings.Index(text[from:], val)
				if i < 0 {
					break
				}
				a, b := from+i, from+i+len(val)
				from = a + 1

				k0, k1 := boundarySpanRange(v.spans, a, b)
				if k0 < 0 || (k0 == k1 && v.spans[k0].at <= a && b <= v.spans[k0].end) {
					continue
				}
				if anyCovered(covered, a, b) {
					continue
				}

				pieces := make([]boundaryPiece, 0, k1-k0+1)
				cut := sliceable
				for pass := 0; pass < 2; pass++ {
					pieces = pieces[:0]
					first := true
					for k := k0; k <= k1; k++ {
						s := v.spans[k]
						lo, hi := s.at, s.end
						if a > lo {
							lo = a
						}
						if b < hi {
							hi = b
						}
						if lo >= hi {
							continue
						}
						p := boundaryPiece{tok: s.tok, lo: s.dec + (lo - s.at), hi: s.dec + (hi - s.at)}
						switch {
						case cut:
							p.with = with[lo-a : hi-a]
						case first:
							p.with = with
						}
						first = false
						pieces = append(pieces, p)
					}
					if !cut {
						break
					}
					// A slice that cuts a multi-byte character is not text; give the whole replacement
					// to the first node instead.
					valid := true
					for _, p := range pieces {
						if !utf8.ValidString(p.with) {
							valid = false
							break
						}
					}
					if valid {
						break
					}
					cut = false
				}

				for _, p := range pieces {
					if p.with == toks[p.tok].decoded[p.lo:p.hi] {
						continue // a slice that keeps the node's bytes (a kept digit) needs no rewrite
					}
					subs[p.tok] = append(subs[p.tok], subEdit{lo: p.lo, hi: p.hi, with: p.with})
					if partsFor[val] == nil {
						partsFor[val] = make(map[string]bool)
					}
					partsFor[val][toks[p.tok].part] = true
				}
				for j := a; j < b; j++ {
					covered[j] = true
				}
			}
		}
	}
	if len(subs) == 0 {
		return nil
	}

	edits := make(map[string][]spanEdit)
	order := make([]int, 0, len(subs))
	for k := range subs {
		order = append(order, k)
	}
	sort.Ints(order)
	for _, k := range order {
		t := toks[k]
		decoded := t.decoded
		list := subs[k]
		sort.Slice(list, func(i, j int) bool { return list[i].lo > list[j].lo })
		for _, e := range list {
			if e.lo < 0 || e.hi > len(decoded) || e.lo > e.hi {
				continue
			}
			decoded = decoded[:e.lo] + e.with + decoded[e.hi:]
		}
		var with []byte
		if t.cell != nil {
			with = rewriteXLSXCell(contents.Files[t.part], t.cell, decoded)
		} else {
			var buf bytes.Buffer
			escapeCharData(&buf, decoded)
			with = buf.Bytes()
		}
		edits[t.part] = append(edits[t.part], spanEdit{srcStart: t.start, srcEnd: t.end, with: with})
	}
	for _, name := range names {
		if es := edits[name]; len(es) > 0 {
			contents.addFile(name, applyEdits(contents.Files[name], es))
		}
	}

	out := make(map[string][]string, len(partsFor))
	for val, set := range partsFor {
		parts := make([]string, 0, len(set))
		for p := range set {
			parts = append(parts, p)
		}
		sort.Strings(parts)
		out[val] = parts
	}
	return out
}
