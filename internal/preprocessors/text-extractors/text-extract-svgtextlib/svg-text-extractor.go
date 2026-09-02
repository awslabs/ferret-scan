// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package textextractsvgtextlib extracts the HUMAN-READABLE text out of an SVG and
// nothing else.
//
// An SVG is XML, so the byte-sniffing text path claims it happily and hands the whole
// document — geometry included — to every validator. Measured at main a0e983c on a
// 75KB SVG built from integer-coordinate glyph paths, the shape real icon and font
// SVGs carry:
//
//	1,313 findings: PHONE 1,143 (162 HIGH), SSN 87, CREDIT_CARD 83,
//	SSN 3 HIGH + 73 LOW  --  every one of them path coordinates
//
// and on 90 real .svg files (9.8MB) collected off one workstation, 19 of 21 findings
// were geometry or base64 image data (`863 76 1012` -> SSN MEDIUM 85,
// `784 474 1269` -> PHONE MEDIUM 65, `8.25.75.75` -> IP_ADDRESS MEDIUM 75,
// `X5VGY3pL7gmlVe1Yr` out of an xlink:href data URI -> VIN MEDIUM 75).
//
// That flood is why embedded .svg parts were excluded from scanning altogether
// (embedded.SkipTextPipeline, #311), which made an SVG carrying PII in its <text>
// nodes a silent miss and, since only reported findings reach the redactor, a
// cleartext leak (#314).
//
// This package inverts the problem instead of trading one half for the other. It
// walks the document and emits ONLY the character data of prose-bearing elements and
// the values of prose-bearing attributes. Geometry is not filtered out after the
// fact — it is never collected, so no coordinate can reach a validator whatever a
// validator's numeric patterns happen to be. The set of things that CAN be emitted is
// an allowlist (proseElements, proseAttrs), so a construct nobody thought of is
// dropped rather than admitted.
package textextractsvgtextlib

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
)

// MaxSVGBytes bounds the document this package will read.
//
// The reader is capped rather than trusted because an .svg reaches here through the
// embedded-part path as well as the CLI, and an OOXML entry's declared size is
// producer-controlled. 32MB is far above any hand-authored drawing (the largest of
// the 90 real files measured above is 285KB) while keeping the worst case bounded.
const MaxSVGBytes = 32 * 1024 * 1024

// MaxDepth bounds element nesting.
//
// <g> nesting in real drawings is single digits; the AWS Architecture Icons package
// tops out at 9. A document deeper than this is a nesting bomb, and the answer is to
// stop DESCENDING while continuing to emit what has already been found, so the
// document is still partly scanned rather than dropped whole.
const MaxDepth = 256

// maxResyncs bounds how many times a syntax error restarts the parser.
//
// A malformed drawing has a handful of mistakes; a document with hundreds is either
// generated garbage or an attempt to make each restart cost another full parse of the
// remainder. The bound is what keeps the total work linear in the document rather than
// quadratic in the number of errors, and hitting it is reported as truncation.
const maxResyncs = 64

// TextContent is the extracted prose and the statistics the preprocessor reports.
//
// Shaped like textextractofficetextlib.TextContent and textextractpdftextlib.TextContent
// so text_preprocessor.go maps all three the same way.
type TextContent struct {
	Filename string
	Text     string
	Format   string

	WordCount int
	CharCount int
	LineCount int

	// Nodes counts the prose-bearing nodes that contributed text. Zero on a drawing
	// that is pure geometry, which is the CORRECT answer for such a file and not a
	// failure — see ExtractionWarning.
	Nodes int

	// NotSVG is true when the bytes are text but their root element is not <svg>.
	//
	// This is the mislabelled-file case, and it is the caller's cue to fall back to
	// scanning the raw bytes. Measured before the fallback existed: a plain text file
	// named .svg holding an SSN and an email reported 2 findings through the plaintext
	// preprocessor, and prose-only extraction would have reported 0 — a regression
	// dressed as a precision win.
	NotSVG bool

	// Truncated records that a bound fired (MaxSVGBytes or MaxDepth), so the text
	// below is partial.
	Truncated bool

	ExtractionWarning string
	ExtractionCause   coverage.Cause
}

// proseElements are the elements whose CHARACTER DATA is human-readable text.
//
// Keyed on the LOCAL name, lower-cased, so a namespace prefix (svg:text, from a
// document embedded in XHTML or in an OOXML part) is treated identically. SVG element
// names are themselves case-sensitive and camelCase (textPath, altGlyph), but a
// producer that writes TEXT or TextPath is the exact half-match this package must not
// have: matching case-insensitively costs nothing and admits it.
//
// Every entry is text a human reads:
//
//	text, tspan, textPath, tref, altGlyph, altGlyphDef, altGlyphItem, glyphRef
//	                    the rendered text content of the drawing (SVG 1.1 §10)
//	title, desc         the accessible name and description (SVG 1.1 §5.4) --
//	                    diagram callouts and author notes land here
//	metadata            RDF/Dublin Core: dc:title, dc:creator, cc:attributionName
//	flowRoot, flowDiv, flowPara, flowSpan, flowLine, flowRegionBreak
//	                    Inkscape flowed text; ordinary prose in every SVG the
//	                    Inkscape text tool has touched
//
// Deliberately ABSENT, and each absence is the point:
//
//	path, polygon, polyline, line, rect, circle, ellipse
//	                    geometry. These carry no character data in a well-formed
//	                    document, so an allowlist drops the malformed case too --
//	                    a <path>0 863 76 1012 109</path> is not prose.
//	style               CSS. Colour hex triples, font stacks, and base64 @font-face
//	                    payloads: machine text with the shape of a credential.
//	script              JavaScript. Same argument, plus it is the one element whose
//	                    content an attacker most wants echoed into a report.
//	image, use, defs, symbol, clipPath, mask, filter, pattern, marker, animate*
//	                    no prose of their own; their children are visited normally,
//	                    so a <text> inside a <symbol> is still collected.
var proseElements = map[string]bool{
	"text":     true,
	"tspan":    true,
	"textpath": true,
	"tref":     true,
	"title":    true,
	"desc":     true,
	"metadata": true,

	// SVG 1.1 alternate-glyph machinery. The character data is the fallback text a
	// reader sees when the glyph is unavailable, so it is prose.
	"altglyph":     true,
	"altglyphdef":  true,
	"altglyphitem": true,
	"glyphref":     true,

	// Inkscape flowed text (SVG 1.2 Tiny draft; Inkscape ships it by default).
	"flowroot":        true,
	"flowdiv":         true,
	"flowpara":        true,
	"flowspan":        true,
	"flowline":        true,
	"flowregionbreak": true,
}

// proseSubtrees are elements whose ENTIRE subtree is foreign prose markup.
//
// <foreignObject> holds XHTML — the mechanism every "export this whiteboard as SVG"
// tool uses for wrapped labels — so the text lives in <p>, <div> and <span>, none of
// which are SVG elements and none of which can be enumerated in proseElements without
// admitting the whole of HTML. Inside such a subtree the polarity flips: collect
// character data from everything except the two elements whose content is never prose.
var proseSubtrees = map[string]bool{
	"foreignobject": true,
}

// neverProse are the elements whose character data is machine text, in EITHER
// polarity — inside a foreign subtree as well as outside it.
//
// This is the one denylist in the package, and it exists because proseSubtrees
// inverts the default. A <style> or <script> inside a <foreignObject> is still CSS
// and still JavaScript.
var neverProse = map[string]bool{
	"style":  true,
	"script": true,
}

// proseAttrs are the attribute names whose VALUES are human-readable text.
//
// Keyed on the local name, lower-cased, so xlink:title and title match the same
// entry. The list is short on purpose: an attribute is admitted only if its value is
// prose written for a human by definition, never merely because it CAN hold prose.
//
//	aria-label, aria-description, aria-roledescription, aria-valuetext
//	                the accessible name and description (WAI-ARIA 1.2). The
//	                repo's own docs/images/demo.svg carries a sentence here.
//	alt             the fallback text convention for <image>
//	title           the tooltip attribute, including xlink:title
//	label           Inkscape layer and object labels (inkscape:label), which is
//	                where a diagram's author names things
//	docname         sodipodi:docname: the file's original name on the author's
//	                disk, which is a path and routinely carries a person's name
//	content         <meta http-equiv=... content=...> inside a <foreignObject>
//
// Deliberately ABSENT: d, points, transform, viewBox, x, y, dx, dy, cx, cy, r, rx,
// ry, x1, y1, x2, y2, width, height, offset, gradientTransform, patternTransform,
// clip-path, stroke-dasharray, style, href, xlink:href, id, class, and every other
// presentation attribute. Because this is an allowlist they are excluded by
// construction rather than by being listed, so an attribute a future SVG version adds
// is dropped by default. Two of those absences were each measured producing a false
// positive above: `d` (SSN, PHONE, CREDIT_CARD) and `xlink:href` (VIN, out of the
// base64 of an embedded raster).
//
// `id` is absent although it is author-chosen and can read as prose. It is also
// generator-chosen far more often ("image0_407_6053", "SVGID_1_"), and admitting it
// re-introduces exactly the opaque-token surface this package removes.
var proseAttrs = map[string]bool{
	"aria-label":           true,
	"aria-description":     true,
	"aria-roledescription": true,
	"aria-valuetext":       true,
	"alt":                  true,
	"title":                true,
	"label":                true,
	"docname":              true,
	"content":              true,
}

// ExtractText extracts the prose from the SVG at filePath.
func ExtractText(filePath string) (*TextContent, error) {
	content := &TextContent{
		Filename: filepath.Base(filePath),
		Format:   "SVG Image",
	}

	f, err := os.Open(filepath.Clean(filePath)) // #nosec G304 -- path already vetted by the router
	if err != nil {
		content.ExtractionCause = coverage.CauseUnreadable
		content.ExtractionWarning = fmt.Sprintf(
			"no text extracted from %s: %v, so drawing text was NOT scanned",
			filepath.Ext(filePath), err)
		return content, fmt.Errorf("failed to open SVG: %w", err)
	}
	defer func() { _ = f.Close() }()

	return extract(f, content, filepath.Ext(filePath))
}

// ExtractFromBytes extracts the prose from in-memory SVG bytes.
//
// Exported for the tests and for any caller holding a part's decompressed bytes; the
// filesystem is not part of this package's contract.
func ExtractFromBytes(name string, data []byte) (*TextContent, error) {
	content := &TextContent{
		Filename: filepath.Base(name),
		Format:   "SVG Image",
	}
	return extract(bytes.NewReader(data), content, filepath.Ext(name))
}

// extract does the walk. Split from ExtractText so the bounds and the parser are
// exercised without a file on disk.
func extract(r io.Reader, content *TextContent, ext string) (out *TextContent, err error) {
	// The XML parser is fed producer-controlled bytes. encoding/xml is memory-safe
	// and does not expand DTD entity declarations at all, which is what makes the
	// billion-laughs shape a non-event here rather than a bound to tune -- but a
	// panic anywhere below would take down a whole directory scan, and the router's
	// own recover() would report it as a preprocessor failure with a temp path in
	// the message. Recovering here keeps the failure describable.
	defer func() {
		if r := recover(); r != nil {
			out = content
			out.ExtractionCause = coverage.CauseUnparseable
			out.ExtractionWarning = fmt.Sprintf(
				"no text extracted from %s: the XML parser failed, so drawing text was NOT scanned", ext)
			err = fmt.Errorf("SVG parser panic on %s: %v", content.Filename, r)
		}
	}()

	// Read at most one byte past the cap so a document AT the cap is not reported as
	// truncated and a document past it is.
	raw, readErr := io.ReadAll(io.LimitReader(r, MaxSVGBytes+1))
	if readErr != nil {
		content.ExtractionCause = coverage.CauseUnreadable
		content.ExtractionWarning = fmt.Sprintf(
			"no text extracted from %s: %v, so drawing text was NOT scanned", ext, readErr)
		return content, fmt.Errorf("failed to read SVG: %w", readErr)
	}
	if len(raw) > MaxSVGBytes {
		raw = raw[:MaxSVGBytes]
		content.Truncated = true
	}

	// Root-element gate, before any collection.
	//
	// A file named .svg whose root is not <svg> is a MISLABELLED file, not an SVG,
	// and prose-only extraction is the wrong reading of it. Reporting NotSVG lets the
	// caller scan the raw bytes instead, which is what the plaintext preprocessor did
	// for such a file before .svg was claimed here.
	if !looksLikeSVG(raw) {
		content.NotSVG = true
		return content, nil
	}

	var b strings.Builder
	// Emitting one line per node is what gives a finding a line number an operator can
	// act on, and it also separates two adjacent labels so a validator cannot read a
	// value spanning the join between them.
	emit := func(s string) {
		s = collapseSpace(s)
		if s == "" {
			return
		}
		b.WriteString(s)
		b.WriteByte('\n')
		content.Nodes++
	}

	dec := xml.NewDecoder(bytes.NewReader(raw))
	// Strict=false is REQUIRED, not a convenience. An SVG in the wild carries HTML
	// entities (&nbsp;) that no XML DTD declares, and in strict mode the decoder stops
	// at the first one -- which would silently truncate the prose of an otherwise fine
	// drawing. Non-strict mode passes an unknown entity through as literal text.
	dec.Strict = false
	// AutoClose covers the void elements a <foreignObject> full of HTML brings with it
	// (<br>, <img>, <hr>), which in strict XML terms are unclosed tags.
	dec.AutoClose = xml.HTMLAutoClose
	// Entity seeds the HTML entity table. Without it &nbsp; survives as the literal
	// text "&nbsp;" in non-strict mode, which is harmless but would appear inside a
	// value and could split a match.
	dec.Entity = xml.HTMLEntity

	// stack holds the local names of the open elements, so a decision needs no
	// lookahead and no second pass.
	var stack []string
	// proseDepth > 0 means we are inside a proseElements element; subtreeDepth > 0
	// means inside a proseSubtrees element. Counters rather than booleans so nesting
	// (a <tspan> inside a <text>) unwinds correctly.
	proseDepth, subtreeDepth, neverDepth := 0, 0, 0
	// stopped is set by the depth bound. A separate flag rather than a break inside
	// the type switch, which would only leave the switch.
	stopped := false

	// consumed is how much of raw the decoders retired, so a resync can advance.
	consumed := int64(0)
	resyncs := 0

	for !stopped {
		tok, tokErr := dec.Token()
		if tokErr != nil {
			if errors.Is(tokErr, io.EOF) {
				break
			}
			// A MALFORMED document is partly scanned, not refused, AND the parser is
			// resynchronised past the offending construct.
			//
			// Stopping at the first syntax error loses every label BELOW it, and hand-
			// edited SVG is routinely malformed. Measured on
			// `<svg></g></tspan><text>Employee SSN: ...</text></svg>` -- a stray close
			// tag, which encoding/xml rejects even with Strict=false: stopping recovered
			// ZERO nodes, resyncing recovers the SSN. The stray tag is before the value,
			// so a reader that stops reports a clean drawing over a document holding an
			// SSN.
			//
			// Resync is a fresh decoder over the remaining bytes, which DISCARDS the
			// element stack. That fails closed rather than open: with proseDepth back at
			// 0 the default is to drop character data, so restarting inside a <style>
			// block cannot start collecting CSS -- it can only miss prose, never invent
			// it.
			//
			// Bounded twice. resyncs caps the number of restarts, and each restart must
			// advance `consumed` strictly, so a construct the parser cannot get past
			// terminates the loop instead of spinning on it.
			content.Truncated = true

			off := consumed + dec.InputOffset()
			if resyncs >= maxResyncs || off <= consumed || off >= int64(len(raw)) {
				break
			}
			// Step one byte past the offset the decoder stopped at. Without the +1 the
			// new decoder re-reads the same offending byte and fails identically, and
			// the strict-progress test above would then end the loop with the remainder
			// unread.
			consumed = off + 1
			resyncs++
			dec = xml.NewDecoder(bytes.NewReader(raw[consumed:]))
			dec.Strict = false
			dec.AutoClose = xml.HTMLAutoClose
			dec.Entity = xml.HTMLEntity
			stack = stack[:0]
			proseDepth, subtreeDepth, neverDepth = 0, 0, 0
			continue
		}

		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= MaxDepth {
				// Refuse to DESCEND, and stop. Continuing to read tokens while
				// ignoring them buys nothing and a nesting bomb is cheap to write.
				content.Truncated = true
				stopped = true
				continue
			}
			name := localName(t.Name.Local)
			stack = append(stack, name)

			switch {
			case neverProse[name]:
				neverDepth++
			case proseSubtrees[name]:
				subtreeDepth++
			case proseElements[name]:
				proseDepth++
			}

			// Attributes are read for EVERY element, prose-bearing or not: an
			// aria-label on a <g> or a <path> is still the accessible name a human
			// reads. Only the attribute NAME decides, never the element's.
			if neverDepth == 0 {
				for _, a := range t.Attr {
					name := localName(strings.ToLower(a.Name.Local))
					if proseAttrs[name] {
						emit(a.Value)
						continue
					}
					// href / xlink:href are admitted by VALUE, not by name — the only
					// value-conditional rule in this package. See contactTarget.
					if linkAttrs[name] {
						if v, ok := contactTarget(a.Value); ok {
							emit(v)
						}
					}
				}
			}

		case xml.EndElement:
			if len(stack) == 0 {
				// A stray close tag in a malformed document. Ignore it rather than
				// unwinding past the bottom of the stack.
				continue
			}
			name := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			switch {
			case neverProse[name]:
				if neverDepth > 0 {
					neverDepth--
				}
			case proseSubtrees[name]:
				if subtreeDepth > 0 {
					subtreeDepth--
				}
			case proseElements[name]:
				if proseDepth > 0 {
					proseDepth--
				}
			}

		case xml.CharData:
			if neverDepth > 0 {
				continue
			}
			if proseDepth > 0 || subtreeDepth > 0 {
				emit(string(t))
			}

		case xml.Comment:
			// An XML comment is author-written prose and is exactly where a "TODO:
			// ask bob@example.com" ends up. It is not geometry, so it is collected.
			// Skipped inside <style>/<script> along with their character data: a
			// comment there is a CSS or JavaScript comment.
			if neverDepth == 0 {
				emit(string(t))
			}
		}
	}

	content.Text = b.String()
	content.CharCount = len(content.Text)
	content.WordCount = len(strings.Fields(content.Text))
	content.LineCount = len(strings.Split(content.Text, "\n"))

	// TRUNCATION IS DISCLOSED. NO PROSE IS NOT.
	//
	// Order matters, and an earlier revision had it the other way round: a nesting
	// bomb reaches the depth bound with zero prose collected, so testing Nodes == 0
	// first reported "there was no text" about a document that was cut short. That is
	// a true disclosure under a false heading, which is half a fix.
	if content.Truncated {
		content.ExtractionWarning = fmt.Sprintf(
			"%s was only partly read (size or nesting bound, or malformed markup), "+
				"so some drawing text was NOT scanned", ext)
		content.ExtractionCause = coverage.CauseCutShort
		return content, nil
	}

	// A drawing that parsed completely and carried no prose is CLEAN AND FULLY
	// HANDLED, and says nothing. This is a deliberate choice against the PDF
	// extractor's, which warns for a page that parsed with no text layer, and the
	// reason is which of the two situations is ambiguous.
	//
	// A PDF page with no text layer is a page of visible text a human reads and the
	// tool did not: coverage was genuinely lost. An SVG with no prose nodes is
	// overwhelmingly an ICON -- a chevron, a logo mark, a status dot -- with no text
	// in it at all, so claiming lost coverage would be a false alarm on nearly every
	// .svg in existence. Measured on 90 real .svg files off one workstation: 88 carry
	// no prose. Eighty-eight NOT-FULLY-EXAMINED lines, and exit 3 under
	// --fail-on-incomplete, is how the disclosure that matters becomes noise an
	// operator filters out -- the same argument base_metadata_preprocessor.go makes
	// for not warning about every decorative .emf.
	//
	// The case this gives up is text CONVERTED TO OUTLINES, which Illustrator does on
	// export: the drawing shows words and carries only <path>. That is unreadable
	// without glyph reconstruction, and it is the same class of gap as the pixels of a
	// raster image, which this tool also does not warn about per file. It is a known
	// limitation, not a silence about something we could have read.
	return content, nil
}

// looksLikeSVG reports whether the first element of the document is <svg>.
//
// Deliberately a scan of the LEADING markup rather than a full parse: the caller needs
// this answer before deciding which of two readings of the file to take, and a
// document whose root is <svg> but whose body is malformed must take the SVG reading
// (partly scanned) rather than the raw-text one.
//
// It skips the XML declaration, comments, processing instructions and a DOCTYPE, which
// is everything that can legally precede the root element.
func looksLikeSVG(raw []byte) bool {
	s := raw
	for {
		i := bytes.IndexByte(s, '<')
		if i < 0 {
			return false
		}
		s = s[i+1:]
		switch {
		case bytes.HasPrefix(s, []byte("?")):
			// <?xml ...?> or a processing instruction.
			j := bytes.Index(s, []byte("?>"))
			if j < 0 {
				return false
			}
			s = s[j+2:]
		case bytes.HasPrefix(s, []byte("!--")):
			j := bytes.Index(s[3:], []byte("-->"))
			if j < 0 {
				return false
			}
			s = s[3+j+3:]
		case bytes.HasPrefix(s, []byte("!")):
			// DOCTYPE, possibly with an internal subset. Skipping to the matching
			// ">" is enough: an internal subset's own ">" characters only appear
			// inside declarations, and getting this wrong costs at most a false
			// "not an SVG", which falls back to scanning the raw bytes.
			j := bytes.IndexByte(s, '>')
			if j < 0 {
				return false
			}
			s = s[j+1:]
		default:
			// The first real element. Compare its LOCAL name so svg:svg matches.
			end := bytes.IndexAny(s, " \t\r\n>/")
			if end < 0 {
				end = len(s)
			}
			return localName(string(s[:end])) == "svg"
		}
	}
}

// localName strips a namespace prefix ("svg:text" -> "text") and lower-cases the rest.
func localName(n string) string {
	if i := strings.LastIndexByte(n, ':'); i >= 0 {
		n = n[i+1:]
	}
	return strings.ToLower(n)
}

// collapseSpace trims a node's text and folds internal whitespace runs to one space.
//
// Needed because SVG markup is indented: a <desc> spanning three source lines arrives
// as one CharData full of newlines, and emitting it verbatim would split a value
// across output lines and cost the finding. Folding is done in a single pass with one
// allocation, so it stays linear in the node's length -- the scaling measurement in
// svg_complexity_test.go depends on it.
func collapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteByte(c)
	}
	return b.String()
}

// linkAttrs are the attributes whose value is a link TARGET rather than prose. Their values are
// admitted only through contactTarget, never wholesale.
var linkAttrs = map[string]bool{"href": true}

// contactTarget returns the contact inside a mailto: or tel: URI, and whether the value is one.
//
// This is the single value-conditional admission in this package, and the reason it earns an
// exception to the name-only rule above is that a link target is the commonest place a real diagram
// carries a contact: an <a xlink:href="mailto:..."> wrapping a "Contact the owner" label puts the
// address in the attribute and only the label in the text node. Measured on such a diagram, the
// address was reported at HIGH 100 by the pre-#314 raw-XML scan and not at all by the prose
// extractor, so excluding every href traded 1,313 coordinate false positives for one real miss.
//
// Only mailto: and tel: are admitted, and that restriction is what keeps the flood out. Measured on
// 300 <a> elements whose href is an ordinary numeric CDN asset URL
// (https://cdn.example.com/asset/1234567890/v2): scanning those targets yields 256 PHONE and 9 NPI
// findings, every one false. The same rule admits 0 of them, because none is a contact scheme.
// http/https/data/fragment/relative targets stay excluded by construction — this is an allowlist of
// two schemes, not a denylist.
//
// The scheme is matched case-insensitively because RFC 3986 §3.1 defines it as case-insensitive, and
// real files do write "MAILTO:". Percent-encoding is decoded because a generator may emit
// "mailto:a%40b.example" for an address a validator would otherwise never see; a value that fails to
// decode is passed through as-is rather than dropped, since a malformed escape is not a reason to
// lose the contact.
//
// The scheme prefix itself is stripped so the emitted text is the bare address or number. Leaving
// "mailto:" attached made the EMAIL validator's own boundary handling the thing under test, which is
// not this package's business. Any ?subject=/&body= query is cut for the same reason: it is prose
// aimed at a mail client, and admitting it re-opens an unbounded surface.
func contactTarget(raw string) (string, bool) {
	v := strings.TrimSpace(raw)
	lower := strings.ToLower(v)
	var rest string
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		rest = v[len("mailto:"):]
	case strings.HasPrefix(lower, "tel:"):
		rest = v[len("tel:"):]
	default:
		return "", false
	}
	// Drop a mailto query (?subject=, &body=) and any fragment.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	// PathUnescape, NOT QueryUnescape: the latter decodes "+" to a SPACE, which destroys the
	// international prefix of a tel: number. Measured — "tel:+14159263481" came out as
	// "14159263481", and PHONE then declined it. A tel: URI is a path, not a query.
	if dec, err := url.PathUnescape(rest); err == nil {
		rest = dec
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return rest, true
}
