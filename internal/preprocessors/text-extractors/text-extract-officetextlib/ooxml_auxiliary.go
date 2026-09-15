// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"regexp"
	"strings"
)

// Auxiliary part coverage: the parts that hold user text but no format pass reads, and the parts
// deliberately left out — with every one of them CLASSIFIED, so a part nobody has considered fails
// the build instead of being silently missed.
//
// # The class, and why one more `matching()` call is not a fix
//
// Part coverage has now been wrong seven times: an extension list that omitted a real part name, a
// container the extractor walked but the redactor did not, a case-sensitive match, docProps behind a
// body-part prefix, the *.rels parts that are in no predicate at all (#670), and then #680, which
// found six MORE parts read by nothing. Each was fixed at its own site, which is exactly what
// guaranteed the next one. The part names are chosen by producers and the set grows with every Office
// release — ppt/comments/modernComment_*.xml did not exist when this extractor was written — so no
// list of names written today can be complete tomorrow.
//
// # Why the answer is not "read everything"
//
// That was the first implementation, and it was MEASURED on 399 real .docx/.xlsx/.pptx: +3,348
// findings, +47.7%, +680 in the HIGH band. Sampled, the additions were dominated
// by template and producer parts, not by content:
//
//	ppt/slideLayouts/*      ~50 findings PER LAYOUT part, in decks with 26 of them: the deck's
//	                        copyright and confidentiality boilerplate re-reported once per layout,
//	                        plus 10-digit ids read as PHONE at confidence 85
//	ppt/notesMasters/*      the same boilerplate again
//	word/numbering.xml      list-definition GUID fragments as PHONE and SWIFT_BIC
//	xl/externalLinks/*      cached remote workbook labels: "Hong Kong" and "Middle East" as
//	                        PERSON_NAME at confidence 92-100
//
// That is the customXml result (#679: 403 findings, false positives essentially throughout) at nine
// times the scale, and it would bury the real values this change exists to surface.
//
// # So: three states, and the third one fails CI
//
// Every XML part in a container is one of:
//
//	INCLUDED   — listed in auxiliaryPartIncludes below, read by this pass.
//	EXCLUDED   — listed in auxiliaryPartExclusions below WITH a reason, deliberately not read.
//	unclassified — neither. TestOfficePartCoverageIsClassified in cmd/ FAILS on it.
//
// The gate is that third state. An allowlist alone is what failed seven times, because nothing
// asserted it was complete; here a producer part nobody has thought of does not go silently unread —
// it stops the build and someone decides which of the two lists it belongs in, with a reason. That
// keeps the precision an allowlist gives while removing the silence that made it dangerous.
//
// Under the sink rule the cost of the two mistakes is not symmetric — a part the extractor does not
// read is written to the "redacted" copy in cleartext at exit 0, while an extra part costs review
// noise — which is why the unclassified state is an error rather than a default in either direction.
//
// # Why attribute values, and not just character data
//
// Stripping tags and keeping character data — what every other extraction path here does — misses
// three of #680's six parts outright, because in configuration-shaped parts the user's text lives in
// an ATTRIBUTE:
//
//	<p:tag name="OWNER" val="..."/>              ppt/tags
//	<tableColumn id="1" name="..."/>             xl/tables — user-authored column headings
//	<p:custShow name="..."/>                     ppt/presentation.xml
//
// while chart titles (xl/charts, word/charts) and PowerPoint comments are ordinary <a:t> character
// data. So both are read. Attributes are taken by NAME from labelBearingAttrs below rather than
// wholesale: an OOXML part is mostly ids, GUIDs, style tokens and measurements, and reading every
// attribute value would bury real findings in them. An attribute-name list is a fair thing to
// maintain where a part-name list is not — the names are fixed by the ECMA-376 schema, not chosen
// per document by the producer.

// auxiliaryPartIncludes are the part families this pass reads. Each entry is a lowercased path
// fragment matched anywhere in the part name, so a producer's directory casing cannot drop one.
var auxiliaryPartIncludes = []struct {
	match string
	why   string
}{
	{"ppt/comments/", "PowerPoint review comments (modernComment_*.xml), the direct analogue of the " +
		"Word and Excel comment parts already read. A review comment naming a person is ordinary"},
	{"ppt/tags/", "producer and user tags; the value is in a `val` ATTRIBUTE, so a character-data " +
		"pass sees nothing"},
	{"ppt/presentation.xml", "presentation-level text. This part was already resolved to follow its " +
		"relationships to the slides, which is why the gap was invisible: it was in the package map " +
		"but no pass extracted its text"},
	{"xl/tables/", "table column headings, which are user-authored, in a `name` ATTRIBUTE"},
	{"xl/charts/", "chart titles and series labels"},
	{"word/charts/", "chart titles and series labels; on the real corpus word/chartN.xml held " +
		"PERSON_NAME and VIN"},

	// Found by the coverage guard, NOT by #680, which listed six parts. Classifying every XML part in
	// the real corpus left 23 unclassified, and five of them hold authored text — three of those
	// hold display names. This is the guard doing the job the issue's own list could not.
	{"word/people.xml", "comment author display names, in a `w15:person w15:author` ATTRIBUTE. " +
		"Present in 47 real containers and read by nothing before this change. A reviewer's " +
		"name is exactly what the tool already reports out of docProps, so omitting it here was " +
		"inconsistent as well as a miss"},
	{"ppt/commentauthors.xml", "comment author display names (`p:cmAuthor name`) and the presence " +
		"records beside them (`p15:presenceInfo userId`). Present in 26 real containers"},
	{"ppt/authors.xml", "modern comment author display names (`p188:author name`). Present in 13 of " +
		"the real corpus"},
	{"diagrams/data", "SmartArt content, for both word/diagrams/ and ppt/diagrams/. Ordinary authored " +
		"text — an org chart is a diagram full of names — held in a:t runs like any other DrawingML. " +
		"All 23 such parts in the corpus carry at least one run"},
	{"word/glossary/", "Quick Parts and AutoText: user-defined building blocks. Mostly template " +
		"scaffolding — 12 of 16 real parts hold nothing but [placeholder] runs — but a saved building " +
		"block is authored content, and under the sink rule a part that SOMETIMES holds a value is read"},
}

var auxiliaryPartExclusions = []struct {
	// match is a lowercased path fragment; prefix true compares against the start of the part
	// name, false anywhere in it.
	match  string
	prefix bool
	why    string
}{
	{"[content_types].xml", true, "package manifest: content types and extensions, no user text"},
	{"_rels/", false, "relationship parts are read by appendExternalRelationshipTargets, which " +
		"handles TargetMode=External targets; reading them here would double-report every hyperlink"},
	{"docprops/", true, "core/app/custom properties are the metadata extractor's job (office_metadata); " +
		"reading them here would report every title and author twice, in two different sections"},
	{"customxml/", true, "MEASURED and deliberately excluded: 403 findings across 422 real containers, " +
		"false positives essentially throughout — zero-padded record ids as PHONE (210) and " +
		"DRIVERS_LICENSE (99), nine-digit record ids as SSN (27), and country names as PERSON_NAME at " +
		"confidence 93-100 (30). The part is a column-per-element schema dump, so it is bare " +
		"identifiers with no surrounding words and every context-weighing validator has nothing to " +
		"weigh. It does carry real values and is present in 207 of 402 real .docx, so this needs a " +
		"precision approach for unlabelled identifiers rather than another extraction call (#680)"},
	{"/theme/", false, "colour palettes and typeface names defined by the template, not the author"},
	{"styles.xml", false, "style definitions; style NAMES are template vocabulary (\"Heading 1\")"},
	{"styleswitheffects.xml", false, "as styles.xml, kept for older Word versions"},
	{"fonttable.xml", false, "the fonts the document references"},
	{"websettings.xml", false, "HTML round-trip settings written by the producer"},
	{"settings.xml", false, "producer configuration: MEASURED at zero findings across 403 real " +
		"containers, and it holds revision-tracking GUIDs that read as identifiers"},
	{"calcchain.xml", false, "formula evaluation order: cell references and numeric ids only"},
	{"presprops.xml", false, "presentation view/producer properties"},
	{"viewprops.xml", false, "presentation view state"},
	{"tablestyles.xml", false, "table style definitions from the template"},
	{"sharedstrings.xml", false, "already read by extractSharedStringsSimple, which resolves the " +
		"cell references that point INTO it; reading it again reports every cell twice"},
	{"ppt/slidelayouts/", true, "MEASURED: ~50 findings per layout part, and a deck carries up to 26 " +
		"of them — the same copyright and confidentiality boilerplate re-reported once per layout, " +
		"plus 10-digit layout ids as PHONE at confidence 85. Layout placeholder text is template " +
		"vocabulary (\"Click to add title\"), not authored content; anything a user typed lives on the " +
		"slide, which is read"},
	{"ppt/notesmasters/", true, "the notes template: the same per-deck boilerplate as slideLayouts"},
	{"ppt/slidemasters/", true, "already extracted by the master loop in extractPptxText"},
	{"ppt/notesslides/", true, "already extracted per slide, resolved through that slide's own " +
		"relationships so the notes are attributed to the right slide"},
	{"ppt/slides/", true, "already extracted by the slide loop in extractPptxText"},
	{"xl/worksheets/", true, "already extracted by the worksheet loop in extractXlsxText"},
	{"xl/externallinks/", true, "MEASURED: cached labels from a remote workbook, which produced " +
		"\"Hong Kong\" and \"Middle East\" as PERSON_NAME at confidence 92-100. The values are a stale " +
		"copy of another document's headings, not this document's content"},
	{"numbering.xml", false, "MEASURED: list-numbering definitions, whose GUID fragments read as " +
		"PHONE and SWIFT_BIC. No user prose"},
	{"word/document.xml", true, "the body, extracted by extractDocxText"},
	{"word/header", true, "already extracted by the header loop"},
	{"word/footer", true, "already extracted by the footer loop"},
	{"word/comments", true, "already extracted by the annotation loop"},
	{"word/footnotes", true, "already extracted by the annotation loop"},
	{"word/endnotes", true, "already extracted by the annotation loop"},
	{"xl/comments", true, "already extracted by the comment loop in extractXlsxText"},
	{"xl/threadedcomments/", true, "already extracted by the comment loop"},
	{"xl/persons/", true, "already extracted by the comment loop; holds threaded-comment authors"},
	{"xl/workbook.xml", true, "sheet names are read from here by the worksheet pass"},
	{"ppt/tablestyles.xml", true, "table style definitions from the template"},
	{"xl/metadata.xml", true, "cell-metadata type definitions, no values"},
	{"xl/connections.xml", true, "data-source connection strings are producer configuration"},
	{"drawing", false, "shape geometry and positioning; any text in a drawing is in the a:t runs of " +
		"the part that owns it, which is read"},
	{"vmldrawing", false, "legacy VML shape geometry for comment anchors"},
	{"activex", false, "embedded control state, not text"},
	{"ctrlprop", false, "embedded control properties"},
	{"chartcolorstyle", false, "chart colour variation from the template"},
	{"chartstyle", false, "chart style definition from the template"},
	{"colors", false, "colour definitions"},
	{"slicer", false, "PivotTable slicer definitions: cache field references"},
	{"pivotcache", false, "PivotTable cache: a machine copy of source cells that are read in the " +
		"worksheet they came from"},
	{"pivottable", false, "PivotTable layout definition"},
	{"querytable", false, "external query definition"},
	{"volatiledependencies", false, "volatile function dependency tracking"},
	{"person.xml", false, "modern comment authors, read with the threaded comments"},
	{"docmetadata", false, "producer document metadata mirrors"},
	{"embeddings/", false, "embedded OLE objects: the embedded-container path's job, not this one"},
	{"printersettings", false, "printer configuration"},

	// The rest of what the coverage guard surfaced across the real corpus. Each was inspected and
	// holds no authored text, so it is skipped rather than left unclassified.
	{"diagrams/layout", false, "SmartArt layout ALGORITHM definition; the content is in data*.xml"},
	{"diagrams/quickstyle", false, "SmartArt style variation from the template"},
	{"diagrams/drawing", false, "SmartArt rendered geometry, generated from data*.xml"},
	{"ppt/handoutmasters/", true, "the handout template: per-deck boilerplate, like slideLayouts"},
	{"ppt/revisioninfo.xml", true, "co-authoring revision tokens: inspected, no text and no names"},
	{"ppt/changesinfos/", true, "co-authoring change log: revision ids, no authored text"},
	{"word/tasks.xml", true, "comment-task state: inspected across 3 real parts, no text, no names"},
	{"word/documenttasks/", true, "comment-task assignment records; an assignee's display name " +
		"reaches the report through word/people.xml, which IS read"},
	{"word/intelligence", true, "Word's writing-assistance annotations: inspected across 20 real " +
		"parts, no text and no names"},
	{"webextensions/", false, "Office add-in configuration: app ids, store references, taskpane state"},
	{"word/customizations.xml", true, "UI ribbon and toolbar customisation"},
}

// labelBearingAttrs names the (element, attribute) pairs that carry human-authored text in
// ECMA-376. Keys are "element|attribute", both lowercased with any namespace prefix removed.
//
// # Why the pair, and not the attribute name alone
//
// Because `val` is OOXML's UNIVERSAL scalar attribute, and keying on it alone was measured wrong.
// The first version of this list had a bare "val", added for <p:tag name="OWNER" val="..."/>, and it
// produced 24 false positives across the real corpus — every one of them a chart axis identifier:
//
//	<c:axId val="1829252287"/>       -> PHONE, confidence 25
//	<c:crossAx val="1978746304"/>    -> PHONE, confidence 25
//
// The same attribute spells gap widths, overlaps, orientations, booleans and tick positions. Its
// meaning is entirely a function of the element holding it, so the element has to be part of the key.
// Elements are cheap to enumerate here because these are schema names fixed by ECMA-376, not part
// names chosen per document by a producer — which is the distinction that makes this list
// maintainable where a part-name allowlist is not.
var labelBearingAttrs = map[string]bool{
	"tag|val":                true, // <p:tag name="OWNER" val="..."/> — the tag's user-set value
	"tag|name":               true, // and its user-set key
	"tablecolumn|name":       true, // xl/tables: the column heading a user typed
	"table|name":             true,
	"table|displayname":      true,
	"custshow|name":          true, // ppt/presentation.xml: a named custom show
	"definedname|name":       true, // a user-named range
	"hlinkclick|tooltip":     true, // hyperlink tooltip text
	"hyperlink|tooltip":      true,
	"comment|author":         true,
	"threadedcomment|author": true,
	"person|author":          true, // word/people.xml: <w15:person w15:author="..."/>
	"cmauthor|name":          true, // ppt/commentAuthors.xml: <p:cmAuthor name="..."/>
	// NOT p15:presenceInfo/@userId, which sits beside cmAuthor in the same part and looks like a
	// second copy of the name. It is one in some containers and an internal NUMERIC id in most:
	// measured, it produced 21 SSN findings from a 9-digit id present in 18 containers. The
	// author's name is already carried by cmAuthor/@name, so reading userId adds a false positive and
	// no recall.
	"author|name": true, // ppt/authors.xml: <p188:author name="..."/>
}

var (
	// xmlTagRe strips markup; xmlAttrRe pulls attribute name/value pairs out of the markup that
	// was stripped, so a value in an attribute is not lost with the tag that held it.
	xmlTagRe  = regexp.MustCompile(`(?s)<[^>]*>`)
	xmlAttrRe = regexp.MustCompile(`([A-Za-z_][\w:.-]*)\s*=\s*"([^"]*)"`)

	// drawingTextRunRe isolates DrawingML text runs. Any namespace prefix is accepted because a
	// producer chooses it: the conventional "a" is not required by the schema, and a part that spelled
	// it differently would otherwise contribute nothing. (?s) so a run split across lines is kept.
	drawingTextRunRe = regexp.MustCompile(`(?s)<(?:[A-Za-z_][\w.-]*:)?t\b[^>]*>(.*?)</(?:[A-Za-z_][\w.-]*:)?t>`)
)

// partClassification is the three-state answer for one part name.
type partClassification int

const (
	// partUnclassified is the state that fails the build: nobody has decided about this part.
	partUnclassified partClassification = iota
	partIncluded
	partExcluded
)

// classifyPart returns whether a part is read, deliberately skipped, or unclassified, and the reason
// recorded for it. Exclusions are checked BEFORE inclusions so a narrower "already read elsewhere"
// entry wins over a broad include prefix.
func classifyPart(name string) (partClassification, string) {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".xml") {
		return partExcluded, "not an .xml part: media, binary OLE data, or a .rels part handled elsewhere"
	}
	for _, ex := range auxiliaryPartExclusions {
		if ex.prefix {
			if strings.HasPrefix(lower, ex.match) {
				return partExcluded, ex.why
			}
			continue
		}
		if strings.Contains(lower, ex.match) {
			return partExcluded, ex.why
		}
	}
	for _, in := range auxiliaryPartIncludes {
		if strings.Contains(lower, in.match) {
			return partIncluded, in.why
		}
	}
	return partUnclassified, ""
}

// AuxiliaryPartDecision reports the classification of a part name for the coverage guard in cmd/,
// which is in a different package. Returns the state and the recorded reason.
//
// Exported solely for that guard: the guard must ask the SAME function the extractor uses, or it
// would be testing a copy of the rules rather than the rules.
func AuxiliaryPartDecision(name string) (included, excluded bool, why string) {
	c, why := classifyPart(name)
	return c == partIncluded, c == partExcluded, why
}

// extractAuxiliaryPartText returns the AUTHORED text of one part: its label-bearing attribute values
// and its DrawingML text runs. It deliberately does not return arbitrary character data.
//
// # Why not all character data
//
// Because a chart part is mostly a numeric cache. Taking every character-data run from the six
// included parts was MEASURED on 399 real containers: +29 findings, and sampling every one of them
// showed they were false positives essentially throughout, all from <c:v> cache entries inside
// xl/charts and word/charts:
//
//	VIN         78260869565217395   confidence 90   a 17-digit cached datum, not a VIN
//	PHONE       1978746304          confidence 25   10-digit cached data, many of them
//	SSN         870366751           confidence 50   9-digit cached datum
//	PERSON_NAME "Security Engineer III"  confidence 63   a job title from a series label
//
// That is the customXml result in miniature, and it refutes the reason #680 gave for reading chart
// parts at all ("word/chartN.xml held PERSON_NAME and VIN on the real corpus") — those two were this
// VIN and this job title, so the evidence for the row was itself a pair of false positives.
//
// A chart's authored text is its title and series labels, which are <a:t> runs; the numbers plotted
// are <c:v> entries duplicated from cells that are already read in the worksheet they live in. So
// this reads the former and not the latter, which keeps every one of #680's six parts covered while
// adding none of the cache.
//
// # Why <a:t> and attributes are enough for all six
//
// DrawingML's a:t is the text run element shared by every OOXML format, so it carries the PowerPoint
// comment body and the chart title alike. The three configuration-shaped parts hold their text in an
// attribute instead — ppt/tags in `val`, xl/tables and ppt/presentation.xml in `name` — and those come
// from labelBearingAttrs. Verified against a planted value in each of the six.
//
// Attributes are collected from the markup BEFORE tags are stripped, because stripping is what loses
// them. Runs are joined with newlines rather than spaces so a validator's line-oriented context does
// not run a chart title into an unrelated table heading — see the cross-line label leak, where a byte
// window spanning two unrelated values produced a finding belonging to neither.
func extractAuxiliaryPartText(file *zip.File) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	raw, err := readZipEntryLimited(rc)
	if err != nil {
		return "", err
	}
	xmlText := string(raw)

	var out strings.Builder
	seen := make(map[string]bool)
	addLine := func(s string) {
		s = strings.TrimSpace(decodeXMLEntities(s))
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out.WriteString(s)
		out.WriteString("\n")
	}

	// Label-bearing attribute values, read from the tags themselves and keyed by the element that
	// holds them — see labelBearingAttrs for why the element is part of the key.
	for _, tag := range xmlTagRe.FindAllString(xmlText, -1) {
		elem := elementName(tag)
		if elem == "" {
			continue
		}
		for _, m := range xmlAttrRe.FindAllStringSubmatch(tag, -1) {
			if labelBearingAttrs[elem+"|"+localName(m[1])] {
				addLine(m[2])
			}
		}
	}

	// DrawingML text runs: the authored text, whatever the schema around it.
	for _, m := range drawingTextRunRe.FindAllStringSubmatch(xmlText, -1) {
		addLine(xmlTagRe.ReplaceAllString(m[1], ""))
	}

	return out.String(), nil
}

// elementName returns the lowercased, namespace-stripped element name of a start or empty tag, or ""
// for a closing tag, comment, declaration or processing instruction — none of which carry attributes
// that mean anything here.
func elementName(tag string) string {
	t := strings.TrimPrefix(tag, "<")
	if t == "" || t[0] == '/' || t[0] == '!' || t[0] == '?' {
		return ""
	}
	end := strings.IndexAny(t, " \t\r\n/>")
	if end < 0 {
		end = len(t)
	}
	return localName(t[:end])
}

// localName lowercases a name and drops any namespace prefix, so a producer's choice of prefix
// cannot change whether an attribute is recognised.
func localName(n string) string {
	n = strings.ToLower(n)
	if i := strings.LastIndex(n, ":"); i >= 0 {
		return n[i+1:]
	}
	return n
}

// appendAuxiliaryParts appends the text of every auxiliary part not already consumed by the caller.
//
// alreadyRead holds the part names the format-specific pass extracted, compared case-insensitively —
// a producer's capital letter has previously dropped a whole body part. Dedup comes from that set
// rather than from a second list of body-part names, so the two can never drift apart.
func appendAuxiliaryParts(allText *strings.Builder, pkg *ooxmlPackage, alreadyRead map[string]bool) {
	for _, f := range pkg.files {
		if allText.Len() > MaxTotalTextBytes {
			return
		}
		if alreadyRead[strings.ToLower(f.Name)] {
			continue
		}
		if c, _ := classifyPart(f.Name); c != partIncluded {
			continue
		}
		text, err := extractAuxiliaryPartText(f)
		if err != nil || strings.TrimSpace(text) == "" {
			continue
		}
		allText.WriteString("\n\n--- " + f.Name + " ---\n")
		allText.WriteString(text)
	}
}

// markRead records the parts a format pass consumed, for appendAuxiliaryParts to skip.
func markRead(read map[string]bool, lists ...[]*zip.File) {
	for _, list := range lists {
		for _, f := range list {
			if f != nil {
				read[strings.ToLower(f.Name)] = true
			}
		}
	}
}
