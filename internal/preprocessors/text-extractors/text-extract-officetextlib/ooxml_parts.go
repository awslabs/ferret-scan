// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Part selection for OOXML containers.
//
// This file exists because the extractors used to pick parts by hardcoded,
// case-SENSITIVE literal names ("word/document.xml", "xl/sharedStrings.xml",
// prefix "ppt/slides/slide"). A zip entry name is producer-controlled data, and
// nothing in the OOXML specification makes those literals normative — the package
// relationships do. So one capital letter defeated extraction entirely: measured
// with a prebuilt binary, renaming word/document.xml to word/Document.xml took a
// .docx from 4 findings {SSN, VISA, AUTHOR_INFO, LAST_MODIFIED_BY} to 2
// (metadata only). The SSN and the card number never entered the extracted text,
// so no validator could see them and — since only reported findings are redacted
// — they passed through --enable-redaction in cleartext. Renaming the part to
// word/main.xml did the same. No routing or validator change can reach this: the
// bytes are simply absent from what gets scanned.
//
// Selection is therefore done two ways and the results are UNIONED:
//
//  1. Through the package relationships (_rels/.rels and the part-level .rels),
//     which is how the format actually specifies which part is the document, the
//     workbook, a worksheet, a slide. This is authoritative and case-exact.
//  2. Through the conventional names, matched case-INSENSITIVELY, as a fallback
//     for a package whose relationships are missing, malformed, or deliberately
//     point elsewhere.
//
// The union is the point. Taking only (1) would LOSE content today's code finds:
// a package whose .rels points at word/evil.xml while word/document.xml also
// carries PII would have that second part dropped, and unreferenced parts are
// still bytes sitting in the file. Taking only (2) is the bug being fixed.
// Scanning both can only add text, never remove it, so a conventional document —
// where both routes name the same single part and dedup collapses them — extracts
// byte-identically to before.

// ooxmlPackage indexes an opened OOXML archive so parts can be found without
// relying on the producer's choice of letter case, and so relationships can be
// followed.
type ooxmlPackage struct {
	files   []*zip.File
	byLower map[string]*zip.File
}

func newOOXMLPackage(files []*zip.File) *ooxmlPackage {
	p := &ooxmlPackage{files: files, byLower: make(map[string]*zip.File, len(files))}
	for _, f := range files {
		key := strings.ToLower(f.Name)
		// First writer wins, so a package carrying both "word/document.xml" and
		// "word/Document.xml" resolves deterministically to the earlier entry
		// rather than to whichever the map happened to see last.
		if _, seen := p.byLower[key]; !seen {
			p.byLower[key] = f
		}
	}
	return p
}

// lookup finds a part by name, ignoring case.
func (p *ooxmlPackage) lookup(name string) *zip.File {
	return p.byLower[strings.ToLower(name)]
}

// matching returns every part whose name has the given prefix and suffix,
// compared case-insensitively, in archive order.
func (p *ooxmlPackage) matching(prefix, suffix string) []*zip.File {
	var out []*zip.File
	lp, ls := strings.ToLower(prefix), strings.ToLower(suffix)
	for _, f := range p.files {
		ln := strings.ToLower(f.Name)
		if strings.HasPrefix(ln, lp) && strings.HasSuffix(ln, ls) {
			out = append(out, f)
		}
	}
	return out
}

var (
	// relElemRe isolates each <Relationship .../> element; relAttrRe then pulls its
	// attributes, so Type/Target/TargetMode order does not matter.
	relElemRe = regexp.MustCompile(`(?s)<Relationship\b[^>]*>`)
	relAttrRe = regexp.MustCompile(`([A-Za-z:]+)\s*=\s*"([^"]*)"`)
)

// relsPartFor returns the name of the .rels part describing ownerPart's
// relationships. The package-level relationships (ownerPart "") live in
// "_rels/.rels"; a part's live alongside it under "_rels/<base>.rels".
func relsPartFor(ownerPart string) string {
	if ownerPart == "" {
		return "_rels/.rels"
	}
	dir, base := path.Split(ownerPart)
	return dir + "_rels/" + base + ".rels"
}

// resolveTarget turns a relationship Target into a package part name. Targets are
// relative to the owning part's directory unless they begin with "/", in which
// case they are already package-absolute.
func resolveTarget(ownerPart, target string) string {
	if target == "" {
		return ""
	}
	if strings.HasPrefix(target, "/") {
		return strings.TrimPrefix(path.Clean(target), "/")
	}
	dir, _ := path.Split(ownerPart)
	// path.Join cleans as it joins, which is what resolves a leading "../".
	return strings.TrimPrefix(path.Join(dir, target), "/")
}

// relatedParts returns the parts reachable from ownerPart by a relationship whose
// Type ends in "/"+relType (e.g. "officeDocument", "worksheet", "slide"). Targets
// that do not resolve to a part in this archive, and external targets, are
// skipped — a relationship is a claim about the package, not a guarantee.
func (p *ooxmlPackage) relatedParts(ownerPart, relType string) []*zip.File {
	relsFile := p.lookup(relsPartFor(ownerPart))
	if relsFile == nil {
		return nil
	}

	rc, err := relsFile.Open()
	if err != nil {
		return nil
	}
	data, err := readZipEntryLimited(rc)
	rc.Close()
	if err != nil {
		return nil
	}

	wantSuffix := "/" + strings.ToLower(relType)

	var out []*zip.File
	for _, elem := range relElemRe.FindAll(data, -1) {
		var relTypeAttr, target string
		external := false
		for _, attr := range relAttrRe.FindAllSubmatch(elem, -1) {
			switch strings.ToLower(string(attr[1])) {
			case "type":
				relTypeAttr = string(attr[2])
			case "target":
				target = string(attr[2])
			case "targetmode":
				external = strings.EqualFold(string(attr[2]), "External")
			}
		}
		if external || !strings.HasSuffix(strings.ToLower(relTypeAttr), wantSuffix) {
			continue
		}
		if f := p.lookup(resolveTarget(ownerPart, target)); f != nil {
			out = append(out, f)
		}
	}
	return out
}

// unionParts concatenates part lists, keeping the first occurrence of each part
// and preserving the order given. Relationship-resolved parts are passed first so
// the authoritative ordering leads.
func unionParts(lists ...[]*zip.File) []*zip.File {
	var out []*zip.File
	seen := make(map[string]bool)
	for _, list := range lists {
		for _, f := range list {
			if f == nil || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			out = append(out, f)
		}
	}
	return out
}

// trimPartLabel strips a directory prefix and the ".xml" suffix from a part name
// case-insensitively, yielding the section label the extractor emits (e.g.
// "xl/Worksheets/sheet1.xml" -> "sheet1"). A case-sensitive strings.TrimPrefix
// left the whole path in the label whenever the producer capitalized the
// directory.
func trimPartLabel(name, prefix string) string {
	if len(name) >= len(prefix) && strings.EqualFold(name[:len(prefix)], prefix) {
		name = name[len(prefix):]
	}
	if strings.HasSuffix(strings.ToLower(name), ".xml") {
		name = name[:len(name)-len(".xml")]
	}
	return name
}

// externalRelationshipTargets returns every EXTERNAL relationship target in the package, in
// deterministic order.
//
// relatedParts deliberately skips external relationships, and rightly so — its job is to resolve a
// relationship to a PART inside the zip, and an external one points outside it. But the target itself
// is content: a hyperlink is stored as
//
//	<Relationship Id="rId7" Type=".../hyperlink" Target="mailto:someone@example.org"
//	              TargetMode="External"/>
//
// so an address or an internal URL a user linked lives only in a *.rels part, as an ATTRIBUTE, and was
// therefore read by nothing. Measured: an identifier planted in a hyperlink target was absent from
// --preprocess-only output, reported by no validator, and written to the "redacted" copy in cleartext
// at exit 0 (#670). Every one of 330 real .docx sampled contains word/_rels/document.xml.rels, so this
// is not a corner of the format.
//
// Targets only, never Id or Type: those are producer-generated identifiers with no user content, and
// emitting them would add noise to every scan for no recall.
//
// Deduplicated, because the same address is commonly linked from several places and a reader does not
// benefit from seeing it once per link. Sorted for reproducibility — this text reaches findings, and a
// map iteration order would make line numbers move between runs.
func (p *ooxmlPackage) externalRelationshipTargets() []string {
	seen := make(map[string]struct{})
	for _, f := range p.files {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".rels") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := readZipEntryLimited(rc)
		rc.Close()
		if err != nil {
			continue
		}
		for _, elem := range relElemRe.FindAllString(string(data), -1) {
			var target string
			external := false
			for _, attr := range relAttrRe.FindAllStringSubmatch(elem, -1) {
				switch strings.ToLower(attr[1]) {
				case "target":
					target = attr[2]
				case "targetmode":
					external = strings.EqualFold(attr[2], "External")
				}
			}
			if !external || target == "" {
				continue
			}
			seen[decodeXMLEntities(target)] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
