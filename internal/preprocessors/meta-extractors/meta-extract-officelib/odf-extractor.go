// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
)

// ODF containers were admitted and then rejected, so their metadata was invisible at exit 0.
//
// `.odt`/`.ods`/`.odp` are in `officeExtensions`, so `IsOfficeFile` is true and the office metadata
// preprocessor CLAIMS them — then ExtractMetadata's format switch fell through to
// `unsupported file format: .odt`. The preprocessor returned that error, the router moved on to the
// text extractor, and the run reported only body text. Nothing said the metadata had been skipped:
// three layers each behaved reasonably and the value vanished between them (#498).
//
// Measured on real files rather than fixtures. Eight real `.docx` documents converted to `.odt` by
// LibreOffice on this host, plus LibreOffice's own shipped samples: **4 of the 5 that carry a
// dc:creator had an author name that never appeared in anything ferret extracted.** The fifth was
// only "visible" because that same name also occurs in the body text — content.xml, not meta.xml.
//
// Field inventory across 11 real ODF files, which is what this reads rather than what the spec
// permits:
//
//	meta:user-defined       15    arbitrary custom properties (the OOXML custom.xml analogue)
//	meta:generator          11
//	meta:creation-date       8
//	dc:creator               7    LAST MODIFIED BY — see the semantic note below
//	meta:template            7    an empty element carrying xlink:href — a filesystem path
//	meta:initial-creator     6    the ORIGINAL author
//	dc:title, dc:description, dc:language
//
// # dc:creator does NOT mean the same thing it means in OOXML
//
// This is the detail that would be silently wrong if the OOXML arm were copied. OOXML puts the
// original author in `dc:creator` and the last editor in `cp:lastModifiedBy`. ODF 1.2 §4.3.2
// inverts the first of those:
//
//	meta:initial-creator  "the name of the person who created the document initially"
//	dc:creator            "the name of the person who last modified the document"
//
// So `meta:initial-creator` maps to Creator/Author and `dc:creator` maps to LastModifiedBy. Mapping
// dc:creator to Author would label the last editor as the author on every ODF document — both are
// reported either way, so no value would be LOST, but every one of them would be attributed to the
// wrong person, which for a metadata finding is the whole content of the finding.

// odfDocumentMeta mirrors meta.xml.
//
// Decoded with encoding/xml's namespace-agnostic local-name matching, the same way CoreProperties
// handles docProps/core.xml: the field tags below are local names, so a writer's choice of namespace
// prefix cannot change what is read.
type odfDocumentMeta struct {
	Meta odfMeta `xml:"meta"`
}

// odfMeta is the office:meta element's children.
type odfMeta struct {
	// The two identity fields, whose ODF meanings are the inverse of the OOXML ones.
	InitialCreator string `xml:"initial-creator"`
	Creator        string `xml:"creator"`

	Title       string `xml:"title"`
	Subject     string `xml:"subject"`
	Description string `xml:"description"`
	Language    string `xml:"language"`

	// Repeatable in ODF — a document may carry several keyword elements rather than one
	// comma-joined string, so this must be a slice or all but the last would be dropped.
	Keywords []string `xml:"keyword"`

	CreationDate string `xml:"creation-date"`
	Date         string `xml:"date"`

	Generator       string `xml:"generator"`
	PrintedBy       string `xml:"printed-by"`
	PrintDate       string `xml:"print-date"`
	EditingCycles   string `xml:"editing-cycles"`
	EditingDuration string `xml:"editing-duration"`

	// Template is an EMPTY element whose content is in its xlink:href attribute, so it needs an
	// attr tag rather than chardata. It is a filesystem path, which the OOXML arm already treats as
	// high-risk — it leaks a user directory and often a person's name.
	Template odfTemplate `xml:"template"`

	// UserDefined is the ODF analogue of docProps/custom.xml: operator-chosen name/value pairs,
	// which in practice is where matter numbers, client names and case references end up.
	UserDefined []odfUserDefined `xml:"user-defined"`
}

// odfTemplate is meta:template, whose value lives in an attribute.
type odfTemplate struct {
	Href  string `xml:"href,attr"`
	Title string `xml:"title,attr"`
}

// odfUserDefined is one meta:user-defined property.
type odfUserDefined struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

// extractODFMetadata reads meta.xml out of an ODF container.
//
// Mirrors extractOfficeOpenXMLMetadata's shape deliberately — same ZIP open, same file index, same
// size-bounded read, same secureXMLUnmarshal — so the two paths cannot drift on XXE handling or on
// the MaxXMLSize bound. The values land in the same Metadata fields and the same Properties map, so
// the existing metadata validators, confidence boosts and the office_metadata section header all
// apply unchanged; nothing downstream needs to know ODF exists.
func extractODFMetadata(filePath string, metadata *Metadata) (*Metadata, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return metadata, newSanitizedError("error opening file as ZIP", err)
	}
	defer reader.Close()

	fileIndex := createFileIndex(reader)

	metaFile, exists := lookupPart(fileIndex, "meta.xml")
	if !exists {
		// A valid ODF package need not carry meta.xml (ODF 1.2 §2.2.3 makes it optional), and a
		// container with none has no metadata to lose. Returning the metadata built so far rather
		// than an error keeps the body-text path working, which is what the caller falls back to.
		return metadata, nil
	}

	odf, err := readODFMeta(metaFile)
	if err != nil {
		return metadata, err
	}

	applyODFMeta(odf, metadata)
	return metadata, nil
}

// readODFMeta opens, bounds and parses meta.xml.
func readODFMeta(metaFile *zip.File) (*odfMeta, error) {
	rc, err := metaFile.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	content, err := io.ReadAll(io.LimitReader(rc, MaxXMLSize))
	if err != nil {
		return nil, newSanitizedError("failed to read ODF metadata", err)
	}

	var doc odfDocumentMeta
	if err := secureXMLUnmarshal(content, &doc); err != nil {
		return nil, newSanitizedError("failed to parse ODF metadata XML", err)
	}
	return &doc.Meta, nil
}

// applyODFMeta copies the parsed fields onto Metadata.
//
// Separate from the read so it can be tested against a byte layout without a ZIP, and so the field
// mapping — the part with the ODF-versus-OOXML inversion in it — is readable in one place.
func applyODFMeta(odf *odfMeta, metadata *Metadata) {
	// The inversion. See the package comment: ODF's initial-creator is the author, and its
	// dc:creator is the last editor.
	metadata.Creator = strings.TrimSpace(odf.InitialCreator)
	metadata.Author = metadata.Creator
	metadata.LastModifiedBy = strings.TrimSpace(odf.Creator)

	// A document edited by one person and created by another yields both, which is the case worth
	// getting right. When only dc:creator is present — LibreOffice writes that alone on some
	// conversions, seen in 1 of 11 real files here — Author would otherwise be empty while a real
	// name sat in LastModifiedBy. Fill Author from it so the value is never unattributed, and keep
	// LastModifiedBy too so the report still says which field it came from.
	if metadata.Author == "" && metadata.LastModifiedBy != "" {
		metadata.Author = metadata.LastModifiedBy
		metadata.Creator = metadata.LastModifiedBy
	}

	metadata.Title = strings.TrimSpace(odf.Title)
	metadata.Subject = strings.TrimSpace(odf.Subject)
	metadata.Description = strings.TrimSpace(odf.Description)
	metadata.Language = strings.TrimSpace(odf.Language)
	metadata.Keywords = joinODFKeywords(odf.Keywords)
	metadata.Application = strings.TrimSpace(odf.Generator)
	metadata.Revision = strings.TrimSpace(odf.EditingCycles)
	metadata.TotalEditTime = strings.TrimSpace(odf.EditingDuration)

	if odf.CreationDate != "" {
		if t, err := parseOfficeDate(odf.CreationDate); err == nil {
			metadata.Created = t
		}
	}
	if odf.Date != "" {
		if t, err := parseOfficeDate(odf.Date); err == nil {
			metadata.Modified = t
		}
	}

	// Template is a path, and the OOXML arm already records it under this exact key so the
	// downstream TEMPLATE_INFO treatment is shared rather than duplicated.
	if href := strings.TrimSpace(odf.Template.Href); href != "" {
		metadata.Template = href
		metadata.Properties["Template"] = href
	}
	if title := strings.TrimSpace(odf.Template.Title); title != "" {
		metadata.Properties["TemplateTitle"] = title
	}
	if by := strings.TrimSpace(odf.PrintedBy); by != "" {
		metadata.Properties["PrintedBy"] = by
	}
	if d := strings.TrimSpace(odf.PrintDate); d != "" {
		metadata.Properties["PrintDate"] = d
	}

	applyODFUserDefined(odf.UserDefined, metadata)
}

// joinODFKeywords collapses repeatable meta:keyword elements into the one string Metadata carries.
//
// Comma-joined to match what the OOXML arm does with its keywords slice, so a consumer sees one
// shape for both container families.
func joinODFKeywords(keywords []string) string {
	kept := make([]string, 0, len(keywords))
	for _, k := range keywords {
		if k = strings.TrimSpace(k); k != "" {
			kept = append(kept, k)
		}
	}
	return strings.Join(kept, ", ")
}

// applyODFUserDefined records meta:user-defined pairs.
//
// A name is attacker-controlled, so it is never used as a bare Properties key: an entry named
// "Template" or "Author" would otherwise overwrite a real field read above, which is a way to hide a
// value from the report by choosing its name. Prefixed instead, which also tells a reader that the
// name came from the document rather than from the extractor.
//
// An unnamed entry keeps its value under a positional key rather than being dropped — the value is
// what the validators scan, and the name is only a label.
func applyODFUserDefined(entries []odfUserDefined, metadata *Metadata) {
	for i, e := range entries {
		value := strings.TrimSpace(e.Value)
		if value == "" {
			continue
		}
		name := strings.TrimSpace(e.Name)
		if name == "" {
			name = fmt.Sprintf("%d", i+1)
		}
		metadata.Properties["ODFUserDefined_"+name] = value
	}
}
