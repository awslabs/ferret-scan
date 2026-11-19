// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

import "strings"

// Labels: every row of this validator is tier B (#884 Part B, B2). A value is reported only when a
// label for ITS type sits immediately before it on the same line, separated by filler alone. A shape
// with a valid check digit and no label is not reported: the checks pass roughly 1 random value in
// 10 (the RUT, CUIL and SIN) to 1 in 100 (the CPF), which is no evidence on its own.
//
// shortcut: the label must be on the value's line, before it. A label heading the value's column or
// standing on the line above is not read; add it (as vin/labels.go does) when a tabular layout is
// measured.

// label is one spelling that names an identifier.
type label struct {
	// text is the label folded (lower-case, accents removed; see fold).
	text string
	// abbr marks an acronym (CPF, SIN, RUN, ...). An acronym is a common word or acronym in another
	// sense often enough ("sin" is Spanish for "without", "run" is an English verb, "NAS" is network
	// storage) that it counts only when written in capitals, or when a colon, '=', '#' or an ordinal
	// sign (nº, n°) separates it from the value.
	abbr bool
	// strict marks an acronym that counts ONLY with such a separator: "NAS" is written in capitals
	// in English too ("backup to the NAS" before a 3-3-3 number).
	strict bool
}

// labelsByType holds each type's labels, long forms with their accented spellings folded.
var labelsByType = map[string][]label{
	TypeBRCPF: {
		{text: "cpf", abbr: true},
		{text: "cadastro de pessoas fisicas"},
		{text: "cadastro de pessoa fisica"},
	},
	TypeCLRUT: {
		{text: "rut", abbr: true},
		{text: "run", abbr: true},
		{text: "rol unico tributario"},
		{text: "rol unico nacional"},
	},
	TypeARCUIL: {
		{text: "cuil", abbr: true},
		{text: "cuit", abbr: true},
		{text: "codigo unico de identificacion laboral"},
		{text: "clave unica de identificacion tributaria"},
	},
	TypeCASIN: {
		{text: "sin", abbr: true},
		{text: "nas", abbr: true, strict: true},
		{text: "social insurance number"},
		{text: "social insurance no"},
		{text: "numero d'assurance sociale"},
		{text: "no d'assurance sociale"},
	},
	TypeMXCURP: {
		{text: "curp", abbr: true},
		{text: "clave unica de registro de poblacion"},
	},
	TypeMXRFC: {
		{text: "rfc", abbr: true},
		{text: "registro federal de contribuyentes"},
	},
}

// anyLabelText is every label's folded text, for the per-line prefilter.
var anyLabelText = func() []string {
	var out []string
	for _, t := range Types {
		for _, l := range labelsByType[t] {
			out = append(out, l.text)
		}
	}
	return out
}()

// folder lower-cases what strings.ToLower leaves accented and maps the typographic apostrophe.
var folder = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a", "ä", "a",
	"é", "e", "ê", "e", "è", "e", "ë", "e",
	"í", "i", "î", "i", "ï", "i",
	"ó", "o", "ô", "o", "õ", "o", "ö", "o",
	"ú", "u", "ü", "u", "û", "u",
	"ç", "c", "ñ", "n",
	"\u2019", "'", "\u02bc", "'",
)

// fold returns s lower-cased with the accents Portuguese, Spanish and French labels carry removed.
// It is applied to a short label window only; no offset into it is mapped back to the line.
func fold(s string) string {
	return folder.Replace(strings.ToLower(s))
}

// lineMayHaveLabel is the per-line prefilter: whether any label's text occurs anywhere in the folded
// line. It is a superset of what labelBefore accepts, so a false here skips every regex for the line.
func lineMayHaveLabel(folded string) bool {
	for _, t := range anyLabelText {
		if strings.Contains(folded, t) {
			return true
		}
	}
	return false
}

// fillerWords may stand between a label and its value (#1021): the abbreviations of "number" (nº, n°,
// no., nro., núm., número, number) and the copula of "Our Social Insurance Number is ..." (is, es). At
// most maxFillerWords of them, so "SIN number is: 123" reads and a sentence does not. Folded; the
// Portuguese "é" is matched on its accented spelling (isFillerWord), because folded it is "e", "and".
// "Número do CPF: …" needs none, since its label is last.
var fillerWords = []string{"nº", "n°", "no", "nro", "num", "numero", "n", "number", "is", "es"}

// maxFillerWords is how many filler words may stand between the label and the value.
const maxFillerWords = 2

func isFillerWord(raw string) bool {
	if strings.ToLower(raw) == "é" {
		return true
	}
	word := fold(raw)
	for _, f := range fillerWords {
		if word == f {
			return true
		}
	}
	return false
}

// maxLabelWindow bounds how far before the value the label may start, in bytes.
const maxLabelWindow = 96

func isFillerByte(c byte) bool {
	switch c {
	case ' ', '\t', ':', '#', '=', '-', '.', ',', ';', '|', '(', ')', '[', ']', '"', '\'', '*', '_', '/':
		return true
	}
	return false
}

// strongSeparator reports whether the gap between label and value says "this is the value of that
// label" in itself: a colon, '=', '#', or an ordinal sign.
func strongSeparator(gap string) bool {
	return strings.ContainsAny(gap, ":=#") || strings.Contains(gap, "º") || strings.Contains(gap, "°")
}

func isWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c >= 0x80
}

// labelBefore reports which of the type's labels sits immediately before line[start:], with only
// filler between, and returns it with that filler. ok is false when none does.
func labelBefore(line string, start int, dataType string) (l label, gap string, ok bool) {
	from := start - maxLabelWindow
	if from < 0 {
		from = 0
	}
	// Align to a rune start so a multi-byte character is never split.
	for from > 0 && from < start && line[from]&0xC0 == 0x80 {
		from++
	}
	prefix := line[from:start]

	// Try the label as written, then with one filler word stripped, then two: "Social Insurance
	// Number: 123" ends in a filler word of its own, so the label is tried before each strip.
	end := len(prefix)
	for words := 0; ; words++ {
		for end > 0 && isFillerByte(prefix[end-1]) {
			end--
		}
		if l, ok := labelEndingAt(prefix[:end], prefix[end:], dataType); ok {
			return l, prefix[end:], true
		}
		w := end
		for w > 0 && isWordByte(prefix[w-1]) {
			w--
		}
		if words == maxFillerWords || w == end || !isFillerWord(prefix[w:end]) {
			break
		}
		end = w
	}
	return label{}, "", false
}

// labelEndingAt reports which of the type's labels ends head, the text before the value up to its
// last non-filler byte; gap is the filler between them.
func labelEndingAt(head, gap, dataType string) (label, bool) {
	headFolded := fold(head)
	for _, l := range labelsByType[dataType] {
		if !strings.HasSuffix(headFolded, l.text) {
			continue
		}
		before := len(headFolded) - len(l.text)
		if before > 0 && isWordByte(headFolded[before-1]) {
			continue // the label is the tail of a longer word ("pasin")
		}
		if l.abbr {
			strong := strongSeparator(gap)
			if l.strict && !strong {
				continue
			}
			// The acronym as written is the last len(text) bytes of head when those bytes are ASCII.
			written := head[len(head)-len(l.text):]
			if strings.ToLower(written) != l.text {
				continue // an accented spelling folded onto the acronym ("sín")
			}
			if !strong && written != strings.ToUpper(written) {
				continue
			}
		}
		return l, true
	}
	return label{}, false
}
