// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The generator for iban_registry.go and iban_registry_examples_test.go, and the drift check
// against a fresh download. It lives in a test so it needs no extra package or binary, and so the
// parser is exercised by the same toolchain that compiles the table it writes.
//
// The SWIFT IBAN Registry is published as a tab-separated TXT: one row per data element, the
// element's name in the first column and one column per country, with CRLF line endings and
// quoted cells that may span lines (the contact addresses). Only the rows below are read.
const (
	ibanRegistryTXTEnv      = "IBAN_REGISTRY_TXT"
	ibanRegistryUpdateEnv   = "UPDATE_IBAN_REGISTRY"
	ibanRegistryReadDateEnv = "IBAN_REGISTRY_READ_DATE"
	ibanRegistrySourceURL   = "https://www.swift.com/swift-resource/11971/download"

	rowCountryCode     = "IBAN prefix country code (ISO 3166)"
	rowBBANStructure   = "BBAN structure"
	rowBBANLength      = "BBAN length"
	rowIBANStructure   = "IBAN structure"
	rowIBANLength      = "IBAN length"
	rowElectronicIBAN  = "IBAN electronic format example"
	rowLastUpdateDate  = "Last update date"
	generatedTableFile = "iban_registry.go"
	generatedExamples  = "iban_registry_examples_test.go"
)

// registryEntry is one country column of the download, after every cross-check passed.
type registryEntry struct {
	code      string
	length    int
	structure string // the BBAN structure row, verbatim
	example   string // the electronic-format example IBAN
}

var reTwoLetterCode = regexp.MustCompile(`^[A-Z]{2}$`)

// parseIBANRegistryTXT reads the download and returns its entries sorted by code, plus the newest
// "Last update date" it carries (the download has no release number, so this is what the
// generated header records). Every entry is cross-checked three ways before it is accepted: the
// BBAN structure row and the IBAN structure row must describe the same per-position layout, both
// length rows must equal that layout's size, and the registry's own example IBAN must have that
// length, that layout and a valid mod-97 checksum. A download that fails any of them is refused:
// a table generated from it would reject real IBANs, which is a leak, not a cosmetic defect.
func parseIBANRegistryTXT(data []byte) ([]registryEntry, string, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.Comma = '\t'
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, "", fmt.Errorf("parse registry TXT: %w", err)
	}
	rows := map[string][]string{}
	for _, rec := range records {
		if len(rec) == 0 {
			continue
		}
		label := strings.TrimSpace(rec[0])
		if _, seen := rows[label]; seen {
			continue // first occurrence wins; the rows read here are unique in the registry
		}
		vals := make([]string, len(rec)-1)
		for i, v := range rec[1:] {
			vals[i] = strings.TrimSpace(v)
		}
		rows[label] = vals
	}
	need := []string{rowCountryCode, rowBBANStructure, rowBBANLength, rowIBANStructure, rowIBANLength, rowElectronicIBAN}
	for _, label := range need {
		if _, ok := rows[label]; !ok {
			return nil, "", fmt.Errorf("registry TXT has no %q row; is this the SWIFT IBAN Registry download?", label)
		}
	}
	codes := rows[rowCountryCode]
	// Trailing empty cells are the only ones tolerated past the last country.
	for len(codes) > 0 && codes[len(codes)-1] == "" {
		codes = codes[:len(codes)-1]
	}
	if len(codes) == 0 {
		return nil, "", fmt.Errorf("registry TXT lists no country codes")
	}
	for _, label := range need[1:] {
		if len(rows[label]) < len(codes) {
			return nil, "", fmt.Errorf("row %q has %d cells for %d countries", label, len(rows[label]), len(codes))
		}
	}

	seen := map[string]bool{}
	var entries []registryEntry
	var problems []string
	for i, code := range codes {
		bad := func(format string, args ...any) {
			problems = append(problems, code+": "+fmt.Sprintf(format, args...))
		}
		if !reTwoLetterCode.MatchString(code) {
			bad("not a two-letter country code")
			continue
		}
		if seen[code] {
			bad("listed twice")
			continue
		}
		seen[code] = true

		bban := rows[rowBBANStructure][i]
		layout, err := expandBBANStructure(bban)
		if err != nil {
			bad("%v", err)
			continue
		}
		ibanStructure := rows[rowIBANStructure][i]
		prefix := code + "2!n"
		if !strings.HasPrefix(ibanStructure, prefix) {
			bad("IBAN structure %q does not start with %q", ibanStructure, prefix)
			continue
		}
		ibanLayout, err := expandBBANStructure(ibanStructure[len(prefix):])
		if err != nil {
			bad("IBAN structure: %v", err)
			continue
		}
		if ibanLayout != layout {
			bad("BBAN structure %q and IBAN structure %q disagree", bban, ibanStructure)
			continue
		}
		ibanLen, err1 := strconv.Atoi(rows[rowIBANLength][i])
		bbanLen, err2 := strconv.Atoi(rows[rowBBANLength][i])
		if err1 != nil || err2 != nil || ibanLen != 4+len(layout) || bbanLen != len(layout) {
			bad("lengths IBAN %q / BBAN %q do not match structure %q (%d)", rows[rowIBANLength][i], rows[rowBBANLength][i], bban, len(layout))
			continue
		}
		example := strings.ReplaceAll(rows[rowElectronicIBAN][i], " ", "")
		if len(example) != ibanLen || example[:2] != code || !bbanConforms(example[4:], layout) || !ibanChecksumValid(example) {
			bad("example %q does not fit its own entry (length %d, structure %q, mod-97)", example, ibanLen, bban)
			continue
		}
		entries = append(entries, registryEntry{code: code, length: ibanLen, structure: bban, example: example})
	}
	if len(problems) > 0 {
		return nil, "", fmt.Errorf("registry TXT refused, %d entries inconsistent:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].code < entries[b].code })

	newest := ""
	var newestT time.Time
	for _, v := range rows[rowLastUpdateDate] {
		if t, err := time.Parse("Jan-06", v); err == nil && t.After(newestT) {
			newestT, newest = t, v
		}
	}
	return entries, newest, nil
}

// renderIBANRegistry writes iban_registry.go for entries. readDate and newest go into the header.
func renderIBANRegistry(entries []registryEntry, readDate, newest string) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

// ibanRegistry is the SWIFT IBAN Registry: the IBAN length and BBAN structure of every country
// with a registered national IBAN format. isValidIBAN and the display-form scan read only this
// table, so a country missing here is an IBAN never reported, and never redacted.
//
// GENERATED DATA, not hand-maintained. Regenerate it, and check it for drift, from the registry's
// TXT download (swift.com/standards/data-standards/iban-international-bank-account-number):
//
//	IBAN_REGISTRY_TXT=/path/to/iban-registry.txt UPDATE_IBAN_REGISTRY=1 \
//	    go test ./internal/validators/bankaccount/ -run TestIBANRegistryMatchesDownload
//
// Without UPDATE_IBAN_REGISTRY the same command fails on any added, removed or changed entry, and
// without IBAN_REGISTRY_TXT it skips. The download carries no release number, so what was read is
// recorded instead:
//
`)
	fmt.Fprintf(&b, "//\tread %s from %s\n", readDate, ibanRegistrySourceURL)
	fmt.Fprintf(&b, "//\t%d entries; newest \"Last update date\" in the download: %s\n", len(entries), newest)
	b.WriteString(`//
// Only code, length and structure are copied. The registry's examples are kept for the tests in
// iban_registry_examples_test.go; its contact details are not copied at all.
//
// # Why generated
//
// The map this replaced was hand-written, labelled a "subset", and had no source or refresh path.
// It held 74 of the registry's 89 entries, so an IBAN from Egypt, Russia, Oman, Somalia or any of
// eleven other registered countries was never reported in any form (#862). Its 74 lengths were
// right; it was the missing rows nobody could see, because nothing compared it with the registry.
var ibanRegistry = map[string]ibanFormat{
`)
	for _, e := range entries {
		fmt.Fprintf(&b, "\t%q: {length: %d, structure: %q},\n", e.code, e.length, e.structure)
	}
	b.WriteString("}\n\n")
	b.WriteString(`// ibanRegistryEntries is the number of entries the generator wrote. TestIBANRegistryCompiles
// requires ibanRegistry to hold exactly this many, so a hand edit that adds or drops a country,
// instead of regenerating, fails.
`)
	fmt.Fprintf(&b, "const ibanRegistryEntries = %d\n", len(entries))
	return format.Source([]byte(b.String()))
}

// renderIBANRegistryExamples writes iban_registry_examples_test.go for entries.
func renderIBANRegistryExamples(entries []registryEntry, readDate string) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

// ibanRegistryExamples is each registry entry's own "IBAN electronic format example": published
// specimens, not accounts. They are the positive control for iban_registry.go, since a structure
// or length that rejected the registry's own example would reject real IBANs of that country.
//
// GENERATED DATA, written together with iban_registry.go by TestIBANRegistryMatchesDownload.
`)
	fmt.Fprintf(&b, "// Read %s from %s.\n", readDate, ibanRegistrySourceURL)
	b.WriteString("var ibanRegistryExamples = map[string]string{\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "\t%q: %q,\n", e.code, e.example)
	}
	b.WriteString("}\n")
	return format.Source([]byte(b.String()))
}

var reRecordedReadDate = regexp.MustCompile(`(?m)^//\tread (\d{4}-\d{2}-\d{2}) from `)

// TestIBANRegistryMatchesDownload is the generator and the drift check. It needs the registry's
// TXT download, so without IBAN_REGISTRY_TXT it skips: an offline run must not fail on an
// external registry it cannot read.
func TestIBANRegistryMatchesDownload(t *testing.T) {
	path := os.Getenv(ibanRegistryTXTEnv)
	if path == "" {
		t.Skipf("set %s to the SWIFT IBAN Registry TXT (%s) to check iban_registry.go against it; "+
			"add %s=1 to regenerate", ibanRegistryTXTEnv, ibanRegistrySourceURL, ibanRegistryUpdateEnv)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a path the developer passed in on purpose
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	entries, newest, err := parseIBANRegistryTXT(data)
	if err != nil {
		t.Fatal(err)
	}

	if os.Getenv(ibanRegistryUpdateEnv) == "1" {
		readDate := os.Getenv(ibanRegistryReadDateEnv)
		if readDate == "" {
			readDate = time.Now().UTC().Format("2006-01-02")
		}
		table, err := renderIBANRegistry(entries, readDate, newest)
		if err != nil {
			t.Fatalf("render %s: %v", generatedTableFile, err)
		}
		examples, err := renderIBANRegistryExamples(entries, readDate)
		if err != nil {
			t.Fatalf("render %s: %v", generatedExamples, err)
		}
		if err := os.WriteFile(generatedTableFile, table, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(generatedExamples, examples, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s and %s: %d entries, newest update %s", generatedTableFile, generatedExamples, len(entries), newest)
		return
	}

	// Drift check: the entries, not the header, decide. "Last update date" also moves when only a
	// registrant's contact details change, which is no reason to fail.
	var drift []string
	inDownload := map[string]bool{}
	for _, e := range entries {
		inDownload[e.code] = true
		got, ok := ibanRegistry[e.code]
		switch {
		case !ok:
			drift = append(drift, fmt.Sprintf("+ %s length %d structure %s (not in iban_registry.go)", e.code, e.length, e.structure))
		case got.length != e.length || got.structure != e.structure:
			drift = append(drift, fmt.Sprintf("~ %s length %d structure %s (iban_registry.go: %d %s)", e.code, e.length, e.structure, got.length, got.structure))
		}
		if ex, ok := ibanRegistryExamples[e.code]; ok && ex != e.example {
			drift = append(drift, fmt.Sprintf("~ %s example %s (iban_registry_examples_test.go: %s)", e.code, e.example, ex))
		}
	}
	for code := range ibanRegistry {
		if !inDownload[code] {
			drift = append(drift, fmt.Sprintf("- %s (in iban_registry.go, not in the download)", code))
		}
	}
	sort.Strings(drift)
	if len(drift) > 0 {
		t.Fatalf("iban_registry.go has drifted from %s (%d entries, newest update %s):\n  %s\nregenerate with %s=1",
			path, len(entries), newest, strings.Join(drift, "\n  "), ibanRegistryUpdateEnv)
	}
	src, _ := os.ReadFile(generatedTableFile)
	recorded := "unknown"
	if m := reRecordedReadDate.FindSubmatch(src); m != nil {
		recorded = string(m[1])
	}
	t.Logf("iban_registry.go (read %s) matches the download: %d entries, newest update %s", recorded, len(entries), newest)
}

// TestIBANRegistryParserReadsTheDownloadLayout: the real TXT has CRLF line endings, quoted cells
// that span lines (the contact addresses), Windows-1252 bytes in names, rows the parser does not
// read, and cells padded with spaces. None of that may shift a column.
func TestIBANRegistryParserReadsTheDownloadLayout(t *testing.T) {
	txt := "Data element\tDescription - Pattern - Example\tDescription - Pattern - Example\r\n" +
		"Name of country\tMalta\tNorway\r\n" +
		rowCountryCode + "\tMT\tNO\r\n" +
		"BBAN\r\n" +
		rowBBANStructure + "\t4!a5!n18!c \t4!n6!n1!n\r\n" +
		rowBBANLength + "\t27\t11\r\n" +
		"IBAN\r\n" +
		rowIBANStructure + "\tMT2!n4!a5!n18!c\tNO2!n4!n6!n1!n\r\n" +
		rowIBANLength + "\t31\t15\r\n" +
		rowElectronicIBAN + "\tMT84MALT011000012345MTLCAST001S\tNO9386011117947\r\n" +
		"Street Address\t\"48/2 Birkirkara Road\r\nAttard\"\t\"P.O Box 7100\r\nBergen\"\r\n" +
		"Organisation\tMalta Bankers\x92 Association\tDnB NOR Bank\r\n" +
		rowLastUpdateDate + "\tOct-25\tAug-09\r\n"
	entries, newest, err := parseIBANRegistryTXT([]byte(txt))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 2 || entries[0].code != "MT" || entries[0].structure != "4!a5!n18!c" || entries[1].length != 15 {
		t.Fatalf("parsed %+v", entries)
	}
	if newest != "Oct-25" {
		t.Errorf("newest update %q, want Oct-25", newest)
	}
}

// TestIBANRegistryParserRefusesAnInconsistentDownload pins the cross-checks: a download whose
// rows disagree must not produce a table.
func TestIBANRegistryParserRefusesAnInconsistentDownload(t *testing.T) {
	row := func(label string, vals ...string) string { return label + "\t" + strings.Join(vals, "\t") + "\r\n" }
	good := []string{
		row("Name of country", "Germany", "Norway"),
		row(rowCountryCode, "DE", "NO"),
		row(rowBBANStructure, "8!n10!n", "4!n6!n1!n"),
		row(rowBBANLength, "18", "11"),
		row(rowIBANStructure, "DE2!n8!n10!n", "NO2!n4!n6!n1!n"),
		row(rowIBANLength, "22", "15"),
		row(rowElectronicIBAN, "DE89370400440532013000", "NO9386011117947"),
		row(rowLastUpdateDate, "Jan-11", "Aug-09"),
	}
	entries, newest, err := parseIBANRegistryTXT([]byte(strings.Join(good, "")))
	if err != nil {
		t.Fatalf("a consistent two-country download was refused: %v", err)
	}
	if len(entries) != 2 || entries[0].code != "DE" || entries[1].length != 15 || newest != "Jan-11" {
		t.Fatalf("parsed %+v newest %q", entries, newest)
	}

	// mutate replaces rows by index, so each case breaks exactly the cross-check it names.
	mutate := func(repl map[int]string) string {
		rows := append([]string(nil), good...)
		for i, r := range repl {
			rows[i] = r
		}
		return strings.Join(rows, "")
	}
	for name, txt := range map[string]string{
		"structure rows disagree": mutate(map[int]string{4: row(rowIBANStructure, "DE2!n8!n9!n1!a", "NO2!n4!n6!n1!n")}),
		"IBAN length disagrees":   mutate(map[int]string{5: row(rowIBANLength, "23", "15")}),
		"BBAN length disagrees":   mutate(map[int]string{3: row(rowBBANLength, "18", "12")}),
		"example fails mod-97":    mutate(map[int]string{6: row(rowElectronicIBAN, "DE88370400440532013000", "NO9386011117947")}),
		"example breaks structure": mutate(map[int]string{
			2: row(rowBBANStructure, "8!a10!n", "4!n6!n1!n"),
			4: row(rowIBANStructure, "DE2!n8!a10!n", "NO2!n4!n6!n1!n"),
		}),
		"unknown class":     mutate(map[int]string{2: row(rowBBANStructure, "8!e10!n", "4!n6!n1!n")}),
		"code listed twice": mutate(map[int]string{1: row(rowCountryCode, "DE", "DE")}),
		"row missing":       strings.Join(append(append([]string(nil), good[:6]...), good[7]), ""),
	} {
		if _, _, err := parseIBANRegistryTXT([]byte(txt)); err == nil {
			t.Errorf("%s: parser accepted it", name)
		}
	}
}
