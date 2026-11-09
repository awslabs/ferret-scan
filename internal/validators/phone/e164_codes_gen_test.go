// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
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

// The generator for e164_codes.go, and the drift check against a fresh copy of its source. It lives
// in a test, as bankaccount's IBAN registry generator does, so it needs no extra package or binary
// and the parser is exercised by the toolchain that compiles the table it writes.
//
// The source is libphonenumber's PhoneNumberMetadata.xml (Apache-2.0): one <territory> per region,
// carrying its countryCode, its nationalPrefix and, per number type, the national lengths a number
// of that type may have. Only those three facts are copied.
const (
	e164MetadataXMLEnv      = "E164_METADATA_XML"
	e164MetadataUpdateEnv   = "UPDATE_E164_CODES"
	e164MetadataReadDateEnv = "E164_METADATA_READ_DATE"
	e164MetadataSourceEnv   = "E164_METADATA_SOURCE"
	e164MetadataDefaultURL  = "https://raw.githubusercontent.com/google/libphonenumber/v9.0.43/resources/PhoneNumberMetadata.xml"
	e164GeneratedFile       = "e164_codes.go"
)

// e164NumberTypes are the number-type elements whose possible lengths make up a code's national
// lengths. noInternationalDialling is deliberately absent: its numbers cannot be dialled with a
// country code at all, so they never appear behind "+CC" or "00CC".
var e164NumberTypes = []string{
	"fixedLine", "mobile", "pager", "tollFree", "premiumRate", "sharedCost", "personalNumber",
	"voip", "uan", "voicemail",
}

type xmlPossibleLengths struct {
	National  string `xml:"national,attr"`
	LocalOnly string `xml:"localOnly,attr"`
}

type xmlNumberDesc struct {
	XMLName         xml.Name
	PossibleLengths *xmlPossibleLengths `xml:"possibleLengths"`
}

type xmlTerritory struct {
	ID                 string          `xml:"id,attr"`
	CountryCode        string          `xml:"countryCode,attr"`
	MainCountryForCode string          `xml:"mainCountryForCode,attr"`
	NationalPrefix     string          `xml:"nationalPrefix,attr"`
	Descs              []xmlNumberDesc `xml:",any"`
}

type xmlPhoneMetadata struct {
	Territories []xmlTerritory `xml:"territories>territory"`
}

// e164Entry is one calling code of the download, after every cross-check passed.
type e164Entry struct {
	code    string
	region  string   // the code's main region (mainCountryForCode, or its only territory)
	regions []string // every territory sharing the code, sorted
	lengths uint32   // bit n set: n is a possible national length
	trunk0  bool
}

var reCallingCode = regexp.MustCompile(`^[1-9][0-9]{0,2}$`)
var reRegionID = regexp.MustCompile(`^(?:[A-Z]{2}|001)$`)

// parsePossibleLengths reads libphonenumber's possibleLengths syntax: a comma-separated list of
// lengths and inclusive ranges, "9", "7,9,10", "[8-12]", "[5-7],9".
func parsePossibleLengths(spec string) (uint32, error) {
	var mask uint32
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return 0, fmt.Errorf("empty element in %q", spec)
		}
		lo, hi := part, part
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			bounds := strings.SplitN(part[1:len(part)-1], "-", 2)
			if len(bounds) != 2 {
				return 0, fmt.Errorf("range %q in %q", part, spec)
			}
			lo, hi = bounds[0], bounds[1]
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 31 || a > b {
			return 0, fmt.Errorf("length %q in %q", part, spec)
		}
		for n := a; n <= b; n++ {
			mask |= 1 << uint(n)
		}
	}
	return mask, nil
}

// parseE164Metadata reads the download and returns one entry per calling code, sorted by code. A
// download that fails any cross-check is refused: a table generated from it would reject real
// numbers, and a rejected number is not redacted.
func parseE164Metadata(data []byte) ([]e164Entry, int, error) {
	var md xmlPhoneMetadata
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	if err := dec.Decode(&md); err != nil {
		return nil, 0, fmt.Errorf("parse metadata XML: %w", err)
	}
	if len(md.Territories) == 0 {
		return nil, 0, fmt.Errorf("metadata XML holds no <territory>; is this libphonenumber's PhoneNumberMetadata.xml?")
	}

	type acc struct {
		regions []string
		mains   []string
		lengths uint32
		trunk0  bool
	}
	byCode := map[string]*acc{}
	seenRegion := map[string]bool{}
	var problems []string
	for _, t := range md.Territories {
		bad := func(format string, args ...any) {
			problems = append(problems, t.ID+"/"+t.CountryCode+": "+fmt.Sprintf(format, args...))
		}
		if !reRegionID.MatchString(t.ID) {
			bad("not a region ID")
			continue
		}
		if !reCallingCode.MatchString(t.CountryCode) {
			bad("not a 1-3 digit calling code")
			continue
		}
		if t.ID != "001" {
			if seenRegion[t.ID] {
				bad("region listed twice")
				continue
			}
			seenRegion[t.ID] = true
		}
		var lengths uint32
		for _, d := range t.Descs {
			name := d.XMLName.Local
			isType := false
			for _, want := range e164NumberTypes {
				if name == want {
					isType = true
					break
				}
			}
			if !isType {
				continue
			}
			if d.PossibleLengths == nil || d.PossibleLengths.National == "" {
				bad("%s has no national possibleLengths", name)
				continue
			}
			m, err := parsePossibleLengths(d.PossibleLengths.National)
			if err != nil {
				bad("%s: %v", name, err)
				continue
			}
			lengths |= m
		}
		if lengths == 0 {
			bad("no number type with a national length")
			continue
		}
		a := byCode[t.CountryCode]
		if a == nil {
			a = &acc{}
			byCode[t.CountryCode] = a
		}
		a.regions = append(a.regions, t.ID)
		if t.MainCountryForCode == "true" {
			a.mains = append(a.mains, t.ID)
		}
		a.lengths |= lengths
		if t.NationalPrefix == "0" {
			a.trunk0 = true
		}
	}

	var entries []e164Entry
	for code, a := range byCode {
		sort.Strings(a.regions)
		region := ""
		switch {
		case len(a.mains) == 1:
			region = a.mains[0]
		case len(a.mains) == 0 && len(a.regions) == 1:
			region = a.regions[0]
		default:
			problems = append(problems, fmt.Sprintf("%s: %d territories %v and main countries %v; want exactly one main", code, len(a.regions), a.regions, a.mains))
			continue
		}
		entries = append(entries, e164Entry{code: code, region: region, regions: a.regions, lengths: a.lengths, trunk0: a.trunk0})
	}
	// E.164 calling codes are a prefix code: no assigned code begins another. The lookup reads at most
	// one of a number's 1-, 2- and 3-digit prefixes as a code, which is only sound while this holds.
	for _, a := range entries {
		for _, b := range entries {
			if a.code != b.code && strings.HasPrefix(b.code, a.code) {
				problems = append(problems, fmt.Sprintf("code %s is a prefix of code %s", a.code, b.code))
			}
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, 0, fmt.Errorf("metadata refused, %d problems:\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].code) != len(entries[j].code) {
			return len(entries[i].code) < len(entries[j].code)
		}
		return entries[i].code < entries[j].code
	})
	return entries, len(md.Territories), nil
}

// lengthsLiteral renders a length mask as the Go expression the generated file uses.
func lengthsLiteral(mask uint32) string {
	var parts []string
	for n := 1; n < 32; n++ {
		if mask&(1<<uint(n)) != 0 {
			parts = append(parts, fmt.Sprintf("1<<%d", n))
		}
	}
	return strings.Join(parts, " | ")
}

// renderE164Codes writes e164_codes.go for entries.
func renderE164Codes(entries []e164Entry, territories int, source, readDate, digest string) ([]byte, error) {
	var b strings.Builder
	b.WriteString(`// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

// e164Codes is every assigned ITU-T E.164 country calling code: the code's main region, the national
// (significant) number lengths its plan allows, and whether the plan writes a trunk "0" in front of
// a national number, which international display forms show as "(0)". The E.164 gate
// (international.go) reads only this table, so a code missing here is a number never reported in
// the "+CC" or "00CC" form, and never redacted.
//
// GENERATED DATA, not hand-maintained. Regenerate it, and check it for drift, from libphonenumber's
// PhoneNumberMetadata.xml (Apache-2.0, github.com/google/libphonenumber):
//
//	E164_METADATA_XML=/path/to/PhoneNumberMetadata.xml UPDATE_E164_CODES=1 \
//	    go test ./internal/validators/phone/ -run TestE164CodesMatchMetadata
//
// Without UPDATE_E164_CODES the same command fails on any added, removed or changed code, and without
// E164_METADATA_XML it skips. What was read is recorded here:
//
`)
	fmt.Fprintf(&b, "//\tread %s from %s\n", readDate, source)
	fmt.Fprintf(&b, "//\tsha256 %s\n", digest)
	fmt.Fprintf(&b, "//\t%d territories, %d calling codes\n", territories, len(entries))
	b.WriteString(`//
// A code's lengths are the union, over every territory sharing it and every number type, of
// libphonenumber's "possibleLengths national": the lengths a number may have once the country code
// is written, so local-only lengths are excluded and so are numbers that cannot be dialled from
// abroad. The 15-digit E.164 maximum is applied separately, by the gate.
//
// # Why generated
//
// The map this replaces held 36 hand-typed codes with no lengths, so "+33 1 99 00 47 18" and
// "+44 (0)161 496 0815" could not be checked, the "00" form had no bound at all, and a code that does
// not exist ("+553 274 123 784", "00" followed by "0") passed for a country (#889).
var e164Codes = map[string]e164Code{
`)
	for _, e := range entries {
		if len(e.regions) > 1 {
			fmt.Fprintf(&b, "\t// shared by %s\n", strings.Join(e.regions, " "))
		}
		trunk := ""
		if e.trunk0 {
			trunk = ", trunk0: true"
		}
		fmt.Fprintf(&b, "\t%q: {region: %q, lengths: %s%s},\n", e.code, e.region, lengthsLiteral(e.lengths), trunk)
	}
	b.WriteString("}\n\n")
	b.WriteString(`// e164CodeCount is the number of codes the generator wrote. TestE164CodesCount requires e164Codes to
// hold exactly this many, so a hand edit that adds or drops a code, instead of regenerating, fails.
`)
	fmt.Fprintf(&b, "const e164CodeCount = %d\n", len(entries))
	return format.Source([]byte(b.String()))
}

var reRecordedE164Read = regexp.MustCompile(`(?m)^//\tread (\d{4}-\d{2}-\d{2}) from `)

// TestE164CodesMatchMetadata is the generator and the drift check. It needs the metadata XML, so
// without E164_METADATA_XML it skips: an offline run must not fail on an external file it cannot
// read.
func TestE164CodesMatchMetadata(t *testing.T) {
	path := os.Getenv(e164MetadataXMLEnv)
	if path == "" {
		t.Skipf("set %s to libphonenumber's PhoneNumberMetadata.xml (%s) to check e164_codes.go against it; "+
			"add %s=1 to regenerate", e164MetadataXMLEnv, e164MetadataDefaultURL, e164MetadataUpdateEnv)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- a path the developer passed in on purpose
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	entries, territories, err := parseE164Metadata(data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])

	if os.Getenv(e164MetadataUpdateEnv) == "1" {
		readDate := os.Getenv(e164MetadataReadDateEnv)
		if readDate == "" {
			readDate = time.Now().UTC().Format("2006-01-02")
		}
		source := os.Getenv(e164MetadataSourceEnv)
		if source == "" {
			source = e164MetadataDefaultURL
		}
		src, err := renderE164Codes(entries, territories, source, readDate, digest)
		if err != nil {
			t.Fatalf("render %s: %v", e164GeneratedFile, err)
		}
		if err := os.WriteFile(e164GeneratedFile, src, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s: %d codes from %d territories", e164GeneratedFile, len(entries), territories)
		return
	}

	var drift []string
	inDownload := map[string]bool{}
	for _, e := range entries {
		inDownload[e.code] = true
		got, ok := e164Codes[e.code]
		switch {
		case !ok:
			drift = append(drift, fmt.Sprintf("+ %s %s lengths %s (not in e164_codes.go)", e.code, e.region, lengthsLiteral(e.lengths)))
		case got.region != e.region || got.lengths != e.lengths || got.trunk0 != e.trunk0:
			drift = append(drift, fmt.Sprintf("~ %s %s lengths %s trunk0 %t (e164_codes.go: %s %s %t)",
				e.code, e.region, lengthsLiteral(e.lengths), e.trunk0, got.region, lengthsLiteral(got.lengths), got.trunk0))
		}
	}
	for code := range e164Codes {
		if !inDownload[code] {
			drift = append(drift, fmt.Sprintf("- %s (in e164_codes.go, not in the download)", code))
		}
	}
	sort.Strings(drift)
	if len(drift) > 0 {
		t.Fatalf("e164_codes.go has drifted from %s (%d codes):\n  %s\nregenerate with %s=1",
			path, len(entries), strings.Join(drift, "\n  "), e164MetadataUpdateEnv)
	}
	src, _ := os.ReadFile(e164GeneratedFile)
	recorded := "unknown"
	if m := reRecordedE164Read.FindSubmatch(src); m != nil {
		recorded = string(m[1])
	}
	t.Logf("e164_codes.go (read %s) matches the download: %d codes, sha256 %s", recorded, len(entries), digest)
}

// TestE164MetadataParserReadsTheLayout pins the parts of the real layout the parser depends on: the
// DOCTYPE with its internal subset, territories sharing a code, ranges in possibleLengths,
// localOnly lengths (excluded) and noInternationalDialling (excluded).
func TestE164MetadataParserReadsTheLayout(t *testing.T) {
	xmlText := `<!-- comment -->
<!DOCTYPE phoneNumberMetadata [
    <!ELEMENT phoneNumberMetadata (territories)>
    <!ATTLIST territory id CDATA #REQUIRED>
]>
<phoneNumberMetadata>
  <territories>
    <!-- Guernsey (GG) -->
    <territory id="GG" countryCode="44" internationalPrefix="00" nationalPrefix="0">
      <generalDesc><nationalNumberPattern>\d{6,10}</nationalNumberPattern></generalDesc>
      <fixedLine><possibleLengths national="10" localOnly="6"/><exampleNumber>1481256789</exampleNumber><nationalNumberPattern>1481[25-9]\d{5}</nationalNumberPattern></fixedLine>
    </territory>
    <territory id="GB" countryCode="44" mainCountryForCode="true" internationalPrefix="00" nationalPrefix="0">
      <generalDesc><nationalNumberPattern>\d{7,10}</nationalNumberPattern></generalDesc>
      <noInternationalDialling><possibleLengths national="11"/><nationalNumberPattern>\d{11}</nationalNumberPattern></noInternationalDialling>
      <fixedLine><possibleLengths national="[9-10]" localOnly="[4-8]"/><exampleNumber>1212345678</exampleNumber><nationalNumberPattern>\d{9,10}</nationalNumberPattern></fixedLine>
      <mobile><possibleLengths national="10"/><exampleNumber>7400123456</exampleNumber><nationalNumberPattern>7\d{9}</nationalNumberPattern></mobile>
      <voip><possibleLengths national="7,10"/><exampleNumber>5612345678</exampleNumber><nationalNumberPattern>\d{7,10}</nationalNumberPattern></voip>
    </territory>
    <territory id="IT" countryCode="39" mainCountryForCode="true" internationalPrefix="00">
      <generalDesc><nationalNumberPattern>\d{6,12}</nationalNumberPattern></generalDesc>
      <fixedLine><possibleLengths national="[6-11]"/><exampleNumber>0212345678</exampleNumber><nationalNumberPattern>0\d{5,10}</nationalNumberPattern></fixedLine>
    </territory>
    <territory id="VA" countryCode="39" internationalPrefix="00">
      <generalDesc><nationalNumberPattern>\d{6,12}</nationalNumberPattern></generalDesc>
      <mobile><possibleLengths national="[9-10]"/><exampleNumber>3123456789</exampleNumber><nationalNumberPattern>3\d{8,9}</nationalNumberPattern></mobile>
    </territory>
    <territory id="001" countryCode="800" internationalPrefix="">
      <generalDesc><nationalNumberPattern>\d{8}</nationalNumberPattern></generalDesc>
      <tollFree><possibleLengths national="8"/><exampleNumber>12345678</exampleNumber><nationalNumberPattern>\d{8}</nationalNumberPattern></tollFree>
    </territory>
  </territories>
</phoneNumberMetadata>
`
	entries, territories, err := parseE164Metadata([]byte(xmlText))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if territories != 5 || len(entries) != 3 {
		t.Fatalf("parsed %d territories into %d codes, want 5 into 3: %+v", territories, len(entries), entries)
	}
	byCode := map[string]e164Entry{}
	for _, e := range entries {
		byCode[e.code] = e
	}
	gb := byCode["44"]
	if gb.region != "GB" || gb.lengths != 1<<7|1<<9|1<<10 || !gb.trunk0 || strings.Join(gb.regions, " ") != "GB GG" {
		t.Errorf("44 parsed as %+v; want region GB, lengths 7,9,10 (no localOnly, no noInternationalDialling 11), trunk0, regions GB GG", gb)
	}
	it := byCode["39"]
	if it.region != "IT" || it.lengths != 1<<6|1<<7|1<<8|1<<9|1<<10|1<<11 || it.trunk0 {
		t.Errorf("39 parsed as %+v; want region IT, lengths 6-11, no trunk 0", it)
	}
	if e := byCode["800"]; e.region != "001" || e.lengths != 1<<8 {
		t.Errorf("800 parsed as %+v; want region 001, length 8", e)
	}
}

// TestE164MetadataParserRefusesAnInconsistentDownload pins the cross-checks.
func TestE164MetadataParserRefusesAnInconsistentDownload(t *testing.T) {
	territory := func(id, code, main, lengths string) string {
		attr := ""
		if main != "" {
			attr = ` mainCountryForCode="` + main + `"`
		}
		return `<territory id="` + id + `" countryCode="` + code + `"` + attr + `><fixedLine><possibleLengths national="` +
			lengths + `"/></fixedLine></territory>`
	}
	doc := func(ts ...string) string {
		return "<phoneNumberMetadata><territories>" + strings.Join(ts, "") + "</territories></phoneNumberMetadata>"
	}
	if _, _, err := parseE164Metadata([]byte(doc(territory("FR", "33", "", "9"), territory("DE", "49", "", "[4-15]")))); err != nil {
		t.Fatalf("a consistent download was refused: %v", err)
	}
	for name, text := range map[string]string{
		"no territories":        doc(),
		"code with a leading 0": doc(territory("FR", "033", "", "9")),
		"four-digit code":       doc(territory("FR", "3312", "", "9")),
		"bad length":            doc(territory("FR", "33", "", "nine")),
		"reversed range":        doc(territory("FR", "33", "", "[9-4]")),
		"no main for a shared":  doc(territory("GB", "44", "", "10"), territory("GG", "44", "", "10")),
		"two mains":             doc(territory("GB", "44", "true", "10"), territory("GG", "44", "true", "10")),
		"prefix codes":          doc(territory("FR", "33", "", "9"), territory("XX", "331", "", "9")),
		"region twice":          doc(territory("FR", "33", "", "9"), territory("FR", "34", "", "9")),
		"no lengths":            doc(`<territory id="FR" countryCode="33"><generalDesc/></territory>`),
	} {
		if _, _, err := parseE164Metadata([]byte(text)); err == nil {
			t.Errorf("%s: parser accepted it", name)
		}
	}
}
