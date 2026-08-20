// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// A value inside a VECTOR-valued property must be removable, or #267 would trade a silent
// miss for a reported-but-unredactable value — by this tool's own sink rule, a leak dressed
// as a success.
//
// It works for a reason worth stating: a vector element is stored as a 4-byte length
// followed by its bytes, and a same-length overwrite never touches the length. So the
// element is masked in place, every sector offset and FAT chain behind it stays valid, and
// the container still parses. Measured end to end on an .xls whose sheet-name list carried
// an SSN: the redacted copy is byte-for-byte the same SIZE, the SSN is gone, and reading it
// back yields the sheet name with the value masked.
//
// The read half — decoding the vector so the value is reported at all — lives in
// internal/preprocessors/meta-extractors/meta-extract-officelib. Neither half is useful
// without the other, which is why this assertion is here rather than left implied.
func TestRedaction_ReachesAVectorPropertyElement(t *testing.T) {
	const (
		ssn   = "452-11-9384"
		sheet = "Payroll SSN " + ssn
	)

	pkg := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWorkbook, Data: []byte("Workbook body with nothing sensitive.")},
		{Name: olefixture.StreamDocSummaryInformation, Data: olefixture.DocSummaryInformationWithVectors(
			map[uint32]string{olefixture.PropCompany: "Fairbanks Holdings"},
			map[uint32][]string{olefixture.PropDocumentParts: {"Q3 Forecast", sheet, "Notes"}},
		)},
	})

	dir := t.TempDir()
	src := filepath.Join(dir, "vectors.xls")
	if err := os.WriteFile(src, pkg, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	// The value must really be in there, or every assertion below is vacuous.
	if !bytes.Contains(pkg, []byte(ssn)) {
		t.Fatal("the fixture does not contain the value it is meant to carry")
	}

	out := filepath.Join(dir, "redacted.xls")
	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(src, out, matchesFor(map[string]string{ssn: "SSN"}),
		redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if !res.Success {
		t.Fatal("RedactDocument reported failure")
	}

	redacted, err := os.ReadFile(out) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if bytes.Contains(redacted, []byte(ssn)) {
		t.Error("the SSN survives inside the vector property of a file reported as redacted")
	}
	if len(redacted) != len(pkg) {
		t.Errorf("size changed from %d to %d bytes; a length change would invalidate every "+
			"sector offset and FAT chain behind it", len(pkg), len(redacted))
	}

	// The element's NEIGHBOURS and its length prefix must survive, or the list is corrupt
	// even though the value is gone — which reads as a successful redaction of a file no
	// reader can parse.
	streams := streamContents(t, out)
	props, ok := streams["DocumentSummaryInformation"]
	if !ok {
		t.Fatalf("no DocumentSummaryInformation stream in the output: %v", keysOf(streams))
	}
	for _, keep := range []string{"Q3 Forecast", "Notes", "Fairbanks Holdings"} {
		if !bytes.Contains(props, []byte(keep)) {
			t.Errorf("the property stream lost the UNREPORTED value %q; redaction must overwrite "+
				"only what was reported", keep)
		}
	}
	// "Payroll SSN " is the reported value's prefix inside the same element: it is not part
	// of the match, so it stays — which is also what proves the overwrite was scoped to the
	// value and not to the element.
	if !bytes.Contains(props, []byte("Payroll SSN ")) {
		t.Error("the whole element was overwritten rather than just the reported value")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
